import subprocess
import os
import json
import logging
import re
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
from pathlib import Path
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Network Scanner Service")

DEFAULT_TIMEOUT = int(os.getenv("NETWORK_SCAN_TIMEOUT", "120"))


class ScanRequest(BaseModel):
    url: str
    mode: str = "quick"
    include_ssl: bool = True
    timeout: Optional[int] = None

    @property
    def effective_timeout(self) -> int:
        return self.timeout if self.timeout else DEFAULT_TIMEOUT


@app.get("/health")
def health():
    return {"status": "ok"}


# ── Helpers ──────────────────────────────────

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.hostname or parsed.path.split("/")[0]
    except Exception:
        return url


def run_nmap(target: str, args: list, timeout: int) -> dict:
    try:
        xml_path = f"/tmp/nmap_{target.replace('.','_')}.xml"
        cmd = ["nmap"] + args + ["-oX", xml_path, target]
        logger.info("NMAP CMD: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        if not Path(xml_path).exists():
            return {"error": result.stderr.strip()}
        return parse_nmap_xml(xml_path)
    except subprocess.TimeoutExpired:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


def parse_nmap_xml(xml_path: str) -> dict:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        hosts = []
        for host in root.findall("host"):
            h = {}
            # Status
            status = host.find("status")
            if status is not None:
                h["status"] = status.get("state")
            # Address
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    h["ip"] = addr.get("addr")
            # Hostname
            hostnames = host.find("hostnames")
            if hostnames is not None:
                names = [hn.get("name") for hn in hostnames.findall("hostname")]
                h["hostnames"] = names
            # OS
            os_elem = host.find("os")
            if os_elem is not None:
                matches = os_elem.findall("osmatch")
                if matches:
                    h["os"] = matches[0].get("name")
            # Ports
            ports_elem = host.find("ports")
            if ports_elem is not None:
                ports = []
                for port in ports_elem.findall("port"):
                    p = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                    }
                    state = port.find("state")
                    if state is not None:
                        p["state"] = state.get("state")
                    service = port.find("service")
                    if service is not None:
                        p["service"] = service.get("name")
                        p["version"] = service.get("version", "")
                        p["product"] = service.get("product", "")
                    ports.append(p)
                h["ports"] = ports
            hosts.append(h)
        return {"hosts": hosts, "source": "nmap"}
    except Exception as e:
        return {"error": f"XML parse error: {e}"}


def get_ssl_info(domain: str, timeout: int = 10) -> dict:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=domain
        ) as s:
            s.settimeout(timeout)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "subject":     dict(x[0] for x in cert.get("subject", [])),
                "issuer":      dict(x[0] for x in cert.get("issuer", [])),
                "valid_from":  cert.get("notBefore"),
                "valid_to":    cert.get("notAfter"),
                "version":     cert.get("version"),
                "serial":      str(cert.get("serialNumber")),
                "source":      "ssl",
            }
    except ssl.SSLCertVerificationError as e:
        return {"error": f"SSL cert error: {e}", "source": "ssl"}
    except Exception as e:
        return {"error": str(e), "source": "ssl"}


def get_dns_records(domain: str) -> dict:
    try:
        import dns.resolver
        records = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
        return {"records": records, "source": "dns"}
    except ImportError:
        # fallback sans dnspython
        try:
            ip = socket.gethostbyname(domain)
            return {"records": {"A": [ip]}, "source": "dns"}
        except Exception as e:
            return {"error": str(e), "source": "dns"}


# ── Endpoints ────────────────────────────────

@app.post("/scan")
def scan(req: ScanRequest):
    domain = extract_domain(req.url)
    if not domain:
        return {"error": "URL invalide", "source": "network"}

    logger.info("NETWORK SCAN: %s mode=%s", domain, req.mode)

    results = {
        "target_url": req.url,
        "domain": domain,
        "mode": req.mode,
        "source": "network",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # ── Nmap ──
    if req.mode == "quick":
        nmap_args = ["-sT", "-T4", "--top-ports", "100", "--open"]
    elif req.mode == "full":
        nmap_args = ["-sT", "-T4", "-p-", "--open", "-sV"]
    else:
        nmap_args = ["-sT", "-T4", "--top-ports", "1000", "--open", "-sV"]

    results["nmap"] = run_nmap(domain, nmap_args, req.effective_timeout)

    # ── SSL ──
    if req.include_ssl:
        results["ssl"] = get_ssl_info(domain)

    # ── DNS ──
    results["dns"] = get_dns_records(domain)

    # ── Résumé ──
    hosts = results["nmap"].get("hosts", [])
    open_ports = []
    for h in hosts:
        for p in h.get("ports", []):
            if p.get("state") == "open":
                open_ports.append(p)

    results["summary"] = {
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
        "ssl_valid": "error" not in results.get("ssl", {}),
        "dns_records_count": sum(
            len(v) for v in results.get("dns", {}).get("records", {}).values()
        ),
    }

    logger.info(
        "NETWORK SCAN DONE: %s — %d ports ouverts",
        domain, len(open_ports)
    )
    return results
