FROM python:3.11-slim

# Installer nmap + outils réseau
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Installer dépendances Python
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    dnspython \
    python-whois

WORKDIR /app
COPY main.py .

EXPOSE 8002
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
