# ── stage 1: build the Go recon tools (subfinder / httpx / nuclei / ffuf) ──
FROM golang:1.22-bookworm AS tools
ENV GOBIN=/out CGO_ENABLED=0
RUN mkdir -p /out && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest

# ── stage 2: runtime ──
FROM python:3.12-slim-bookworm

# Recon utilities that ship as OS packages. nmap needs NET_RAW at runtime
# (granted via docker-compose cap_add) for SYN scans.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap curl ca-certificates dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/subfinder /out/httpx /out/nuclei /out/ffuf /usr/local/bin/

ENV PYTHONUNBUFFERED=1 \
    HOME=/root \
    ROUNDTABLE_DATA_DIR=/app/data \
    ROUNDTABLE_WORDLIST=/app/wordlists/common.txt

WORKDIR /app

# Python deps first for layer caching.
COPY server/requirements.txt /app/server/requirements.txt
RUN pip install --no-cache-dir -r /app/server/requirements.txt

# App code: the web platform + the reused Knights + CLI config.
COPY server/ /app/server/
COPY knights/ /app/knights/
COPY wordlists/ /app/wordlists/

# Prefer the full SecLists common wordlist; keep the bundled seed on failure.
RUN curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
      -o /tmp/common.txt && mv /tmp/common.txt /app/wordlists/common.txt || \
      echo "[build] SecLists fetch failed — using bundled seed wordlist"

RUN mkdir -p /app/data

EXPOSE 8000
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
