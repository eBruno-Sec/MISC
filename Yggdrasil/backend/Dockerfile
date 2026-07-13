FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap whois curl wget unzip dnsutils netcat-openbsd jq procps \
    git python3-pip \
    && rm -rf /var/lib/apt/lists/*

# ── ProjectDiscovery + fuzzing binaries ──────────────────────────
RUN wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip" \
    -O /tmp/sf.zip && unzip -q /tmp/sf.zip subfinder -d /usr/local/bin \
    && chmod +x /usr/local/bin/subfinder && rm /tmp/sf.zip || echo "subfinder skipped"

RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip" \
    -O /tmp/nu.zip && unzip -q /tmp/nu.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei && rm /tmp/nu.zip || echo "nuclei skipped"

RUN wget -q "https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_linux_amd64.zip" \
    -O /tmp/hx.zip && unzip -q /tmp/hx.zip httpx -d /usr/local/bin \
    && chmod +x /usr/local/bin/httpx && rm /tmp/hx.zip || echo "httpx skipped"

RUN wget -q "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz" \
    -O /tmp/ff.tgz && tar -xzf /tmp/ff.tgz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf && rm /tmp/ff.tgz || echo "ffuf skipped"

# ── Crawler + URL harvesting ─────────────────────────────────────
RUN wget -q "https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip" \
    -O /tmp/kt.zip && unzip -q /tmp/kt.zip katana -d /usr/local/bin \
    && chmod +x /usr/local/bin/katana && rm /tmp/kt.zip || echo "katana skipped"

# ── Active injection: dalfox (XSS) ───────────────────────────────
RUN wget -q "https://github.com/hahwul/dalfox/releases/download/v2.9.2/dalfox_2.9.2_linux_amd64.tar.gz" \
    -O /tmp/df.tgz && tar -xzf /tmp/df.tgz -C /usr/local/bin dalfox \
    && chmod +x /usr/local/bin/dalfox && rm /tmp/df.tgz || echo "dalfox skipped"

# ── Active injection: sqlmap (SQLi) ──────────────────────────────
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && printf '#!/bin/sh\npython3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap || echo "sqlmap skipped"

# ── SecLists (real wordlists) ────────────────────────────────────
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists || echo "seclists skipped"

# Optional parameter-discovery tooling. Tyr has native fallbacks, so scans keep
# working even if one of these third-party installs fails during image build.
RUN pip install --no-cache-dir wfuzz arjun || echo "wfuzz/arjun skipped"
RUN git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git /opt/ParamSpider \
    && pip install --no-cache-dir /opt/ParamSpider || echo "paramspider skipped"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/reports /app/wordlists

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
