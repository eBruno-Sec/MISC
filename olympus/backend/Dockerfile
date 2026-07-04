FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap whois curl wget unzip dnsutils netcat-openbsd jq procps \
    && rm -rf /var/lib/apt/lists/*

# Pre-built Go security tool binaries (fail gracefully if network restricted)
RUN wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip" \
    -O /tmp/sf.zip && unzip -q /tmp/sf.zip subfinder -d /usr/local/bin \
    && chmod +x /usr/local/bin/subfinder && rm /tmp/sf.zip || echo "subfinder install skipped"

RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip" \
    -O /tmp/nu.zip && unzip -q /tmp/nu.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei && rm /tmp/nu.zip || echo "nuclei install skipped"

RUN wget -q "https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_linux_amd64.zip" \
    -O /tmp/hx.zip && unzip -q /tmp/hx.zip httpx -d /usr/local/bin \
    && chmod +x /usr/local/bin/httpx && rm /tmp/hx.zip || echo "httpx install skipped"

RUN wget -q "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz" \
    -O /tmp/ff.tgz && tar -xzf /tmp/ff.tgz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf && rm /tmp/ff.tgz || echo "ffuf install skipped"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/reports /app/wordlists

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
