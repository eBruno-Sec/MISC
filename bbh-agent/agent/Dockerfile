# Stage 1: compile Go-based security tools
FROM golang:1.22-bookworm AS go-builder

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null
RUN go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null
RUN go install -v github.com/hahwul/dalfox/v2@latest 2>/dev/null

# Stage 2: Kali Linux runtime
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# SQLite database for mission/finding/evidence persistence (mounted volume)
ENV BBH_DB_PATH=/app/data/bbh.db

RUN apt-get update -q && apt-get install -y -q \
    python3 python3-pip \
    nmap whatweb \
    dirb sqlmap \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/katana /usr/local/bin/
COPY --from=go-builder /go/bin/ffuf /usr/local/bin/
COPY --from=go-builder /go/bin/dalfox /usr/local/bin/

WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt --break-system-packages

# Headless Chromium for the browser-based XSS execution pass (run_xss).
# Best-effort: if the fetch fails (offline build), run_xss falls back to
# reflection-only analysis and the rest of the agent is unaffected.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
RUN python3 -m playwright install --with-deps chromium || \
    echo "[WARN] Chromium install skipped; run_xss will use reflection-only mode"

RUN mkdir -p /app/data
COPY *.py .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
