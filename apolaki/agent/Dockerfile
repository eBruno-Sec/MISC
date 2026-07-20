# Stage 1: compile Go-based security tools
# Go 1.24 satisfies current ProjectDiscovery module requirements; GOTOOLCHAIN=auto
# lets `go install` fetch a newer toolchain automatically if a tool bumps its
# requirement later. CGO off => static binaries that run on the Kali stage with
# no shared-lib deps.
FROM golang:1.24-bookworm AS go-builder
ENV CGO_ENABLED=0
ENV GOTOOLCHAIN=auto
RUN mkdir -p /go/bin

# Each install is best-effort: a single tool that fails to build (Go-version bump,
# transient network) must not kill the whole image — the agent skips any missing
# binary at runtime and uses its native equivalents. Errors stay visible in the
# build log (no 2>/dev/null) so a real failure can be diagnosed.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo "[WARN] subfinder build skipped"
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest         || echo "[WARN] httpx build skipped"
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest    || echo "[WARN] nuclei build skipped"
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest       || echo "[WARN] katana build skipped"
RUN go install github.com/ffuf/ffuf/v2@latest                             || echo "[WARN] ffuf build skipped"
RUN go install github.com/hahwul/dalfox/v2@latest                         || echo "[WARN] dalfox build skipped"

# Stage 2: runtime — Debian slim (Python preinstalled) rather than Kali, whose
# rolling mirror (http.kali.org) frequently 503s mid-build. Every security package
# we use (nmap/whatweb/dirb/sqlmap) is in Debian too, served from the reliable
# deb.debian.org CDN.
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# SQLite database for mission/finding/evidence persistence (mounted volume)
ENV BBH_DB_PATH=/app/data/bbh.db

# These CLI tools are optional — the agent skips any that are missing and uses its
# native equivalents — so a transient apt hiccup must not fail the build.
RUN apt-get update -o Acquire::Retries=3 -q && \
    apt-get install -y --no-install-recommends -q nmap whatweb dirb sqlmap \
      || echo "[WARN] apt security tools skipped; native equivalents will be used"; \
    rm -rf /var/lib/apt/lists/*

# Copy every binary that built (whichever succeeded above). The trailing slash
# copies the directory contents; tools that were skipped simply aren't present.
COPY --from=go-builder /go/bin/ /usr/local/bin/

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Headless Chromium for the browser-based XSS execution pass (run_xss).
# Best-effort: if the fetch fails (offline build), run_xss falls back to
# reflection-only analysis and the rest of the agent is unaffected.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
RUN python3 -m playwright install --with-deps chromium || \
    echo "[WARN] Chromium install skipped; run_xss will use reflection-only mode"

RUN mkdir -p /app/data
COPY *.py .
# Ship the test suite so `docker compose exec agent python3 -m pytest tests/ -q`
# works as documented (conftest.py adds /app to sys.path).
COPY tests ./tests

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
