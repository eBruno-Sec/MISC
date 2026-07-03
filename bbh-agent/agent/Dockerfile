# Stage 1: compile Go-based security tools
FROM golang:1.22-bookworm AS go-builder

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null
RUN go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null

# Stage 2: Kali Linux runtime
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update -q && apt-get install -y -q \
    python3 python3-pip \
    nmap whatweb \
    dirb \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/ffuf /usr/local/bin/

WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt --break-system-packages

COPY *.py .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
