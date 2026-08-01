#!/bin/sh
# Tool + image version manifest — reproducibility ("what exactly is running?").
set -u
echo "[versions] compose images:"
docker compose --profile labs --profile browser --profile proxy --profile dast images 2>/dev/null \
  | awk 'NR==1 || /apolaki|juice|dvwa|bwapp|nowasp|mitmproxy|zap|chromium|intel/' | sed 's/^/  /'

echo "[versions] agent security tools:"
docker exec apolaki-agent-1 sh -c '
for t in nmap nuclei httpx katana ffuf sqlmap whatweb dalfox subfinder; do
  if command -v "$t" >/dev/null 2>&1; then
    v=$("$t" --version 2>/dev/null | head -1)
    printf "  %-10s %s\n" "$t" "$v"
  else
    printf "  %-10s not installed\n" "$t"
  fi
done' 2>/dev/null || echo "  (apolaki-agent-1 not running)"

echo "[versions] agent runtime:"
docker exec apolaki-agent-1 python --version 2>/dev/null | sed 's/^/  /' || true
docker exec apolaki-agent-1 sh -c 'pip show fastapi httpx cryptography 2>/dev/null | awk "/^Name:/{n=\$2} /^Version:/{printf \"  %-14s %s\n\", n, \$2}"' 2>/dev/null || true
