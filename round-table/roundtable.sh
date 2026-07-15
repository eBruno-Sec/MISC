#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# ROUND TABLE // one-command control
#   ./roundtable.sh            build + start (detached), open URL
#   ./roundtable.sh --logs     follow logs
#   ./roundtable.sh --stop     stop the platform
#   ./roundtable.sh --rebuild  rebuild from scratch and start
#   ./roundtable.sh --status   show container status
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$0")"

# docker compose (v2) or docker-compose (v1)
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  echo "ERROR: Docker Compose not found. Install Docker Desktop or the compose plugin." >&2
  exit 1
fi

PORT="$(grep -E '^ROUNDTABLE_PORT=' .env 2>/dev/null | cut -d= -f2 || true)"
PORT="${PORT:-3000}"
URL="http://localhost:${PORT}"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[roundtable] created .env from .env.example (all defaults — edit to add an AI key)"
fi

open_url() {
  command -v xdg-open >/dev/null 2>&1 && xdg-open "$URL" >/dev/null 2>&1 && return 0
  command -v open     >/dev/null 2>&1 && open "$URL"     >/dev/null 2>&1 && return 0
  command -v explorer.exe >/dev/null 2>&1 && explorer.exe "$URL" >/dev/null 2>&1 && return 0
  return 0
}

case "${1:-up}" in
  --stop|stop|down)
    $DC down
    echo "[roundtable] stopped." ;;
  --logs|logs)
    $DC logs -f ;;
  --status|status|ps)
    $DC ps ;;
  --rebuild|rebuild)
    $DC down
    $DC up --build -d
    echo "[roundtable] rebuilt and running at ${URL}" ;;
  --up|up|"")
    echo "[roundtable] building + starting (first build pulls recon tools; give it a few minutes)…"
    $DC up --build -d
    echo ""
    echo "  ⚔  ROUND TABLE is up  →  ${URL}"
    echo "     logs:  ./roundtable.sh --logs      stop:  ./roundtable.sh --stop"
    open_url ;;
  *)
    echo "usage: ./roundtable.sh [--up|--logs|--stop|--rebuild|--status]" ; exit 1 ;;
esac
