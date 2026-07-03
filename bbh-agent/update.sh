#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect compose command
if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
else
    COMPOSE="docker-compose"
fi

echo -e "\n${BOLD}BBH Agent Updater${NC}\n"

info "Pulling latest code..."
git pull origin main

info "Stopping running containers..."
$COMPOSE down

info "Rebuilding image with latest changes..."
$COMPOSE build --no-cache

info "Starting updated container..."
$COMPOSE up -d

sleep 2

success "Update complete."
echo -e "Open: ${CYAN}http://localhost:8000${NC}\n"
