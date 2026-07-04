#!/usr/bin/env bash
# OLYMPUS — One-click installer and health checker
# Usage: ./setup.sh [--rebuild] [--stop] [--logs]
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { echo -e "${CYAN}  ◆ ${NC}$*"; }
ok()    { echo -e "${GREEN}  ✓ ${NC}$*"; }
warn()  { echo -e "${YELLOW}  ⚠ ${NC}$*"; }
die()   { echo -e "${RED}  ✕ ${NC}$*"; exit 1; }
sep()   { echo -e "${DIM}  $(printf '─%.0s' {1..60})${NC}"; }
COMPOSE_CMD=""

# Guard: set by install_docker() re-exec to skip re-prompt
OLYMPUS_DOCKER_READY="${OLYMPUS_DOCKER_READY:-0}"

banner() {
cat << 'BANNER'

  ⚡ OLYMPUS — Autonomous AI Security Platform
     Authorized Testing Only

BANNER
}

# ── Argument Handling ────────────────────────────────────────
handle_args() {
    for arg in "$@"; do
        case $arg in
            --stop)
                info "Stopping OLYMPUS..."
                [[ -n "$COMPOSE_CMD" ]] || detect_compose
                $COMPOSE_CMD down
                ok "Stopped."
                exit 0
                ;;
            --logs)
                [[ -n "$COMPOSE_CMD" ]] || detect_compose
                $COMPOSE_CMD logs -f
                exit 0
                ;;
            --rebuild)
                REBUILD=1
                ;;
        esac
    done
}
REBUILD=0

# ── OS Detection ─────────────────────────────────────────────
detect_os() {
    OS="unknown"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
    fi
}

# ── Docker Installation ──────────────────────────────────────
install_docker() {
    echo ""
    if [[ "$OS" == "linux" ]]; then
        info "Updating system packages (this may take a minute)..."
        sudo apt-get update -y
        sudo apt-get upgrade -y

        # Detect distro — get.docker.com breaks on Kali (kali-rolling has no Docker CE release)
        local distro=""
        if [[ -f /etc/os-release ]]; then
            distro=$(. /etc/os-release && echo "${ID:-}")
        fi

        if [[ "$distro" == "kali" ]]; then
            info "Kali Linux detected — installing docker.io from Kali repos..."
            sudo apt-get install -y docker.io
        elif command -v apt-get &>/dev/null; then
            info "Installing Docker via get.docker.com..."
            curl -fsSL https://get.docker.com | sudo sh
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y docker
        elif command -v yum &>/dev/null; then
            sudo yum install -y docker
        else
            die "Unsupported package manager. Install Docker manually: https://docs.docker.com/get-docker/"
        fi

        info "Enabling Docker service..."
        sudo systemctl enable --now docker
        info "Adding $USER to docker group..."
        sudo usermod -aG docker "$USER"
        ok "Docker installed."
        echo ""
        info "Re-launching with docker group active..."
        SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
        exec sg docker -c "export OLYMPUS_DOCKER_READY=1; exec bash '$SCRIPT_PATH'"
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            info "Installing Docker Desktop via Homebrew..."
            brew install --cask docker
            echo ""
            warn "Docker Desktop installed. Launch Docker.app, wait for it to start, then re-run:"
            echo "       ./setup.sh"
            exit 0
        else
            echo ""
            echo "  Install Docker Desktop for Mac:"
            echo "    https://docs.docker.com/desktop/mac/install/"
            die "Install Docker Desktop and re-run this script."
        fi
    else
        echo ""
        echo "  Install Docker Desktop for Windows:"
        echo "    https://docs.docker.com/desktop/windows/install/"
        die "Auto-install not supported on Windows. Install Docker Desktop and re-run."
    fi
}

# ── Docker Check ─────────────────────────────────────────────
check_docker() {
    if ! command -v docker &>/dev/null; then
        warn "Docker not found."
        echo ""
        read -rp "  Install Docker now? System will update + upgrade + install. [Y/n]: " ans
        ans="${ans:-Y}"
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            install_docker
        else
            echo ""
            case $OS in
                linux)
                    echo "  Manual install:"
                    echo "    curl -fsSL https://get.docker.com | sh"
                    echo "    sudo usermod -aG docker \$USER && newgrp docker"
                    ;;
                macos)
                    echo "  https://docs.docker.com/desktop/mac/install/"
                    ;;
                *)
                    echo "  https://docs.docker.com/get-docker/"
                    ;;
            esac
            echo ""
            die "Install Docker and re-run this script."
        fi
    fi
    local ver
    ver=$(docker --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "unknown")
    if [[ "$OLYMPUS_DOCKER_READY" == "1" ]]; then
        ok "Docker $ver (just installed)"
    else
        ok "Docker $ver"
    fi
}

# ── Docker Compose Installation ──────────────────────────────
install_compose() {
    echo ""
    info "Installing Docker Compose..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -y
        # docker-compose-plugin exists on Docker CE; docker.io (Kali) uses standalone docker-compose
        if apt-cache show docker-compose-plugin &>/dev/null 2>&1; then
            sudo apt-get install -y docker-compose-plugin
        else
            sudo apt-get install -y docker-compose
        fi
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y docker-compose-plugin
    elif command -v yum &>/dev/null; then
        sudo yum install -y docker-compose-plugin
    else
        # Fallback: install standalone binary
        info "Downloading Docker Compose binary..."
        local compose_ver="v2.27.0"
        local arch
        arch=$(uname -m)
        sudo mkdir -p /usr/local/lib/docker/cli-plugins
        sudo curl -SL \
            "https://github.com/docker/compose/releases/download/${compose_ver}/docker-compose-linux-${arch}" \
            -o /usr/local/lib/docker/cli-plugins/docker-compose
        sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
    fi
    ok "Docker Compose installed."
}

# ── Docker Compose Check ─────────────────────────────────────
detect_compose() {
    if docker compose version &>/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &>/dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        warn "Docker Compose not found."
        echo ""
        read -rp "  Install Docker Compose now? [Y/n]: " ans
        ans="${ans:-Y}"
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            install_compose
            # Re-check
            if docker compose version &>/dev/null 2>&1; then
                COMPOSE_CMD="docker compose"
            elif command -v docker-compose &>/dev/null; then
                COMPOSE_CMD="docker-compose"
            else
                die "Docker Compose install failed. Check errors above."
            fi
        else
            echo ""
            echo "  Install: https://docs.docker.com/compose/install/"
            die "Docker Compose required. Install it and re-run."
        fi
    fi
    local ver
    ver=$($COMPOSE_CMD version --short 2>/dev/null || echo "unknown")
    ok "Docker Compose $ver"
}

# ── Resource Check ───────────────────────────────────────────
check_resources() {
    local mem_gb
    mem_gb=$(docker system info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
    mem_gb=$(( mem_gb / 1073741824 ))
    if [[ $mem_gb -gt 0 && $mem_gb -lt 2 ]]; then
        warn "Docker has only ${mem_gb}GB RAM. Recommend 2GB+."
    fi

    local free_gb
    free_gb=$(df -BG . 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G' || echo 99)
    if [[ $free_gb -lt 4 ]]; then
        warn "Low disk space (${free_gb}GB free). Recommend 4GB+."
    fi
}

# ── Port Availability ────────────────────────────────────────
check_ports() {
    local blocked=0
    for port in 3000 8000; do
        if lsof -Pi ":$port" -sTCP:LISTEN -t &>/dev/null 2>&1; then
            warn "Port $port is already in use."
            echo "       Stop the process using port $port, or edit docker-compose.yml to change the port mapping."
            blocked=1
        fi
    done
    [[ $blocked -eq 0 ]] && ok "Ports 3000 and 8000 are available"
}

# ── .env Setup ───────────────────────────────────────────────
setup_env() {
    if [[ ! -f .env ]]; then
        if [[ -f .env.example ]]; then
            cp .env.example .env
            info "Created .env from .env.example"
        else
            die ".env.example not found. Run this script from the olympus/ directory."
        fi
    fi

    local has_key
    has_key=$(grep "ANTHROPIC_API_KEY=" .env | grep -v "your-key" | grep -v "^ANTHROPIC_API_KEY=$" || true)

    if [[ -z "$has_key" ]]; then
        echo ""
        echo -e "  ${YELLOW}Anthropic API key not configured.${NC}"
        echo -e "  ${DIM}Get your key at: https://console.anthropic.com/${NC}"
        echo ""
        read -rp "  Enter API key (sk-ant-...) or Enter to skip AI features: " api_key
        if [[ -n "$api_key" ]]; then
            if sed --version &>/dev/null 2>&1; then
                sed -i "s|ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=$api_key|" .env
            else
                sed -i '' "s|ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=$api_key|" .env
            fi
            ok "API key saved to .env"
        else
            warn "Skipping API key. ATHENA analysis and APOLLO AI summaries will be disabled."
            warn "All other recon and scanning functions work without an API key."
        fi
    else
        ok ".env configured"
    fi
}

# ── Build & Start ────────────────────────────────────────────
start_containers() {
    info "Building and starting OLYMPUS containers..."
    echo "  This may take 3-5 minutes on first run (downloading tool binaries)."
    echo ""

    if [[ $REBUILD -eq 1 ]]; then
        $COMPOSE_CMD down --remove-orphans 2>/dev/null || true
        $COMPOSE_CMD build --no-cache
    fi

    $COMPOSE_CMD up --build -d
    ok "Containers started"
}

# ── Health Check ─────────────────────────────────────────────
wait_for_backend() {
    info "Waiting for backend to be ready..."
    local attempts=0
    local max=45
    while [[ $attempts -lt $max ]]; do
        if curl -sf http://localhost:8000/api/health &>/dev/null; then
            echo ""
            ok "Backend healthy"
            return 0
        fi
        sleep 2
        attempts=$(( attempts + 1 ))
        echo -ne "\r  ${DIM}Attempt $attempts/$max — waiting...${NC}"
    done
    echo ""
    echo ""
    warn "Backend did not respond after ${max} attempts."
    echo ""
    echo "  Debug:"
    echo "    $COMPOSE_CMD logs backend | tail -50"
    echo ""
    die "Startup failed. Check logs above."
}

wait_for_frontend() {
    local attempts=0
    while [[ $attempts -lt 15 ]]; do
        if curl -sf http://localhost:3000 &>/dev/null; then
            ok "Frontend healthy"
            return 0
        fi
        sleep 2
        attempts=$(( attempts + 1 ))
    done
    warn "Frontend may still be starting. Try http://localhost:3000 in a few seconds."
}

# ── Open Browser ─────────────────────────────────────────────
open_browser() {
    local url="http://localhost:3000"
    if command -v xdg-open &>/dev/null; then
        xdg-open "$url" &>/dev/null &
    elif command -v open &>/dev/null; then
        open "$url"
    fi
}

# ── Summary ──────────────────────────────────────────────────
print_summary() {
    echo ""
    sep
    echo ""
    echo -e "  ${GREEN}${BOLD}OLYMPUS is online.${NC}"
    echo ""
    echo -e "  ${BOLD}UI:${NC}      http://localhost:3000"
    echo -e "  ${BOLD}API:${NC}     http://localhost:8000/api/docs"
    echo -e "  ${BOLD}Reports:${NC} http://localhost:8000/api/missions/{id}/report"
    echo ""
    sep
    echo ""
    echo "  Quick commands:"
    echo -e "    ${CYAN}./setup.sh --logs${NC}     stream all container logs"
    echo -e "    ${CYAN}./setup.sh --stop${NC}     stop all containers"
    echo -e "    ${CYAN}./setup.sh --rebuild${NC}  full clean rebuild"
    echo -e "    ${CYAN}$COMPOSE_CMD ps${NC}       check container status"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────
main() {
    banner
    detect_os
    handle_args "$@"

    sep
    info "Running preflight checks..."
    sep
    echo ""

    check_docker
    detect_compose
    check_resources
    check_ports

    echo ""
    sep
    info "Configuring environment..."
    sep
    echo ""

    setup_env

    echo ""
    sep
    info "Starting OLYMPUS..."
    sep
    echo ""

    start_containers
    wait_for_backend
    wait_for_frontend
    open_browser
    print_summary
}

main "$@"
