#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\n${BOLD}Apolaki Installer${NC}"
echo -e "─────────────────────────────────────────────\n"

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ -f /etc/kali-release ]]; then
        echo "kali"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/fedora-release ]]; then
        echo "fedora"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/arch-release ]]; then
        echo "arch"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
info "Detected OS: $OS"

# Root check for Linux
if [[ "$OS" != "macos" && "$EUID" -ne 0 ]]; then
    warn "Some steps require root. Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

# Install Docker if missing
install_docker() {
    info "Installing Docker..."
    case "$OS" in
        macos)
            if ! command -v brew &>/dev/null; then
                info "Installing Homebrew first..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install --cask docker
            echo ""
            warn "Docker Desktop installed. Open it from your Applications folder, wait for it to start, then re-run this script."
            exit 0
            ;;
        kali|debian)
            apt-get update -q
            apt-get install -y -q ca-certificates curl gnupg lsb-release
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            chmod a+r /etc/apt/keyrings/docker.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
                | tee /etc/apt/sources.list.d/docker.list > /dev/null
            apt-get update -q
            apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            systemctl enable --now docker
            REAL_USER="${SUDO_USER:-$USER}"
            if [[ -n "$REAL_USER" && "$REAL_USER" != "root" ]]; then
                usermod -aG docker "$REAL_USER"
                warn "Added $REAL_USER to docker group. Log out and back in if you hit permission errors."
            fi
            ;;
        fedora)
            dnf install -y dnf-plugins-core
            dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
            dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            systemctl enable --now docker
            REAL_USER="${SUDO_USER:-$USER}"
            [[ -n "$REAL_USER" && "$REAL_USER" != "root" ]] && usermod -aG docker "$REAL_USER"
            ;;
        rhel)
            yum install -y yum-utils
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            systemctl enable --now docker
            ;;
        arch)
            pacman -Sy --noconfirm docker docker-compose
            systemctl enable --now docker
            ;;
        *)
            fail "Unsupported OS. Install Docker manually: https://docs.docker.com/engine/install/"
            ;;
    esac
}

# Check Docker
if command -v docker &>/dev/null; then
    success "Docker found: $(docker --version | cut -d' ' -f3 | tr -d ',')"
else
    install_docker
    success "Docker installed."
fi

# Verify Docker is running
if ! docker info &>/dev/null 2>&1; then
    case "$OS" in
        macos)
            fail "Docker Desktop is not running. Open it from Applications and wait for the whale icon, then re-run."
            ;;
        *)
            info "Starting Docker daemon..."
            systemctl start docker
            sleep 3
            docker info &>/dev/null 2>&1 || fail "Docker failed to start. Run: systemctl status docker"
            ;;
    esac
fi
success "Docker daemon is running."

# Detect docker compose command
if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE="docker-compose"
else
    info "Installing Docker Compose plugin..."
    case "$OS" in
        kali|debian)
            apt-get install -y -q docker-compose-plugin
            COMPOSE="docker compose"
            ;;
        fedora|rhel)
            dnf install -y docker-compose-plugin
            COMPOSE="docker compose"
            ;;
        macos)
            brew install docker-compose
            COMPOSE="docker-compose"
            ;;
        *)
            fail "Could not install Docker Compose. Install manually: https://docs.docker.com/compose/install/"
            ;;
    esac
fi
success "Docker Compose found."

# Set up .env
cd "$SCRIPT_DIR"

if [[ -f .env ]]; then
    CURRENT_KEY=$(grep -E "^ANTHROPIC_API_KEY=" .env | cut -d'=' -f2 | tr -d ' ')
    if [[ -n "$CURRENT_KEY" && "$CURRENT_KEY" != "sk-ant-api03-..." ]]; then
        success ".env already configured."
    else
        warn ".env found but ANTHROPIC_API_KEY is not set."
        read -rp "Enter your Anthropic API key (sk-ant-...): " API_KEY
        [[ "$API_KEY" != sk-ant-* ]] && fail "Key must start with sk-ant-"
        echo "ANTHROPIC_API_KEY=${API_KEY}" > .env
        success "API key saved to .env"
    fi
else
    cp .env.example .env
    echo ""
    read -rp "Enter your Anthropic API key (sk-ant-...): " API_KEY
    [[ "$API_KEY" != sk-ant-* ]] && fail "Key must start with sk-ant-"
    sed -i.bak "s|sk-ant-api03-...|${API_KEY}|" .env && rm -f .env.bak
    success "API key saved to .env"
fi

# Build
echo ""
info "Building Docker image. First build takes 10-15 minutes..."
$COMPOSE build

success "Image built."

# Start
info "Starting Apolaki..."
$COMPOSE up -d

sleep 2

if $COMPOSE ps | grep -q "Up\|running"; then
    echo ""
    echo -e "${GREEN}${BOLD}Apolaki is running.${NC}"
    echo -e "Open: ${CYAN}http://localhost:8000${NC}"
    echo ""

    # Try to open browser
    if command -v xdg-open &>/dev/null; then
        xdg-open http://localhost:8000 &>/dev/null &
    elif command -v open &>/dev/null; then
        open http://localhost:8000 &>/dev/null &
    fi
else
    fail "Container did not start. Run: $COMPOSE logs"
fi
