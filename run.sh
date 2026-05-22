#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║      SOC ATTACK SIMULATION TOOL — BN301                         ║
# ║      Auto-setup script for Linux / macOS                        ║
# ╚══════════════════════════════════════════════════════════════════╝
# Usage:  bash run.sh
# Works on: macOS (Homebrew), Debian/Ubuntu/Kali, Fedora/RHEL, Arch

set -e  # exit on first error (overridden per-block where needed)

# ── Colours ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

# ── Banner ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║        SOC ATTACK SIMULATION TOOL — BN301                    ║${RESET}"
echo -e "${BOLD}${CYAN}║        Security Operations Center  |  Auto-Setup              ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""

# ── Detect OS ──────────────────────────────────────────────────────
OS="unknown"
PKG_MGR=""
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ -f /etc/debian_version ]]; then
    OS="debian"   # Kali, Ubuntu, Debian, Parrot
elif [[ -f /etc/fedora-release ]] || [[ -f /etc/redhat-release ]]; then
    OS="fedora"
elif [[ -f /etc/arch-release ]]; then
    OS="arch"
fi
info "Detected OS: ${BOLD}$OS${RESET}"

# ── Helper: install system package ─────────────────────────────────
install_pkg() {
    local pkg="$1"
    case "$OS" in
        macos)  brew install "$pkg" ;;
        debian) sudo apt-get install -y "$pkg" ;;
        fedora) sudo dnf install -y "$pkg" ;;
        arch)   sudo pacman -S --noconfirm "$pkg" ;;
        *)      warn "Cannot auto-install $pkg on unknown OS. Install it manually." ;;
    esac
}

# ── 1. Homebrew (macOS only) ───────────────────────────────────────
if [[ "$OS" == "macos" ]]; then
    if ! command -v brew &>/dev/null; then
        warn "Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        # Add brew to PATH for Apple Silicon
        if [[ -f /opt/homebrew/bin/brew ]]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
        success "Homebrew installed."
    else
        success "Homebrew found: $(brew --version | head -1)"
    fi
fi

# ── 2. Python 3.8+ ────────────────────────────────────────────────
info "Checking Python 3..."
PY=""
for cmd in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c "import sys; print(sys.version_info >= (3,8))" 2>/dev/null)
        if [[ "$VER" == "True" ]]; then
            PY="$cmd"
            break
        fi
    fi
done

if [[ -z "$PY" ]]; then
    warn "Python 3.8+ not found. Installing..."
    case "$OS" in
        macos)  brew install python3 ;;
        debian) sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip python3-venv ;;
        fedora) sudo dnf install -y python3 python3-pip ;;
        arch)   sudo pacman -S --noconfirm python python-pip ;;
        *)      error "Please install Python 3.8+ manually from https://python.org" ;;
    esac
    PY=$(command -v python3)
fi
success "Python found: $($PY --version)"

# ── 3. pip ────────────────────────────────────────────────────────
info "Checking pip..."
if ! $PY -m pip --version &>/dev/null; then
    warn "pip not found. Installing..."
    case "$OS" in
        macos)  brew install python3 ;;  # pip ships with brew python
        debian) sudo apt-get install -y python3-pip ;;
        fedora) sudo dnf install -y python3-pip ;;
        arch)   sudo pacman -S --noconfirm python-pip ;;
        *)      $PY -m ensurepip --upgrade || error "Cannot install pip. Install manually." ;;
    esac
fi
success "pip found: $($PY -m pip --version)"

# ── 4. Virtual environment ────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

info "Setting up virtual environment at .venv/ ..."
if [[ ! -d "$VENV_DIR" ]]; then
    # python3-venv might be missing on Debian systems
    if ! $PY -m venv --help &>/dev/null 2>&1; then
        warn "venv module not found. Installing python3-venv..."
        case "$OS" in
            debian) sudo apt-get install -y python3-venv ;;
            fedora) sudo dnf install -y python3-virtualenv ;;
            arch)   sudo pacman -S --noconfirm python-virtualenv ;;
        esac
    fi
    $PY -m venv "$VENV_DIR"
    success "Virtual environment created."
else
    success "Virtual environment already exists."
fi

# Activate venv
source "$VENV_DIR/bin/activate"
VENV_PY="$VENV_DIR/bin/python"

# ── 5. Python dependencies ────────────────────────────────────────
info "Installing Python packages from requirements.txt..."
"$VENV_PY" -m pip install --upgrade pip --quiet
"$VENV_PY" -m pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
success "Python dependencies installed."

# ── 6. nmap ───────────────────────────────────────────────────────
info "Checking nmap..."
if ! command -v nmap &>/dev/null; then
    warn "nmap not found. Installing..."
    case "$OS" in
        macos)  brew install nmap ;;
        debian) sudo apt-get update -qq && sudo apt-get install -y nmap ;;
        fedora) sudo dnf install -y nmap ;;
        arch)   sudo pacman -S --noconfirm nmap ;;
        *)      error "Please install nmap manually: https://nmap.org/download.html" ;;
    esac
fi
success "nmap found: $(nmap --version | head -1)"

# ── 7. hydra (optional — only warn if missing) ────────────────────
info "Checking hydra (optional for brute force modules)..."
if command -v hydra &>/dev/null; then
    success "hydra found: $(hydra -h 2>&1 | head -1 || echo 'hydra installed')"
else
    warn "hydra not found. Brute force attacks will be unavailable."
    warn "Install with:"
    case "$OS" in
        macos)  warn "  brew install hydra" ;;
        debian) warn "  sudo apt-get install hydra" ;;
        fedora) warn "  sudo dnf install hydra" ;;
        arch)   warn "  sudo pacman -S hydra" ;;
    esac
fi

# ── 8. Launch ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${GREEN}  ✅  All dependencies satisfied. Starting server...           ${RESET}"
echo -e "${BOLD}${GREEN}  🌐  Open your browser at: http://localhost:5050              ${RESET}"
echo -e "${BOLD}${GREEN}  ⏹   Press Ctrl+C to stop                                    ${RESET}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

cd "$SCRIPT_DIR"
"$VENV_PY" app.py
