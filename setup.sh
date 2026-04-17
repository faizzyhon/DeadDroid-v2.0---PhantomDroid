#!/usr/bin/env bash
# DeadDroid — one-shot installer for Kali/Debian/Ubuntu
# Usage: chmod +x setup.sh && sudo ./setup.sh

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✔]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✘]${NC} $1"; exit 1; }

echo -e "${RED}"
cat << 'BANNER'
██████╗ ███████╗ █████╗ ██████╗ ██████╗ ██████╗  ██████╗ ██╗██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗
██║  ██║█████╗  ███████║██║  ██║██║  ██║██████╔╝██║   ██║██║██║  ██║
██║  ██║██╔══╝  ██╔══██║██║  ██║██║  ██║██╔══██╗██║   ██║██║██║  ██║
██████╔╝███████╗██║  ██║██████╔╝██████╔╝██║  ██║╚██████╔╝██║██████╔╝
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝
BANNER
echo -e "${NC}"

info "DeadDroid Setup — Android Penetration Testing Framework"
warn "For authorised penetration testing only!"
echo

# ── Check root ──────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Please run as root: sudo ./setup.sh"

# ── System packages ─────────────────────────────────────────────────────────────
info "Updating package lists..."
apt-get update -qq

info "Installing system dependencies..."
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    default-jdk \
    apktool \
    adb \
    socat \
    nmap \
    curl wget \
    git \
    metasploit-framework \
    2>/dev/null || warn "Some packages may already be installed."

# ── Java / keytool / jarsigner ──────────────────────────────────────────────────
if ! command -v keytool &>/dev/null; then
    info "Installing OpenJDK for keytool/jarsigner..."
    apt-get install -y -qq openjdk-17-jdk
fi
ok "Java tools ready."

# ── ngrok ───────────────────────────────────────────────────────────────────────
if ! command -v ngrok &>/dev/null; then
    info "Installing ngrok..."
    curl -sL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
    echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | tee /etc/apt/sources.list.d/ngrok.list >/dev/null
    apt-get update -qq && apt-get install -y -qq ngrok
    ok "ngrok installed."
else
    ok "ngrok already installed."
fi

# ── frida-tools ─────────────────────────────────────────────────────────────────
if ! command -v frida &>/dev/null; then
    info "Installing frida-tools..."
    pip3 install -q frida-tools
    ok "frida installed."
else
    ok "frida already installed."
fi

# ── Python venv ─────────────────────────────────────────────────────────────────
VENV_DIR="$(cd "$(dirname "$0")" && pwd)/venv"
info "Creating Python virtual environment at $VENV_DIR..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

info "Installing Python requirements..."
pip install -q --upgrade pip
pip install -q -r "$(cd "$(dirname "$0")" && pwd)/requirements.txt"
ok "Python packages installed."

deactivate

# ── Metasploit RPC helper ───────────────────────────────────────────────────────
cat > /usr/local/bin/start-msfrpc << 'MSFRPC'
#!/usr/bin/env bash
# Start Metasploit RPC daemon for DeadDroid
PASSWORD="${1:-msf123}"
PORT="${2:-55553}"
echo "[*] Starting msfrpcd on port $PORT..."
msfrpcd -P "$PASSWORD" -p "$PORT" -S -a 127.0.0.1 &
sleep 5
echo "[✔] msfrpcd running. Password: $PASSWORD  Port: $PORT"
MSFRPC
chmod +x /usr/local/bin/start-msfrpc
ok "start-msfrpc helper installed at /usr/local/bin/start-msfrpc"

# ── Launcher script ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cat > /usr/local/bin/deaddroid << LAUNCHER
#!/usr/bin/env bash
source "${SCRIPT_DIR}/venv/bin/activate"
python3 "${SCRIPT_DIR}/main.py" "\$@"
LAUNCHER
chmod +x /usr/local/bin/deaddroid
ok "Launcher installed: run 'deaddroid' from anywhere."

echo
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✔  DeadDroid installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo "  ► Run:             deaddroid"
echo "  ► Start MSF RPC:   start-msfrpc [password] [port]"
echo "  ► Add ngrok token: ngrok config add-authtoken <YOUR_TOKEN>"
echo
warn "Always obtain written authorisation before testing."
echo
