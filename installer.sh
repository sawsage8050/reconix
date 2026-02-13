#!/bin/bash
# ============================================================
#   Reconix Installer - Advanced Network Reconnaissance Tool
#   Installs all system tools, Python libraries & wordlists
# ============================================================

# ANSI colors
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

PASS="${GREEN}[✓]${RESET}"
FAIL="${RED}[✗]${RESET}"
INFO="${CYAN}[*]${RESET}"
WARN="${YELLOW}[!]${RESET}"

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗"
    echo "    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝"
    echo "    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝ "
    echo "    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗ "
    echo "    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗"
    echo "    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
    echo -e "${RESET}"
    echo -e "${YELLOW}              Installer v2.0 - Enhanced Edition${RESET}"
    echo -e "${WHITE}         ─────────────────────────────────────────${RESET}"
    echo -e "${GREEN}              Educational Use Only | Authorized Testing${RESET}"
    echo -e "${WHITE}         ─────────────────────────────────────────${RESET}"
    echo ""
}

# ── Helpers ───────────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${FAIL} This installer must be run as root."
        echo -e "     Run: ${CYAN}sudo bash installer.sh${RESET}"
        exit 1
    fi
}

check_os() {
    if ! command -v apt-get &>/dev/null; then
        echo -e "${FAIL} This installer requires a Debian/Ubuntu-based system (apt)."
        exit 1
    fi
}

install_apt() {
    local pkg="$1"
    local label="${2:-$1}"
    echo -ne "  ${INFO} Installing ${label}... "
    if apt-get install -y "$pkg" &>/dev/null 2>&1; then
        echo -e "${PASS}"
        return 0
    else
        echo -e "${FAIL}"
        return 1
    fi
}

install_pip() {
    local pkg="$1"
    local label="${2:-$1}"
    echo -ne "  ${INFO} pip install ${label}... "
    if pip3 install "$pkg" --break-system-packages -q 2>/dev/null; then
        echo -e "${PASS}"
        return 0
    else
        # fallback without --break-system-packages (older pip)
        if pip3 install "$pkg" -q 2>/dev/null; then
            echo -e "${PASS}"
            return 0
        fi
        echo -e "${FAIL}"
        return 1
    fi
}

already_installed() {
    echo -e "  ${PASS} ${1} already installed — skipping"
}

section() {
    echo ""
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${BLUE}  $1${RESET}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${RESET}"
    echo ""
}

# ── Track results ─────────────────────────────────────────────────────────────
INSTALLED=()
SKIPPED=()
FAILED=()

apt_pkg() {
    local pkg="$1"
    local label="${2:-$1}"
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
        already_installed "$label"
        SKIPPED+=("$label")
    else
        if install_apt "$pkg" "$label"; then
            INSTALLED+=("$label")
        else
            FAILED+=("$label")
        fi
    fi
}

pip_pkg() {
    local pkg="$1"
    local label="${2:-$1}"
    if python3 -c "import ${3:-$1}" &>/dev/null 2>&1; then
        already_installed "$label"
        SKIPPED+=("$label")
    else
        if install_pip "$pkg" "$label"; then
            INSTALLED+=("$label")
        else
            FAILED+=("$label")
        fi
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
#   MAIN INSTALL
# ═════════════════════════════════════════════════════════════════════════════

print_banner
check_root
check_os

# ── Step 1: System update ─────────────────────────────────────────────────────
section "STEP 1 — Updating Package Lists"
echo -ne "  ${INFO} Running apt-get update... "
apt-get update -qq && echo -e "${PASS}" || echo -e "${FAIL}"

# ── Step 2: Core system dependencies ─────────────────────────────────────────
section "STEP 2 — Core System Dependencies"
apt_pkg "python3"           "Python 3"
apt_pkg "python3-pip"       "pip3"
apt_pkg "python3-dev"       "Python 3 dev headers"
apt_pkg "libssl-dev"        "libssl-dev"
apt_pkg "libffi-dev"        "libffi-dev"
apt_pkg "build-essential"   "build-essential"
apt_pkg "git"               "git"
apt_pkg "curl"              "curl"
apt_pkg "wget"              "wget"

# ── Step 3: Network scanning tools ───────────────────────────────────────────
section "STEP 3 — Network Scanning Tools"
apt_pkg "nmap"              "nmap"
apt_pkg "netcat-openbsd"    "netcat"

# ── Step 4: Exploitation & vulnerability tools ────────────────────────────────
section "STEP 4 — Exploitation & Vulnerability Tools"

# Metasploit Framework
echo -ne "  ${INFO} Checking Metasploit Framework... "
if command -v msfconsole &>/dev/null; then
    echo -e "${PASS} already installed"
    SKIPPED+=("metasploit-framework")
else
    echo -e "${WARN} not found"
    echo -e "  ${INFO} Installing Metasploit Framework (this may take a while)..."
    if curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
        | sed 's/msfupdate//' > /tmp/msf_install.sh 2>/dev/null && bash /tmp/msf_install.sh &>/dev/null; then
        echo -e "  ${PASS} Metasploit installed"
        INSTALLED+=("metasploit-framework")
    else
        # Fallback via apt
        if apt-get install -y metasploit-framework &>/dev/null 2>&1; then
            echo -e "  ${PASS} Metasploit installed via apt"
            INSTALLED+=("metasploit-framework")
        else
            echo -e "  ${WARN} Could not auto-install Metasploit."
            echo -e "       Manual install: ${CYAN}https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html${RESET}"
            FAILED+=("metasploit-framework (manual install required)")
        fi
    fi
fi

# SearchSploit / ExploitDB
apt_pkg "exploitdb"         "searchsploit (exploitdb)"

# Responder
echo -ne "  ${INFO} Checking Responder... "
if command -v responder &>/dev/null; then
    echo -e "${PASS} already installed"
    SKIPPED+=("responder")
else
    echo -e "${WARN} not found — installing..."
    if apt-get install -y responder &>/dev/null 2>&1; then
        echo -e "  ${PASS} Responder installed"
        INSTALLED+=("responder")
    else
        # Fallback: clone from GitHub
        echo -ne "  ${INFO} Cloning Responder from GitHub... "
        if git clone https://github.com/lgandx/Responder /opt/Responder &>/dev/null 2>&1; then
            ln -sf /opt/Responder/Responder.py /usr/local/bin/responder
            echo -e "${PASS}"
            INSTALLED+=("responder")
        else
            echo -e "${FAIL}"
            FAILED+=("responder")
        fi
    fi
fi

# Hydra (RDP brute force support)
apt_pkg "hydra"             "hydra (RDP/VNC brute force)"

# ── Step 5: SMB tools ─────────────────────────────────────────────────────────
section "STEP 5 — SMB & Active Directory Tools"
apt_pkg "smbclient"         "smbclient"
apt_pkg "samba"             "samba"

# ── Step 6: Python libraries ──────────────────────────────────────────────────
section "STEP 6 — Python Libraries"
pip_pkg "python-nmap"       "python-nmap"       "nmap"
pip_pkg "paramiko"          "paramiko (SSH)"    "paramiko"
pip_pkg "impacket"          "impacket (SMB)"    "impacket"
pip_pkg "requests"          "requests (HTTP)"   "requests"
pip_pkg "urllib3"           "urllib3"           "urllib3"

# ── Step 7: Wordlists (SecLists) ──────────────────────────────────────────────
section "STEP 7 — Wordlists (SecLists)"

SECLISTS_PATH="/usr/share/seclists"

echo -ne "  ${INFO} Checking SecLists... "
if [[ -d "$SECLISTS_PATH" ]]; then
    echo -e "${PASS} already installed at ${SECLISTS_PATH}"
    SKIPPED+=("seclists")
else
    echo -e "${WARN} not found"
    echo -ne "  ${INFO} Installing via apt... "
    if apt-get install -y seclists &>/dev/null 2>&1; then
        echo -e "${PASS}"
        INSTALLED+=("seclists")
    else
        echo -e "${WARN} apt failed — cloning from GitHub (this may take a while)..."
        echo -ne "  ${INFO} Cloning SecLists... "
        if git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_PATH" &>/dev/null 2>&1; then
            echo -e "${PASS}"
            INSTALLED+=("seclists")
        else
            echo -e "${FAIL}"
            FAILED+=("seclists")
        fi
    fi
fi

# ── Step 8: Set permissions on reconix.py ────────────────────────────────────
section "STEP 8 — Setting Permissions"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECONIX_PATH="${SCRIPT_DIR}/reconix.py"

echo -ne "  ${INFO} Looking for reconix.py... "
if [[ -f "$RECONIX_PATH" ]]; then
    chmod +x "$RECONIX_PATH"
    echo -e "${PASS} found and made executable"
else
    echo -e "${WARN} reconix.py not found in same directory — skipping chmod"
fi

# Create reports directory
echo -ne "  ${INFO} Creating reports/ directory... "
mkdir -p "${SCRIPT_DIR}/reports"
echo -e "${PASS}"

# ── Final Summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}                  INSTALLATION SUMMARY${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
echo ""

if [[ ${#INSTALLED[@]} -gt 0 ]]; then
    echo -e "${GREEN}${BOLD}Newly Installed (${#INSTALLED[@]})${RESET}"
    for item in "${INSTALLED[@]}"; do
        echo -e "  ${PASS} ${item}"
    done
    echo ""
fi

if [[ ${#SKIPPED[@]} -gt 0 ]]; then
    echo -e "${BLUE}${BOLD}Already Present (${#SKIPPED[@]})${RESET}"
    for item in "${SKIPPED[@]}"; do
        echo -e "  ${INFO} ${item}"
    done
    echo ""
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo -e "${RED}${BOLD}Failed / Manual Install Required (${#FAILED[@]})${RESET}"
    for item in "${FAILED[@]}"; do
        echo -e "  ${FAIL} ${item}"
    done
    echo ""
fi

# Verify critical tools
echo -e "${BOLD}${YELLOW}Tool Verification${RESET}"
echo ""
for tool in nmap python3 pip3 searchsploit msfconsole responder hydra; do
    if command -v "$tool" &>/dev/null; then
        ver=$(${tool} --version 2>&1 | head -1)
        echo -e "  ${PASS} ${tool} — ${ver}"
    else
        echo -e "  ${FAIL} ${tool} — NOT FOUND"
    fi
done

echo ""
for pylib in nmap paramiko impacket requests; do
    if python3 -c "import ${pylib}" &>/dev/null 2>&1; then
        echo -e "  ${PASS} python3: ${pylib}"
    else
        echo -e "  ${FAIL} python3: ${pylib} — NOT FOUND"
    fi
done

# Done
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  ✓  Reconix is ready to use!${RESET}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Run with: ${CYAN}sudo python3 reconix.py <target>${RESET}"
echo -e "  Help:     ${CYAN}sudo python3 reconix.py -h${RESET}"
echo ""
