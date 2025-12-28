#!/bin/bash

# Reconix - Master Installation Script
# This script installs ALL Python modules AND system tools

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
cat << "EOF"
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝ 
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗ 
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
EOF
echo -e "${NC}"
echo -e "${YELLOW}${BOLD}        RECONIX MASTER INSTALLER${NC}"
echo -e "${CYAN}        Installing all dependencies...${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Please run as root: ${YELLOW}sudo ./install.sh${NC}"
    exit 1
fi

echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║              STEP 1: SYSTEM PREPARATION                    ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Update package list
echo -e "${CYAN}[1/12] Updating package list...${NC}"
apt update -qq
echo -e "${GREEN}[✓] Package list updated${NC}"
echo ""

# Install Python3 and pip
echo -e "${CYAN}[2/12] Installing Python3 and pip...${NC}"
apt install -y python3 python3-pip python3-venv > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] Python3 and pip installed${NC}"
else
    echo -e "${YELLOW}[!] Python3 already installed or error occurred${NC}"
fi
echo ""

echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║              STEP 2: PYTHON MODULES                        ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Install python-nmap
echo -e "${CYAN}[3/12] Installing python-nmap module...${NC}"
pip3 install python-nmap --break-system-packages > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] python-nmap installed${NC}"
else
    echo -e "${YELLOW}[!] Trying alternative installation method...${NC}"
    python3 -m pip install python-nmap > /dev/null 2>&1
    echo -e "${GREEN}[✓] python-nmap installed${NC}"
fi
echo ""

echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║              STEP 3: SCANNING TOOLS                        ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Install Nmap
echo -e "${CYAN}[4/12] Installing Nmap...${NC}"
apt install -y nmap > /dev/null 2>&1
if command -v nmap &> /dev/null; then
    echo -e "${GREEN}[✓] Nmap installed ($(nmap --version | head -1))${NC}"
else
    echo -e "${RED}[✗] Failed to install Nmap${NC}"
fi
echo ""

# Install searchsploit (exploitdb)
echo -e "${CYAN}[5/12] Installing searchsploit (exploitdb)...${NC}"
apt install -y exploitdb > /dev/null 2>&1
if command -v searchsploit &> /dev/null; then
    echo -e "${GREEN}[✓] searchsploit installed${NC}"
    echo -e "${YELLOW}[*] Updating exploit database...${NC}"
    searchsploit -u > /dev/null 2>&1
    echo -e "${GREEN}[✓] Exploit database updated${NC}"
else
    echo -e "${RED}[✗] Failed to install searchsploit${NC}"
fi
echo ""

echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║              STEP 4: EXPLOITATION TOOLS                    ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Install Metasploit Framework
echo -e "${CYAN}[6/12] Checking Metasploit Framework...${NC}"
if command -v msfconsole &> /dev/null; then
    echo -e "${GREEN}[✓] Metasploit already installed${NC}"
else
    echo -e "${YELLOW}[!] Metasploit not found. Installing (this may take 5-10 minutes)...${NC}"
    apt install -y metasploit-framework > /dev/null 2>&1
    if command -v msfconsole &> /dev/null; then
        echo -e "${GREEN}[✓] Metasploit installed${NC}"
    else
        echo -e "${YELLOW}[!] Metasploit installation skipped or failed${NC}"
        echo -e "${YELLOW}[!] You can install manually: sudo apt install metasploit-framework${NC}"
    fi
fi
echo ""

echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║              STEP 5: BRUTE FORCE TOOLS                     ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Install Hydra
echo -e "${CYAN}[7/12] Installing Hydra (brute force tool)...${NC}"
apt install -y hydra > /dev/null 2>&1
if command -v hydra &> /dev/null; then
    echo -e "${GREEN}[✓] Hydra installed${NC}"
else
    echo -e "${RED}[✗] Failed to install Hydra${NC}"
fi
echo ""

echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║              STEP 6: SMB ENUMERATION TOOLS                 ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Install SMB tools
echo -e "${CYAN}[8/12] Installing SMB tools (smbclient, enum4linux, smbmap)...${NC}"
apt install -y smbclient enum4linux smbmap cifs-utils > /dev/null 2>&1
if command -v smbclient &> /dev/null; then
    echo -e "${GREEN}[✓] SMB tools installed${NC}"
else
    echo -e "${RED}[✗] Failed to install SMB tools${NC}"
fi
echo ""

echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║              STEP 7: WEB SCANNING TOOLS                    ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Install web scanning tools
echo -e "${CYAN}[9/12] Installing web scanning tools (gobuster, dirb, nikto)...${NC}"
apt install -y gobuster dirb nikto > /dev/null 2>&1
if command -v gobuster &> /dev/null; then
    echo -e "${GREEN}[✓] Web scanning tools installed${NC}"
else
    echo -e "${RED}[✗] Failed to install web tools${NC}"
fi
echo ""

echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║              STEP 8: MITM TOOLS                            ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Install Responder
echo -e "${CYAN}[10/12] Installing Responder (MITM tool)...${NC}"
apt install -y responder > /dev/null 2>&1
if command -v responder &> /dev/null; then
    echo -e "${GREEN}[✓] Responder installed${NC}"
else
    echo -e "${RED}[✗] Failed to install Responder${NC}"
fi
echo ""

echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║              STEP 9: WORDLISTS                             ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Install wordlists
echo -e "${CYAN}[11/12] Installing wordlists (SecLists, rockyou)...${NC}"
apt install -y seclists wordlists > /dev/null 2>&1

# Check if rockyou exists and extract if needed
if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
    echo -e "${YELLOW}[*] Extracting rockyou.txt...${NC}"
    gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
fi

if [ -f "/usr/share/wordlists/rockyou.txt" ]; then
    echo -e "${GREEN}[✓] Wordlists installed and ready${NC}"
else
    echo -e "${YELLOW}[!] Some wordlists may be missing${NC}"
fi
echo ""

echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║              STEP 10: FINALIZING                           ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Make reconix.py executable
echo -e "${CYAN}[12/12] Making Reconix executable...${NC}"
if [ -f "reconix.py" ]; then
    chmod +x reconix.py
    echo -e "${GREEN}[✓] Reconix is now executable${NC}"
else
    echo -e "${YELLOW}[!] reconix.py not found in current directory${NC}"
    echo -e "${YELLOW}[!] Please ensure reconix.py is in the same folder${NC}"
fi
echo ""

# Installation complete banner
echo -e "${GREEN}${BOLD}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                 INSTALLATION COMPLETE!                       ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Verification section
echo -e "${YELLOW}${BOLD}[*] Verifying installations...${NC}\n"

tools=(
    "nmap:Nmap (Network Scanner)"
    "searchsploit:Searchsploit (Exploit DB)"
    "msfconsole:Metasploit Framework"
    "hydra:Hydra (Brute Force)"
    "smbclient:SMB Client"
    "gobuster:Gobuster (Web Scanner)"
    "responder:Responder (MITM)"
)

installed_count=0
total_count=${#tools[@]}

for tool_entry in "${tools[@]}"; do
    IFS=':' read -r tool_cmd tool_name <<< "$tool_entry"
    if command -v $tool_cmd &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} $tool_name"
        ((installed_count++))
    else
        echo -e "${RED}[✗]${NC} $tool_name ${RED}(not found)${NC}"
    fi
done

# Python modules check
echo ""
echo -e "${YELLOW}${BOLD}[*] Checking Python modules...${NC}\n"

python3 -c "import nmap" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} python-nmap"
    ((installed_count++))
else
    echo -e "${RED}[✗]${NC} python-nmap ${RED}(not found)${NC}"
fi

# Summary
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║                    INSTALLATION SUMMARY                      ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Installed: $installed_count / $((total_count + 1))${NC}"
echo ""

# Additional recommendations
echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}${BOLD}║                  QUICK START GUIDE                           ║${NC}"
echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}1. View help menu:${NC}"
echo -e "   ${WHITE}sudo python3 reconix.py -h${NC}"
echo ""
echo -e "${CYAN}2. Basic scan:${NC}"
echo -e "   ${WHITE}sudo python3 reconix.py 192.168.1.0/24${NC}"
echo ""
echo -e "${CYAN}3. Accurate host discovery:${NC}"
echo -e "   ${WHITE}sudo python3 reconix.py -PA 172.16.8.0/24${NC}"
echo ""
echo -e "${CYAN}4. Fast scan with aggressive timing:${NC}"
echo -e "   ${WHITE}sudo python3 reconix.py -sF -T4 192.168.1.0/24${NC}"
echo ""
echo -e "${CYAN}5. Scan all ports:${NC}"
echo -e "   ${WHITE}sudo python3 reconix.py -sA 192.168.1.100${NC}"
echo ""

# Wordlist locations
echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}${BOLD}║                  USEFUL WORDLIST PATHS                       ║${NC}"
echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Common wordlists:${NC}"
echo -e "  ${WHITE}/usr/share/wordlists/rockyou.txt${NC}         (Passwords)"
echo -e "  ${WHITE}/usr/share/wordlists/dirb/common.txt${NC}     (Web directories)"
echo -e "  ${WHITE}/usr/share/seclists/${NC}                     (SecLists collection)"
echo ""

# Warning
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}${BOLD}║                        WARNING                               ║${NC}"
echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${RED}This tool is for ${BOLD}EDUCATIONAL PURPOSES ONLY${NC}${RED}.${NC}"
echo -e "${RED}Only scan networks you ${BOLD}OWN${NC}${RED} or have ${BOLD}WRITTEN PERMISSION${NC}${RED} to test.${NC}"
echo -e "${RED}Unauthorized scanning is ${BOLD}ILLEGAL${NC}${RED} and punishable by law.${NC}"
echo ""

echo -e "${GREEN}${BOLD}Ready to scan! Happy (ethical) hacking! 🚀${NC}"
echo ""
