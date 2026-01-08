#!/bin/bash

# Reconix Installer Script
# Installs all required dependencies for Reconix

RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
RESET='\033[0m'

echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║           RECONIX DEPENDENCY INSTALLER                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Please run as root (sudo ./installer.sh)${RESET}"
    exit 1
fi

echo -e "${YELLOW}[*] Starting installation...${RESET}\n"

# Update package list
echo -e "${CYAN}[1/5] Updating package list...${RESET}"
apt update -qq

# Install system tools
echo -e "${CYAN}[2/5] Installing system tools...${RESET}"

SYSTEM_TOOLS=(
    "nmap"
    "exploitdb"
    "seclists"
    "python3"
    "python3-pip"
    "git"
)

for tool in "${SYSTEM_TOOLS[@]}"; do
    if dpkg -l | grep -q "^ii  $tool"; then
        echo -e "${GREEN}[✓]${RESET} $tool already installed"
    else
        echo -e "${YELLOW}[*]${RESET} Installing $tool..."
        apt install -y $tool > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓]${RESET} $tool installed successfully"
        else
            echo -e "${RED}[✗]${RESET} Failed to install $tool"
        fi
    fi
done

# Install Metasploit (optional but recommended)
echo -e "\n${CYAN}[3/5] Checking Metasploit Framework...${RESET}"
if command -v msfconsole &> /dev/null; then
    echo -e "${GREEN}[✓]${RESET} Metasploit already installed"
else
    echo -e "${YELLOW}[*]${RESET} Metasploit not found"
    read -p "Install Metasploit? (y/n): " install_msf
    if [ "$install_msf" = "y" ]; then
        echo -e "${YELLOW}[*]${RESET} Installing Metasploit (this may take a while)..."
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
        chmod 755 /tmp/msfinstall
        /tmp/msfinstall
        echo -e "${GREEN}[✓]${RESET} Metasploit installed"
    fi
fi

# Install Responder
echo -e "\n${CYAN}[4/5] Checking Responder...${RESET}"
if command -v responder &> /dev/null; then
    echo -e "${GREEN}[✓]${RESET} Responder already installed"
else
    echo -e "${YELLOW}[*]${RESET} Installing Responder..."
    apt install -y responder > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓]${RESET} Responder installed"
    else
        # Try alternative installation
        echo -e "${YELLOW}[*]${RESET} Trying alternative installation..."
        git clone https://github.com/lgandx/Responder.git /opt/Responder
        ln -s /opt/Responder/Responder.py /usr/local/bin/responder
        chmod +x /opt/Responder/Responder.py
        echo -e "${GREEN}[✓]${RESET} Responder installed to /opt/Responder"
    fi
fi

# Install Python dependencies
echo -e "\n${CYAN}[5/5] Installing Python dependencies...${RESET}"

PYTHON_PACKAGES=(
    "python-nmap"
    "paramiko"
    "impacket"
    "requests"
    "urllib3"
    "cryptography"
    "pyasn1"
    "pycryptodome"
)

for package in "${PYTHON_PACKAGES[@]}"; do
    echo -e "${YELLOW}[*]${RESET} Installing $package..."
    pip3 install $package --break-system-packages > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓]${RESET} $package installed"
    else
        # Try without break-system-packages flag
        pip3 install $package > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓]${RESET} $package installed"
        else
            echo -e "${RED}[✗]${RESET} Failed to install $package"
        fi
    fi
done

# Update searchsploit database
echo -e "\n${CYAN}[*] Updating searchsploit database...${RESET}"
if command -v searchsploit &> /dev/null; then
    searchsploit -u
    echo -e "${GREEN}[✓]${RESET} Searchsploit database updated"
fi

# Verify installations
echo -e "\n${CYAN}════════════════════════════════════════════════════════════${RESET}"
echo -e "${CYAN}                   VERIFICATION${RESET}"
echo -e "${CYAN}════════════════════════════════════════════════════════════${RESET}\n"

# Check system tools
echo -e "${YELLOW}System Tools:${RESET}"
command -v nmap &> /dev/null && echo -e "${GREEN}[✓]${RESET} nmap" || echo -e "${RED}[✗]${RESET} nmap"
command -v searchsploit &> /dev/null && echo -e "${GREEN}[✓]${RESET} searchsploit" || echo -e "${RED}[✗]${RESET} searchsploit"
command -v msfconsole &> /dev/null && echo -e "${GREEN}[✓]${RESET} metasploit" || echo -e "${YELLOW}[!]${RESET} metasploit (optional)"
command -v responder &> /dev/null && echo -e "${GREEN}[✓]${RESET} responder" || echo -e "${YELLOW}[!]${RESET} responder (optional)"
[ -d "/usr/share/seclists" ] && echo -e "${GREEN}[✓]${RESET} seclists" || echo -e "${YELLOW}[!]${RESET} seclists (optional)"

# Check Python packages
echo -e "\n${YELLOW}Python Packages:${RESET}"
python3 -c "import nmap" 2>/dev/null && echo -e "${GREEN}[✓]${RESET} python-nmap" || echo -e "${RED}[✗]${RESET} python-nmap"
python3 -c "import paramiko" 2>/dev/null && echo -e "${GREEN}[✓]${RESET} paramiko" || echo -e "${RED}[✗]${RESET} paramiko"
python3 -c "import impacket" 2>/dev/null && echo -e "${GREEN}[✓]${RESET} impacket" || echo -e "${RED}[✗]${RESET} impacket"
python3 -c "import requests" 2>/dev/null && echo -e "${GREEN}[✓]${RESET} requests" || echo -e "${RED}[✗]${RESET} requests"

echo -e "\n${CYAN}════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}[✓] Installation complete!${RESET}"
echo -e "${CYAN}════════════════════════════════════════════════════════════${RESET}\n"

echo -e "${YELLOW}Usage:${RESET}"
echo -e "  sudo python3 reconix.py <target>"
echo -e "  sudo python3 reconix.py -h\n"

echo -e "${YELLOW}Note:${RESET} Reconix requires root privileges to perform network scans\n"
