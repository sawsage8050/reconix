# Reconix

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
```

**Network reconnaissance tool with interactive post-scan menu**

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

---

## What is this?

Reconix is a network reconnaissance and enumeration tool that wraps around **nmap** and other common penetration testing utilities.
After completing a scan, it provides an **interactive post-scan menu** that allows further enumeration, exploitation assistance, and reporting.

The goal is to automate repetitive recon tasks and provide a clean workflow instead of manually running the same commands over and over.

---

## Features

### Scanning

* Host discovery (including aggressive mode to reduce false positives)
* Port scanning (fast, normal, or full 65535 ports)
* Service and version detection
* OS fingerprinting
* Network topology visualization

### Post-Scan Modules

* SearchSploit integration for exploit discovery
* Metasploit command generation
* Brute force attacks (password spray, user spray, full brute)
* SMB share enumeration and file download
* Web directory enumeration
* Security hardening recommendations
* Responder for MITM attacks
* HTML report generation

---

## Installation

### Requirements

* Linux (tested on Kali Linux)
* Python 3.8+
* Root access

### Quick Install

```bash
git clone https://github.com/sawsage8050/reconix.git
cd reconix
chmod +x installer.sh
sudo ./installer.sh
```

The installer script sets up all dependencies including:

* nmap
* python-nmap
* searchsploit
* hydra
* smbclient
* gobuster
* responder
* common wordlists

---

### Manual Install

```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap exploitdb hydra
sudo apt install -y smbclient enum4linux gobuster dirb responder
pip3 install python-nmap
```

---

## Usage

### Basic Syntax

```bash
sudo python3 reconix.py [options] <target>
```

### Common Options

```
-PA, --aggressive-discovery    Accurate host discovery (recommended)
-sF, --fast                    Scan top 100 ports only
-sA, --all-ports               Scan all 65535 ports
-T4                            Aggressive timing
-o, --output <file>            Save results to JSON
-h, --help                     Show help menu
```

---

### Examples

```bash
# Basic scan
sudo python3 reconix.py 192.168.1.0/24

# Accurate host discovery (reduces false positives)
sudo python3 reconix.py -PA 172.16.8.0/24

# Fast scan
sudo python3 reconix.py -sF -T4 10.0.0.0/24

# Scan all ports on a single host
sudo python3 reconix.py -sA 192.168.1.100
```

---

## Interactive Menu

After the scan completes, Reconix presents an interactive menu:

```
[1] Deep Vulnerability Analysis - SearchSploit lookup
[2] Attempt Exploitation - Metasploit helper
[3] Brute Force Attacks - Hydra wrapper
[4] Generate Security Report - HTML output
[5] SMB Share Enumeration - List and download shares
[6] Web Application Scanning - Gobuster / Dirb
[7] Get Hardening Recommendations
[8] Man-in-the-Middle - Responder
[9] Re-scan Options
[0] Exit
```

Select a number and follow the prompts.

---

## Testing & Lab Setup

**Do NOT scan random systems on the internet. That is illegal.**

### Legal Testing Options

* Your own home network
* Vulnerable VMs (Metasploitable 2 / 3 from VulnHub)
* Docker labs (DVWA, Juice Shop)
* College or corporate labs **with permission**

### Quick Lab Setup Example

```bash
# Download VirtualBox
# Import Metasploitable 2 from VulnHub
# Set network adapter to Host-Only
sudo python3 reconix.py -PA 192.168.56.0/24
```

---

## Wordlists

Default wordlist locations:

```
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/dirb/common.txt
/usr/share/seclists/
```

Custom wordlists can be supplied when prompted by entering the full path.

---

## Output

Reconix generates the following files and directories:

* `reconix_report.json` – Default scan results
* `reconix_report_YYYYMMDD_HHMMSS.html` – HTML report
* `smb_<IP>_<share>/` – Downloaded SMB files

---

## Contributing

Pull requests are welcome.

* Keep changes minimal and focused
* Test before submitting
* Follow existing code style

---

## Legal Disclaimer

**This tool is for authorized security testing only.**

* Obtain explicit permission before scanning
* Only test systems you own or are authorized to assess
* Unauthorized scanning is illegal

I am not responsible for misuse of this tool.

---

## License

This project is licensed under the **MIT License**.
See the `LICENSE` file for details.

---

## Credits

Built using:

* Nmap
* Metasploit Framework
* Hydra
* Responder
* Gobuster
* SearchSploit
* SecLists

---

## Author

GitHub: [@sawsage8050](https://github.com/Aditya-k-Jangid)

---

## Known Issues

* Aggressive discovery mode is slower but more accurate
* Some wordlists may require manual extraction
* Metasploit integration only generates commands (manual execution required)

---

## TODO

* Database storage
* Optional GUI
* Improved error handling
* Additional exploitation modules
* Custom NSE script support

---

