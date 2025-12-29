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

Reconix is a network scanning tool that wraps around nmap and other common pentesting tools. After scanning a network, it gives you an interactive menu to do more stuff like vulnerability analysis, brute forcing, SMB enumeration, etc. Basically saves you from typing the same commands over and over.

## Features

**Scanning:**
- Host discovery (with an aggressive mode that actually works)
- Port scanning (fast, normal, or all 65535 ports)
- Service version detection
- OS fingerprinting
- Network topology visualization

**Post-Scan Modules:**
- Searchsploit integration for finding exploits
- Metasploit command generation
- Brute force attacks (password spray, user spray, full brute)
- SMB share enumeration and download
- Web directory enumeration
- Security hardening recommendations
- Responder for MITM attacks
- HTML report generation

## Installation

**Requirements:**
- Linux (tested on Kali)
- Python 3.8+
- Root access

**Quick Install:**

```bash
git clone https://github.com/sawsage8050/reconix.git
cd reconix
chmod +x install.sh
sudo ./install.sh
```

The script installs everything: python-nmap, nmap, searchsploit, hydra, smbclient, gobuster, responder, and wordlists.

**Manual Install:**

```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap exploitdb hydra
sudo apt install -y smbclient enum4linux gobuster dirb responder
pip3 install python-nmap
```

## Usage

**Basic syntax:**
```bash
sudo python3 reconix.py [options] <target>
```

**Common options:**
```
-PA, --aggressive-discovery    Accurate host discovery (recommended)
-sF, --fast                    Scan top 100 ports only
-sA, --all-ports               Scan all 65535 ports
-T4                            Aggressive timing
-o, --output <file>            Save to JSON
-h, --help                     Show help
```

**Examples:**

```bash
# Basic scan
sudo python3 reconix.py 192.168.1.0/24

# Accurate host discovery (fixes false positives)
sudo python3 reconix.py -PA 172.16.8.0/24

# Fast scan
sudo python3 reconix.py -sF -T4 10.0.0.0/24

# Scan all ports
sudo python3 reconix.py -sA 192.168.1.100
```

## Interactive Menu

After scanning, you get a menu:

```
[1] Deep Vulnerability Analysis - searchsploit lookup
[2] Attempt Exploitation - Metasploit helper
[3] Brute Force Attacks - hydra wrapper
[4] Generate Security Report - HTML output
[5] SMB Share Enumeration - list and download shares
[6] Web Application Scanning - gobuster/dirb
[7] Get Hardening Recommendations - security tips
[8] Man-in-the-Middle - responder
[9] Re-scan Options
[0] Exit
```

Pick a number and follow the prompts.

## Testing

Don't scan random stuff on the internet - that's illegal.

**Legal testing options:**
- Your own home network
- Download Metasploitable 2 or 3 (vulnerable VMs from VulnHub)
- Set up Docker containers with DVWA or Juice Shop
- Use your college lab (with permission)

**Quick lab setup:**
```bash
# Download VirtualBox
# Get Metasploitable 2 from VulnHub
# Set network to Host-Only
# Scan: sudo python3 reconix.py -PA 192.168.56.0/24
```

## Wordlists

Default locations:
```
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/dirb/common.txt
/usr/share/seclists/
```

You can use custom wordlists by providing the full path when prompted.

## Output

Reconix creates:
- `reconix_report.json` - Default scan results
- `reconix_report_YYYYMMDD_HHMMSS.html` - HTML reports
- `smb_<IP>_<share>/` - Downloaded SMB files

## Contributing

Pull requests welcome. Keep it simple and test before submitting.

## Legal Stuff

**This tool is for authorized testing only.**

- Get permission before scanning anything
- Only scan networks you own
- Unauthorized scanning is illegal
- I'm not responsible if you do stupid things

Seriously, don't be that guy who scans his university network and gets expelled.

## License

MIT License - do whatever you want with it.

## Credits

Built using:
- Nmap
- Metasploit Framework
- Hydra
- Responder
- Gobuster
- SearchSploit
- SecLists

## Author

GitHub: [@sawsage8050](https://github.com/sawsage8050)

## Known Issues

- Aggressive discovery mode is slower but more accurate
- Some wordlists might need manual extraction
- Metasploit integration is just command generation (you still need to run msfconsole)

## TODO

- Add database storage
- GUI maybe?
- Better error handling
- More exploitation modules
- Custom NSE script support
