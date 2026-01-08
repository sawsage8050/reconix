# Reconix

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
```

**Network reconnaissance tool with custom brute force and web fuzzing engines**

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

---

## What is this?

Reconix is a network reconnaissance and enumeration tool built with **custom implementations** of common penetration testing utilities. Instead of relying on external tools like Hydra and Gobuster, Reconix includes **handwritten brute force** and **web fuzzing engines** written in Python.

After completing a scan, it provides an **interactive post-scan menu** that allows further enumeration, exploitation assistance, and reporting - all with minimal external dependencies.

---

## Key Features

### Scanning & Enumeration

* Host discovery with aggressive mode to reduce false positives
* Port scanning (fast, normal, or full 65535 ports)
* Service and version detection
* OS fingerprinting
* Network topology visualization

### Post-Scan Modules

* **SearchSploit integration** - Automatic exploit discovery
* **Metasploit automation** - Creates `.rc` resource scripts and auto-launches msfconsole
* **Brute force attacks** - Custom implementation (no Hydra needed)
* **SMB enumeration** - List shares and recursively download files
* **Web fuzzing** - Custom directory/subdomain/vhost scanner (no Gobuster needed)
* **HTML reports** - Professional reports with interactive charts (Chart.js)
* **Security recommendations** - Automated hardening advice
* **Responder integration** - MITM attacks (optional)

---

## Installation

### Requirements

* Linux (tested on Kali Linux / Parrot OS)
* Python 3.8+
* Root access (for raw sockets and privileged operations)

### Quick Install

```bash
git clone https://github.com/sawsage8050/reconix.git
cd reconix
chmod +x installer.sh
sudo ./installer.sh
```

The installer script sets up:
* System dependencies (nmap, smbclient, exploitdb, responder)
* Python packages (see requirements.txt)
* Common wordlists (SecLists)

---

### Manual Install

#### 1. System Packages

```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap exploitdb
sudo apt install -y smbclient responder git
```

#### 2. Python Dependencies

```bash
pip3 install -r requirements.txt
```

#### 3. Wordlists (Required for fuzzing and brute force)

```bash
# Install SecLists
sudo apt install -y seclists

# Or manually:
sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists

# Extract rockyou.txt (if compressed)
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
```

**Note:** The tool expects wordlists at these locations:
```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-*.txt
```

---

## Usage

### Basic Syntax

```bash
sudo python3 reconix.py [options] <target>
```

### Common Options

```
TARGET:
  <target>              Network or IP (e.g., 192.168.1.0/24, 10.0.0.1)

SCAN OPTIONS:
  -sA, --all-ports      Scan all 65535 ports
  -sF, --fast           Fast scan (top 100 ports)
  -PA, --aggressive-discovery  Accurate host discovery
  -T0 to -T5            Timing (0=slow, 5=fast)

OPTIONS:
  -h, --help            Show help menu
  -v, --verbose         Verbose output
  -q, --quiet           Quiet mode
  -o, --output FILE     Save to JSON file
```

---

### Examples

```bash
# Basic scan
sudo python3 reconix.py 192.168.1.0/24

# Accurate host discovery (reduces false positives)
sudo python3 reconix.py -PA 172.16.8.0/24

# Fast scan with aggressive timing
sudo python3 reconix.py -sF -T4 10.0.0.0/24

# Scan all ports on a single host
sudo python3 reconix.py -sA 192.168.1.100
```

---

## Interactive Menu

After the scan completes, Reconix presents an interactive menu:

```
[1] 🔍 Deep Vulnerability Analysis - SearchSploit lookup
[2] 🎯 Attempt Exploitation - Metasploit automation (.rc scripts)
[3] 🔨 Brute Force Attacks - Custom engine (SSH/FTP/SMB)
[4] 📊 Generate Security Report - HTML with charts
[5] 🗂️  SMB Share Enumeration - List and download shares
[6] 🌐 Web Application Fuzzing - Custom fuzzer (directory/subdomain/vhost)
[7] 🛡️  Get Hardening Recommendations
[8] 🔴 Man-in-the-Middle - Responder
[9] 🔄 Re-scan Options
[0] 🚪 Exit
```

### Module Details

#### [3] Custom Brute Force Engine

Supports 3 attack modes:
1. **Full Brute Force** - Tests all username:password combinations
2. **Password Spray** - Tests one password against all users (stealthier)
3. **Anonymous Login** - Tests anonymous/null authentication

Protocols supported:
* SSH (port 22) - via paramiko
* FTP (port 21) - via ftplib
* SMB (port 445) - via impacket

#### [6] Custom Web Fuzzer

3 fuzzing modes:
1. **Directory Fuzzing** - Enumerate web directories and files
2. **Subdomain Fuzzing** - Discover subdomains via DNS/HTTP
3. **VHost Fuzzing** - Virtual host enumeration (same IP, different hosts)

3 intensity levels:
* LOW (~1,000 requests)
* MEDIUM (~20,000 requests)
* HIGH (~100,000+ requests)

---

## Testing & Lab Setup

**⚠️ Do NOT scan random systems on the internet. That is illegal.**

### Legal Testing Options

* Your own home network
* Vulnerable VMs (Metasploitable 2/3, HackTheBox, TryHackMe)
* Docker labs (DVWA, Juice Shop)
* College or corporate labs **with written permission**

### Quick Lab Setup Example

```bash
# Download VirtualBox and Metasploitable 2
# Set network adapter to Host-Only
# Find the network range:
ip addr show vboxnet0

# Scan the range:
sudo python3 reconix.py -PA 192.168.56.0/24
```

---

## Wordlists

### Default Locations

The tool automatically looks for wordlists here:

```
# Passwords
/usr/share/wordlists/rockyou.txt

# Web directories
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Subdomains
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

### Custom Wordlists

When prompted, you can provide any custom wordlist path:
```
Enter wordlist path: /home/user/custom-passwords.txt
```

---

## Output

Reconix generates these files:

* `reconix_report.json` - Scan results in JSON format
* `reconix_report_YYYYMMDD_HHMMSS.html` - Professional HTML report with charts
* `reconix_exploit_YYYYMMDD_HHMMSS.rc` - Metasploit resource scripts
* `smb_<IP>/` - Downloaded SMB share contents

---

## Why Custom Implementations?

### Advantages

✅ **Easier Installation** - Just `pip install -r requirements.txt`  
✅ **No External Dependencies** - No need for Hydra, Gobuster, etc.  
✅ **Full Control** - Customize behavior exactly as needed  
✅ **Better Error Handling** - Python exceptions vs parsing tool output  
✅ **Cross-Platform** - Pure Python works anywhere  
✅ **Learning Experience** - Understand how attacks actually work  

### Performance

* **Brute Force:** Multi-threaded (comparable to Hydra for most use cases)
* **Web Fuzzing:** 30 concurrent threads (slightly slower than Go-based tools but sufficient)

For maximum speed on huge wordlists, consider using the original tools (Hydra, ffuf). For 99% of use cases, the custom implementations are fast enough.

---

## Contributing

Pull requests are welcome.

* Keep changes minimal and focused
* Test before submitting
* Follow existing code style (PEP 8)
* Add docstrings to new functions

---

## Legal Disclaimer

**This tool is for authorized security testing only.**

* Obtain explicit written permission before scanning
* Only test systems you own or are authorized to assess
* Unauthorized scanning and hacking is illegal

I am not responsible for misuse of this tool. You are solely responsible for your actions.

---

## License

This project is licensed under the **MIT License**.  
See the `LICENSE` file for details.

---

## Credits

### External Tools Used

* **Nmap** (network scanning)
* **Metasploit Framework** (exploitation guidance)
* **Responder** (MITM attacks - optional)
* **SearchSploit** (exploit database)

### Python Libraries

* **python-nmap** (nmap wrapper)
* **paramiko** (SSH protocol)
* **impacket** (SMB/network protocols)
* **requests** (HTTP client)
* **Chart.js** (HTML report charts)

### Wordlists

* **SecLists** by Daniel Miessler
* **RockYou** password list

---

## Author

GitHub: [@sawsage8050](https://github.com/Aditya-k-Jangid)

---

## Known Issues

* Aggressive host discovery (`-PA`) is slower but more accurate
* Some wordlists may require manual extraction (rockyou.txt.gz)
* Metasploit resource scripts require manual review before execution
* VHost fuzzing requires a known domain name
* SMB enumeration may fail on modern Windows with SMB signing enabled

---

## TODO

- [ ] Add HTTP parameter fuzzing
- [ ] Add DNS zone transfer checks
- [ ] Database storage for scan history
- [ ] Optional GUI mode
- [ ] Support for custom NSE scripts
- [ ] Add email/report scheduling
- [ ] Add exploit suggestion AI (based on CVE scores)

---

## Changelog

### v1.0 (Current)
* Custom brute force engine (SSH/FTP/SMB)
* Custom web fuzzer (directory/subdomain/vhost)
* Metasploit automation with resource scripts
* HTML reports with interactive charts
* SMB enumeration and file download
* Removed Hydra and Gobuster dependencies

---

## FAQ

**Q: Why is it asking for wordlists in /usr/share/seclists?**  
A: Install SecLists: `sudo apt install seclists` or provide custom paths when prompted.

**Q: Can I use this on Windows?**  
A: Theoretically yes (Python is cross-platform), but nmap and some features require elevated privileges. Linux is recommended.

**Q: Why is brute forcing so slow?**  
A: Network speed, target rate limiting, and wordlist size affect speed. Use smaller wordlists or increase threads.

**Q: Is this better than using Hydra/Gobuster directly?**  
A: For most pentesting scenarios, yes - easier to install and customize. For maximum performance on huge wordlists, the original C/Go tools are faster.

**Q: Can I contribute new modules?**  
A: Yes! Fork the repo, add your module, and submit a pull request.

---
