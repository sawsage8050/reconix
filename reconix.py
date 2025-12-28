#!/usr/bin/env python3
"""
Reconix - Advanced Network Reconnaissance Tool
A comprehensive network mapping and vulnerability assessment tool
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

# Global variable to store scan results
SCAN_RESULTS = []

def print_logo():
    """Display the Reconix logo"""
    logo = f"""
{CYAN}{BOLD}
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝ 
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗ 
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
{RESET}
{YELLOW}            Advanced Network Reconnaissance Tool v1.0{RESET}
{WHITE}            ─────────────────────────────────────────{RESET}
{GREEN}            Author: CyberSec Student | Educational Use Only{RESET}
{WHITE}            ─────────────────────────────────────────{RESET}
"""
    print(logo)
    time.sleep(1)

def print_help():
    """Display custom help menu"""
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
    """Animate text printing"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def print_status(message, status='info'):
    """Print formatted status messages"""
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
    """Check if a tool is installed"""
    try:
        subprocess.run([tool_name, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def discover_hosts(network, aggressive=False):
    """Discover active hosts on the network"""
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
    """Perform comprehensive scan on a host"""
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
    
    nmap_args.extend(['-sV', '-O', '--osscan-guess', '-sC'])
    
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
                    version = port_info.get('version', 'unknown')
                    product = port_info.get('product', '')
                    
                    port_data = {
                        'port': port,
                        'state': port_info['state'],
                        'service': service,
                        'version': f"{product} {version}".strip(),
                        'vulnerabilities': []
                    }
                    
                    if service in VULN_DB:
                        for vuln_version, vulns in VULN_DB[service].items():
                            if vuln_version.lower() in version.lower() or vuln_version.lower() in product.lower():
                                port_data['vulnerabilities'].extend(vulns)
                    
                    host_data['ports'].append(port_data)
        
        if args and not args.quiet:
            print_status(f"Scan complete for {host}", 'success')
        
    except Exception as e:
        print_status(f"Error scanning {host}: {e}", 'error')
    
    return host_data

def print_tree_structure(scan_results):
    """Print network tree structure"""
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
    """Print detailed scan report"""
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
                print(f"  {port['port']:<8} {port['service']:<15} {port['version']:<30} {vuln_indicator}")
                
                if port['vulnerabilities']:
                    for vuln in port['vulnerabilities']:
                        print(f"       {RED}└─ ⚠ {vuln}{RESET}")
        else:
            print(f"  {YELLOW}No open ports detected{RESET}")
        
        print()

def save_report(scan_results, filename='reconix_report.json'):
    """Save scan results to file"""
    print_status(f"Saving report to {filename}...", 'info')
    
    try:
        with open(filename, 'w') as f:
            json.dump(scan_results, f, indent=4)
        print_status(f"Report saved successfully to {GREEN}{filename}{RESET}", 'success')
    except Exception as e:
        print_status(f"Error saving report: {e}", 'error')

def interactive_menu(scan_results):
    """Interactive post-scan menu"""
    global SCAN_RESULTS
    SCAN_RESULTS = scan_results
    
    while True:
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{CYAN}║              WHAT WOULD YOU LIKE TO DO NEXT?                 ║{RESET}")
        print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
        
        print(f"{GREEN}[1]{RESET}  🔍 Deep Vulnerability Analysis (searchsploit)")
        print(f"{GREEN}[2]{RESET}  🎯 Attempt Exploitation (Metasploit)")
        print(f"{GREEN}[3]{RESET}  🔨 Brute Force Attacks (SSH/SMB/RDP)")
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

def deep_vulnerability_analysis(scan_results):
    """Deep vulnerability analysis with searchsploit"""
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
                print(f"{YELLOW}[~] Searching: {port['service']} {port['version']}{RESET}")
                
                try:
                    search_term = f"{port['service']} {port['version']}"
                    result_cmd = subprocess.run(['searchsploit', search_term], 
                                              capture_output=True, text=True, timeout=10)
                    
                    if result_cmd.stdout and len(result_cmd.stdout.strip()) > 100:
                        print(f"{GREEN}[+] Exploits found!{RESET}\n")
                        print(result_cmd.stdout)
                        vulnerabilities_found.append({
                            'host': result['ip'],
                            'port': port['port'],
                            'service': f"{port['service']} {port['version']}"
                        })
                    else:
                        print(f"{BLUE}[*] No exploits found{RESET}\n")
                except Exception as e:
                    print_status(f"Error: {e}", 'error')
    
    if vulnerabilities_found:
        print(f"\n{RED}{BOLD}[!] VULNERABLE SERVICES SUMMARY{RESET}")
        for vuln in vulnerabilities_found:
            print(f"{YELLOW}• {vuln['host']}:{vuln['port']} - {vuln['service']}{RESET}")
    
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def attempt_exploitation(scan_results):
    """Exploitation module"""
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
                        'vuln': vuln
                    })
    
    if not vuln_list:
        print_status("No vulnerabilities found!", 'warning')
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        return
    
    print(f"{YELLOW}Found Vulnerabilities:{RESET}\n")
    for idx, vuln in enumerate(vuln_list, 1):
        print(f"{GREEN}[{idx}]{RESET} {vuln['host']}:{vuln['port']} - {vuln['service']} {vuln['version']}")
        print(f"    {RED}└─ {vuln['vuln']}{RESET}\n")
    
    try:
        choice = int(input(f"{CYAN}Select vulnerability (0 to cancel): {RESET}"))
        
        if choice == 0 or choice > len(vuln_list):
            return
        
        selected = vuln_list[choice - 1]
        
        print(f"\n{YELLOW}Target: {selected['host']}:{selected['port']}{RESET}")
        print(f"{YELLOW}Vulnerability: {selected['vuln']}{RESET}\n")
        
        lhost = input(f"{CYAN}LHOST (your IP): {RESET}")
        lport = input(f"{CYAN}LPORT (your port): {RESET}")
        
        print(f"\n{GREEN}Metasploit commands:{RESET}\n")
        print(f"{CYAN}msfconsole{RESET}")
        print(f"{CYAN}search {selected['service']} {selected['version']}{RESET}")
        print(f"{CYAN}use [exploit]{RESET}")
        print(f"{CYAN}set RHOSTS {selected['host']}{RESET}")
        print(f"{CYAN}set RPORT {selected['port']}{RESET}")
        print(f"{CYAN}set LHOST {lhost}{RESET}")
        print(f"{CYAN}set LPORT {lport}{RESET}")
        print(f"{CYAN}exploit{RESET}\n")
        
    except ValueError:
        print_status("Invalid input!", 'error')
    
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def brute_force_attack(scan_results):
    """Brute force module"""
    print(f"\n{BOLD}{RED}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{RED}║           🔨 BRUTE FORCE MODULE                              ║{RESET}")
    print(f"{BOLD}{RED}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
    
    if not check_tool('hydra'):
        print_status("hydra not found! Install: sudo apt install hydra", 'error')
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        return
    
    services_found = {}
    for result in scan_results:
        for port in result['ports']:
            if port['state'] == 'open' and port['service'] in ['ssh', 'ftp', 'smb', 'rdp']:
                if port['service'] not in services_found:
                    services_found[port['service']] = []
                services_found[port['service']].append({'host': result['ip'], 'port': port['port']})
    
    if not services_found:
        print_status("No brute-forceable services found!", 'warning')
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        return
    
    print(f"{YELLOW}Available services:{RESET}\n")
    service_list = list(services_found.keys())
    for idx, service in enumerate(service_list, 1):
        print(f"{GREEN}[{idx}]{RESET} {service.upper()} - {len(services_found[service])} host(s)")
    
    try:
        choice = int(input(f"\n{CYAN}Select service (0=cancel): {RESET}"))
        if choice == 0 or choice > len(service_list):
            return
        
        selected_service = service_list[choice - 1]
        targets = services_found[selected_service]
        
        print(f"\n{YELLOW}Targets:{RESET}")
        for idx, target in enumerate(targets, 1):
            print(f"{GREEN}[{idx}]{RESET} {target['host']}:{target['port']}")
        
        target_choice = int(input(f"\n{CYAN}Select target (0=all): {RESET}"))
        
        print(f"\n{YELLOW}Attack mode:{RESET}")
        print(f"{GREEN}[1]{RESET} Password Spray (user_list + single_pass)")
        print(f"{GREEN}[2]{RESET} User Spray (single_user + pass_list)")
        print(f"{GREEN}[3]{RESET} Full Brute Force (user_list + pass_list)")
        
        mode = int(input(f"\n{CYAN}Select mode: {RESET}"))
        
        if mode == 1:
            user_file = input(f"{CYAN}Username list path: {RESET}")
            password = input(f"{CYAN}Password to spray: {RESET}")
            
            if target_choice == 0:
                for target in targets:
                    print(f"\n{YELLOW}[~] Attacking {target['host']}...{RESET}")
                    os.system(f"hydra -L {user_file} -p {password} {selected_service}://{target['host']}:{target['port']}")
            else:
                target = targets[target_choice - 1]
                os.system(f"hydra -L {user_file} -p {password} {selected_service}://{target['host']}:{target['port']}")
        
        elif mode == 2:
            username = input(f"{CYAN}Username: {RESET}")
            pass_file = input(f"{CYAN}Password list path: {RESET}")
            
            if target_choice == 0:
                for target in targets:
                    print(f"\n{YELLOW}[~] Attacking {target['host']}...{RESET}")
                    os.system(f"hydra -l {username} -P {pass_file} {selected_service}://{target['host']}:{target['port']}")
            else:
                target = targets[target_choice - 1]
                os.system(f"hydra -l {username} -P {pass_file} {selected_service}://{target['host']}:{target['port']}")
        
        elif mode == 3:
            user_file = input(f"{CYAN}Username list: {RESET}")
            pass_file = input(f"{CYAN}Password list: {RESET}")
            
            if target_choice == 0:
                for target in targets:
                    print(f"\n{YELLOW}[~] Attacking {target['host']}...{RESET}")
                    os.system(f"hydra -L {user_file} -P {pass_file} {selected_service}://{target['host']}:{target['port']}")
            else:
                target = targets[target_choice - 1]
                os.system(f"hydra -L {user_file} -P {pass_file} {selected_service}://{target['host']}:{target['port']}")
        
    except Exception as e:
        print_status(f"Error: {e}", 'error')
    
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def generate_security_report(scan_results):
    """Generate HTML report"""
    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{BLUE}║           📊 SECURITY REPORT GENERATOR                       ║{RESET}")
    print(f"{BOLD}{BLUE}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
    
    filename = f"reconix_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    html = f"""<!DOCTYPE html>
<html><head><title>Reconix Report</title>
<style>
body {{font-family:Arial;margin:20px;background:#f5f5f5}}
.header {{background:#2c3e50;color:white;padding:20px;border-radius:5px}}
.host {{background:white;margin:20px 0;padding:20px;border-radius:5px}}
.vuln {{color:#e74c3c;font-weight:bold}}
table {{width:100%;border-collapse:collapse}}
th,td {{padding:10px;border-bottom:1px solid #ddd}}
th {{background:#34495e;color:white}}
</style></head><body>
<div class="header"><h1>Reconix Security Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p></div>
"""
    
    for result in scan_results:
        open_ports = [p for p in result['ports'] if p['state'] == 'open']
        vuln_count = sum(len(p['vulnerabilities']) for p in open_ports)
        
        html += f"""<div class="host"><h2>Host: {result['ip']}</h2>
<p><b>Hostname:</b> {result['hostname']}</p>
<p><b>OS:</b> {result['os']}</p>
<p><b>Vulnerabilities:</b> <span class="vuln">{vuln_count}</span></p>
<table><tr><th>Port</th><th>Service</th><th>Version</th><th>Vulnerabilities</th></tr>
"""
        
        for port in open_ports:
            vulns = '<br>'.join(port['vulnerabilities']) if port['vulnerabilities'] else 'None'
            html += f"<tr><td>{port['port']}</td><td>{port['service']}</td><td>{port['version']}</td><td>{vulns}</td></tr>"
        
        html += "</table></div>"
    
    html += "</body></html>"
    
    try:
        with open(filename, 'w') as f:
            f.write(html)
        print_status(f"Report saved: {GREEN}{filename}{RESET}", 'success')
    except Exception as e:
        print_status(f"Error: {e}", 'error')
    
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def smb_enumeration(scan_results):
    """SMB enumeration"""
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║           🗂️  SMB ENUMERATION                                ║{RESET}")
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
    
    print(f"{YELLOW}SMB Hosts:{RESET}")
    for idx, host in enumerate(smb_hosts, 1):
        print(f"{GREEN}[{idx}]{RESET} {host}")
    
    try:
        choice = int(input(f"\n{CYAN}Select host (0=cancel): {RESET}"))
        if choice == 0 or choice > len(smb_hosts):
            return
        
        target = smb_hosts[choice - 1]
        
        print(f"\n{YELLOW}[~] Enumerating {target}...{RESET}\n")
        os.system(f"smbclient -L //{target} -N")
        
        download = input(f"\n{CYAN}Download shares? (y/n): {RESET}").lower()
        
        if download == 'y':
            share = input(f"{CYAN}Share name (or 'all'): {RESET}")
            
            if share.lower() == 'all':
                os.system(f"smbget -R smb://{target}/* -U guest%")
            else:
                output_dir = f"smb_{target}_{share}"
                os.makedirs(output_dir, exist_ok=True)
                os.system(f"smbget -R smb://{target}/{share} -U guest%")
    
    except Exception as e:
        print_status(f"Error: {e}", 'error')
    
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def web_application_scan(scan_results):
    """Web scanning"""
    print(f"\n{BOLD}{MAGENTA}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{MAGENTA}║           🌐 WEB APPLICATION SCANNING                        ║{RESET}")
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
        url = f"{target['protocol']}://{target['host']}:{target['port']}"
        
        wordlist = input(f"{CYAN}Wordlist path (Enter=default): {RESET}").strip()
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        
        print(f"\n{YELLOW}[~] Scanning {url}...{RESET}\n")
        
        if check_tool('gobuster'):
            os.system(f"gobuster dir -u {url} -w {wordlist} -t 50")
        elif check_tool('dirb'):
            os.system(f"dirb {url} {wordlist}")
        else:
            print_status("gobuster/dirb not found!", 'error')
    
    except Exception as e:
        print_status(f"Error: {e}", 'error')
    
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def hardening_recommendations(scan_results):
    """Security hardening recommendations"""
    print(f"\n{BOLD}{GREEN}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{GREEN}║           🛡️  HARDENING RECOMMENDATIONS                       ║{RESET}")
    print(f"{BOLD}{GREEN}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
    
    for result in scan_results:
        print(f"{CYAN}[*] {result['ip']}{RESET}\n")
        
        for port in result['ports']:
            if port['state'] == 'open':
                if port['service'] == 'ftp':
                    print(f"  🔒 Port {port['port']} (FTP): Use SFTP instead")
                elif port['service'] == 'telnet':
                    print(f"  ⚠️  Port {port['port']} (Telnet): CRITICAL - Use SSH!")
                elif port['service'] == 'ssh':
                    print(f"  🔐 Port {port['port']} (SSH): Key-based auth, disable root")
                elif port['service'] in ['http', 'https']:
                    print(f"  🌐 Port {port['port']}: Enable HTTPS, strong ciphers")
                elif port['port'] in [139, 445]:
                    print(f"  📁 Port {port['port']} (SMB): Disable SMBv1")
                elif port['port'] == 3389:
                    print(f"  🖥️  Port {port['port']} (RDP): NLA, strong passwords")
        print()
    
    print(f"{BOLD}{CYAN}General Recommendations:{RESET}\n")
    print("  🔥 Implement firewall with strict rules")
    print("  🔄 Keep systems updated")
    print("  👥 Strong passwords + MFA")
    print("  📊 Enable logging and monitoring")
    print("  🛡️  Use IDS/IPS systems")
    print("  🔒 Encrypt sensitive data")
    print("  🚫 Close unused ports\n")
    
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def mitm_with_responder():
    """MITM with Responder"""
    print(f"\n{BOLD}{RED}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{RED}║           🔴 MAN-IN-THE-MIDDLE (RESPONDER)                   ║{RESET}")
    print(f"{BOLD}{RED}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
    
    if not check_tool('responder'):
        print_status("Responder not found! Install: sudo apt install responder", 'error')
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        return
    
    print(f"{YELLOW}Interfaces:{RESET}")
    os.system("ip -br a")
    
    interface = input(f"\n{CYAN}Interface (e.g., eth0): {RESET}")
    
    print(f"\n{YELLOW}Options:{RESET}")
    print(f"{GREEN}[1]{RESET} Standard (HTTP, SMB, SQL)")
    print(f"{GREEN}[2]{RESET} Analyze mode (no poisoning)")
    print(f"{GREEN}[3]{RESET} Full poisoning")
    
    try:
        mode = int(input(f"\n{CYAN}Select mode: {RESET}"))
        
        if mode == 1:
            print(f"\n{RED}[!] Starting Responder...{RESET}\n")
            os.system(f"sudo responder -I {interface}")
        elif mode == 2:
            os.system(f"sudo responder -I {interface} -A")
        elif mode == 3:
            os.system(f"sudo responder -I {interface} -wrf")
    except Exception as e:
        print_status(f"Error: {e}", 'error')
    
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def parse_arguments():
    """Parse arguments"""
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
    """Main function"""
    global RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, BOLD, RESET
    
    args = parse_arguments()
    
    if args.help or (not args.target and len(sys.argv) == 1):
        print_help()
        sys.exit(0)
    
    if args.version:
        print(f"{CYAN}{BOLD}Reconix v1.0{RESET}")
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
        
        # Interactive menu
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
