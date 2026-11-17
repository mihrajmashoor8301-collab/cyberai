#!/usr/bin/env python3
"""CyberAI Pentest Toolkit - Interactive CLI with menu system"""

import argparse
import sys
import os
import json
import subprocess
import re
from datetime import datetime


# Global target storage
_current_target = None
_current_url = None


def set_target(target):
    """Set the current target (IP or domain)"""
    global _current_target, _current_url
    target = target.strip()
    if not target:
        return False
    # If it looks like a URL, extract the domain
    if target.startswith(('http://', 'https://')):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        _current_target = parsed.hostname or parsed.netloc
        _current_url = target
    else:
        _current_target = target
        _current_url = None
    return True


def get_target():
    """Get the current target. Returns (domain, url_or_none)"""
    return _current_target, _current_url


def clear_target():
    """Clear the current target"""
    global _current_target, _current_url
    _current_target = None
    _current_url = None


def main():
    parser = argparse.ArgumentParser(prog='cyberai', description='CyberAI Pentest Toolkit')
    parser.add_argument('--menu', '-m', action='store_true', help='Start interactive menu')
    parser.add_argument('--target', '-t', help='Set initial target')
    args = parser.parse_args()
    
    if args.target:
        set_target(args.target)
    
    if args.menu or (not args.menu and len(sys.argv) == 1):
        interactive_menu()
    else:
        # Fallback to CLI mode
        from cyberai.cli import main as cli_main
        cli_main()


def interactive_menu():
    """Interactive menu-driven interface"""
    while True:
        clear_screen()
        print_banner()
        print_menu()
        
        try:
            choice = input("\n🔹 Choose option (1-9, q=quit): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n\n👋 Exiting CyberAI...")
            sys.exit(0)
        
        if choice in ('q', 'quit', 'exit'):
            print("\n👋 Exiting CyberAI...")
            sys.exit(0)
        
        try:
            choice_num = int(choice)
        except ValueError:
            print_red("⚠️  Please enter a number (0-9) or 'q' to quit")
            input("\nPress Enter to continue...")
            continue
        
        if choice_num == 0:
            set_target_option()
        elif choice_num == 1:
            run_network_scan()
        elif choice_num == 2:
            run_web_audit()
        elif choice_num == 3:
            run_dirbust()
        elif choice_num == 4:
            run_cve_lookup()
        elif choice_num == 5:
            run_exploit()
        elif choice_num == 6:
            list_exploits()
        elif choice_num == 7:
            generate_report()
        elif choice_num == 8:
            run_full_pentest()
        elif choice_num == 9:
            show_help()
        else:
            print_red("⚠️  Invalid option. Choose 1-9 or 'q' to quit")
            input("\nPress Enter to continue...")


def run_network_scan():
    """Interactive network scan"""
    clear_screen()
    print_banner()
    print_green("\n📡 NETWORK PORT SCANNER")
    print("-" * 50)
    
    # Get stored target
    stored, _ = get_target()
    if stored:
        target = input(f"  Target IP/Domain [{stored}]: ").strip() or stored
    else:
        target = input("  Target IP/Domain: ").strip()
        if not target:
            print_red("  ⚠️  Target is required")
            input("\nPress Enter to continue...")
            return
    
    from reporting.generator import ReportGenerator
    
    print("\n  Scan types:")
    print("  1. Quick scan (top 100 ports)")
    print("  2. Full scan (all ports)")
    print("  3. Vulnerability scan (service + vuln check)")
    
    scan_type = input("  Choose (1-3) [1]: ").strip()
    
    nmap_args = []
    if scan_type == '1':
        nmap_args = ['-sV', '-sC', '-T4', '--top-ports', '100']
    elif scan_type == '2':
        nmap_args = ['-sV', '-sC', '-T4', '-p', '-']
    elif scan_type == '3':
        nmap_args = ['-sV', '--script', 'vuln', '-T4']
    else:
        nmap_args = ['-sV', '-sC', '-T4', '--top-ports', '100']
    
    print(f"\n  [*] Scanning {target}...")
    print(f"  [*] This may take a while...\n")
    
    try:
        result = subprocess.run(
            ['nmap'] + nmap_args + [target],
            capture_output=True, text=True, timeout=600
        )
        
        output = result.stdout
        
        # Parse results
        ports = []
        for line in output.split('\n'):
            port_match = re.match(r'(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)', line)
            if port_match:
                ports.append({
                    'port': port_match.group(1),
                    'protocol': port_match.group(2),
                    'state': port_match.group(3),
                    'service': port_match.group(4),
                    'version': port_match.group(5).strip() if port_match.group(5) else ''
                })
        
        if ports:
            print_green(f"\n  [+] Found {len(ports)} open port(s):\n")
            print(f"  {'Port':<8} {'Proto':<8} {'State':<10} {'Service':<20} {'Version'}")
            print("  " + "-" * 65)
            for p in ports:
                if p['state'] == 'open':
                    print(f"  {p['port']:<8} {p['protocol']:<8} {p['state']:<10} {p['service']:<20} {p['version']}")
        else:
            print_yellow("  [+] No open ports found or host is down")
        
        # Save results
        print("\n  Save options:")
        print("  1. JSON (raw data)")
        print("  2. HTML (formatted report)")
        print("  3. Both")
        print("  4. Skip")
        
        save_choice = input("\n  Choose (1-4) [1]: ").strip() or '1'
        
        if save_choice in ('1', '3'):
            filename = input("  JSON filename [scan_results.json]: ").strip() or 'scan_results.json'
            with open(filename, 'w') as f:
                json.dump({'target': target, 'ports': ports, 'raw': output}, f, indent=2)
            print_green(f"  [+] JSON saved to {filename}")
        
        if save_choice in ('2', '3'):
            filename = input("  HTML filename [scan_report.html]: ").strip() or 'scan_report.html'
            generator = ReportGenerator()
            generator.generate({'target': target, 'findings': [{'severity': 'INFO', 'title': f'Port {p["port"]}/{p["protocol"]} - {p["service"]}', 'url': target, 'description': f'Version: {p.get("version", "unknown")}' if p['state'] == 'open' else 'Closed'} for p in ports], 'summary': {'total_findings': len([p for p in ports if p['state'] == 'open']), 'open_ports': len([p for p in ports if p['state'] == 'open'])}}, filename, 'html')
            print_green(f"  [+] HTML report saved to {filename}")
    
    except subprocess.TimeoutExpired:
        print_red("  ⚠️  Scan timed out (10 minutes)")
    except Exception as e:
        print_red(f"  ⚠️  Error: {e}")
    
    input("\nPress Enter to continue...")


def run_web_audit():
    """Interactive web audit"""
    clear_screen()
    print_banner()
    print_green("\n🌐 WEB VULNERABILITY SCANNER")
    print("-" * 50)
    
    # Get stored target
    stored, url = get_target()
    if stored:
        url_input = input(f"  Target URL (e.g., https://example.com) [{url or stored}]: ").strip() or (url or stored)
    else:
        url_input = input("  Target URL (e.g., https://example.com): ").strip()
        if not url_input:
            print_red("  ⚠️  URL is required")
            input("\nPress Enter to continue...")
            return
    
    if not url_input.startswith(('http://', 'https://')):
        url_input = 'https://' + url_input
    
    from reporting.generator import ReportGenerator
    
    depth = input("  Crawl depth (1-5) [2]: ").strip() or '2'
    max_pages = input("  Max pages to crawl [20]: ").strip() or '20'
    
    print(f"\n  [*] Auditing {url_input}")
    print(f"  [*] Depth: {depth}, Max pages: {max_pages}\n")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from reporting.generator import ReportGenerator
        from scanners.web import WebScanner
        
        scanner = WebScanner()
        results = scanner.audit(url_input, depth=int(depth), max_pages=int(max_pages))
        
        findings = results.get('findings', [])
        if findings:
            print_green(f"\n  [+] Found {len(findings)} finding(s):\n")
            
            # Group by severity
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                sev_findings = [f for f in findings if f['severity'] == severity]
                if sev_findings:
                    icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '🔵'}[severity]
                    print(f"\n  {icon} {severity} ({len(sev_findings)}):\n")
                    for i, f in enumerate(sev_findings, 1):
                        print(f"    {i}. {f['title']}")
                        print(f"       URL: {f.get('url', 'N/A')}")
                        print(f"       {f.get('description', '')}")
                        if f.get('recommendation'):
                            print(f"       💡 {f['recommendation']}")
                        print()
        else:
            print_green("  [+] No vulnerabilities found")
        
        # Save results
        print("\n  Save options:")
        print("  1. JSON (raw data)")
        print("  2. HTML (formatted report)")
        print("  3. Both")
        print("  4. Skip")
        
        save_choice = input("\n  Choose (1-4) [1]: ").strip() or '1'
        
        if save_choice in ('1', '3'):
            filename = input("  JSON filename [web_audit_results.json]: ").strip() or 'web_audit_results.json'
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print_green(f"  [+] JSON saved to {filename}")
        
        if save_choice in ('2', '3'):
            filename = input("  HTML filename [web_audit_report.html]: ").strip() or 'web_audit_report.html'
            generator = ReportGenerator()
            generator.generate(results, filename, 'html')
            print_green(f"  [+] HTML report saved to {filename}")
    
    except Exception as e:
        print_red(f"  ⚠️  Error: {e}")
        import traceback
        traceback.print_exc()
    
    input("\nPress Enter to continue...")


def run_dirbust():
    """Interactive directory brute-force"""
    clear_screen()
    print_banner()
    print_green("\n📂 DIRECTORY BRUTE-FORCER")
    print("-" * 50)
    
    # Get stored target
    stored, url = get_target()
    if stored:
        url_input = input(f"  Target URL (e.g., https://example.com) [{url or stored}]: ").strip() or (url or stored)
    else:
        url_input = input("  Target URL (e.g., https://example.com): ").strip()
        if not url_input:
            print_red("  ⚠️  URL is required")
            input("\nPress Enter to continue...")
            return
    
    if not url_input.startswith(('http://', 'https://')):
        url_input = 'https://' + url_input
    
    from reporting.generator import ReportGenerator
    
    threads = input("  Threads (1-50) [20]: ").strip() or '20'
    
    print(f"\n  [*] Starting directory bust on {url_input}")
    print(f"  [*] Using default wordlist ({len(['admin', 'login', 'dashboard', 'api', 'config', 'backup', 'test', 'temp', 'upload', 'files', 'images', 'css', 'js', 'assets', 'public', 'www', 'mail', 'ftp', 'ssh', 'mysql', '.git', '.env', '.htaccess', '.htpasswd', 'wp-admin', 'wp-login', 'wp-content', 'administrator', 'console', 'manager', 'phpmyadmin', 'pma', 'mysql', 'server-status', 'server-info', 'robots.txt', 'sitemap.xml', 'debug', 'trace', 'status', 'backup.zip', 'backup.sql', 'dump.sql', 'error.log', 'access.log'])} paths)\n")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from reporting.generator import ReportGenerator
        from scanners.dirbust import DirectoryBuster
        
        buster = DirectoryBuster()
        results = buster.bust(url_input, threads=int(threads))
        
        found = results.get('found', [])
        if found:
            print_green(f"\n  [+] Found {len(found)} paths:\n")
            print(f"  {'Status':<8} {'Size':<10} {'Path'}")
            print("  " + "-" * 60)
            for item in found:
                print(f"  {item['status']:<8} {item['size']:<10} {item['path']}")
        else:
            print_yellow("  [+] No paths found")
        
        # Save results
        print("\n  Save options:")
        print("  1. JSON (raw data)")
        print("  2. HTML (formatted report)")
        print("  3. Both")
        print("  4. Skip")
        
        save_choice = input("\n  Choose (1-4) [1]: ").strip() or '1'
        
        if save_choice in ('1', '3'):
            filename = input("  JSON filename [dirbust_results.json]: ").strip() or 'dirbust_results.json'
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print_green(f"  [+] JSON saved to {filename}")
        
        if save_choice in ('2', '3'):
            filename = input("  HTML filename [dirbust_report.html]: ").strip() or 'dirbust_report.html'
            generator = ReportGenerator()
            generator.generate({'target': url_input, 'findings': [{'severity': 'INFO', 'title': f'Path found: {item["path"]}', 'url': url_input, 'description': f'Status: {item["status"]}, Size: {item["size"]}'} for item in dir_results.get('found', [])], 'summary': {'total_findings': len(dir_results.get('found', []))}}, filename, 'html')
            print_green(f"  [+] HTML report saved to {filename}")
    
    except Exception as e:
        print_red(f"  ⚠️  Error: {e}")
    
    input("\nPress Enter to continue...")


def run_cve_lookup():
    """Interactive CVE lookup"""
    clear_screen()
    print_banner()
    print_green("\n🔍 CVE LOOKUP")
    print("-" * 50)
    
    # Get stored target
    stored, _ = get_target()
    if stored:
        service = input(f"  Service name and version (e.g., apache 2.4.49) [{stored}]: ").strip()
        if not service:
            service = stored
    else:
        service = input("  Service name and version (e.g., apache 2.4.49): ").strip()
        if not service:
            print_red("  ⚠️  Service is required")
            input("\nPress Enter to continue...")
            return
    
    print(f"\n  [*] Searching CVE for: {service}\n")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from reporting.generator import ReportGenerator
        from scanners.cve import CVELookup
        
        lookup = CVELookup()
        results = lookup.search(service)
        
        if results:
            print_green(f"\n  [+] Found {len(results)} CVE(s):\n")
            for i, cve in enumerate(results, 1):
                severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(cve.get('severity', ''), '⚪')
                print(f"  {i}. {severity_icon} {cve.get('id', 'N/A')}")
                print(f"     Severity: {cve.get('severity', 'N/A')}")
                print(f"     CVSS: {cve.get('cvss', 0)}")
                print(f"     Description: {cve.get('description', 'N/A')[:100]}...")
                print(f"     URL: {cve.get('url', 'N/A')}")
                print()
            
            # Save results
            print("\n  Save options:")
            print("  1. JSON (raw data)")
            print("  2. HTML (formatted report)")
            print("  3. Both")
            print("  4. Skip")
            
            save_choice = input("\n  Choose (1-4) [1]: ").strip() or '1'
            
            if save_choice in ('1', '3'):
                filename = input("  JSON filename [cve_results.json]: ").strip() or 'cve_results.json'
                with open(filename, 'w') as f:
                    json.dump({'service': service, 'cves': results}, f, indent=2)
                print_green(f"  [+] JSON saved to {filename}")
            
            if save_choice in ('2', '3'):
                filename = input("  HTML filename [cve_report.html]: ").strip() or 'cve_report.html'
                generator = ReportGenerator()
                generator.generate({'target': service, 'findings': [{'severity': cve.get('severity', 'INFO'), 'title': cve.get('id', 'N/A'), 'description': cve.get('description', 'N/A')[:200], 'url': cve.get('url', 'N/A')} for cve in results], 'summary': {'total_findings': len(results)}}, filename, 'html')
                print_green(f"  [+] HTML report saved to {filename}")
        else:
            print_yellow("  [+] No CVEs found")
    
    except Exception as e:
        print_red(f"  ⚠️  Error: {e}")
    
    input("\nPress Enter to continue...")


def run_exploit():
    """Interactive exploit runner"""
    clear_screen()
    print_banner()
    print_green("\n💥 EXPLOIT FRAMEWORK")
    print("-" * 50)
    
    # Get stored target
    stored, _ = get_target()
    if stored:
        target = input(f"  Target (IP/Domain) [{stored}]: ").strip() or stored
    else:
        target = input("  Target (IP/Domain): ").strip()
        if not target:
            print_red("  ⚠️  Target is required")
            input("\nPress Enter to continue...")
            return
    
    port_input = input("  Port (optional): ").strip()
    port = int(port_input) if port_input else None
    
    print(f"\n  [*] Running exploit on {target}:{port or 'default'}\n")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from exploits.manager import ExploitManager
        
        manager = ExploitManager()
        exploits = manager.list_exploits()
        
        if not exploits:
            print_yellow("  [+] No exploits available")
            input("\nPress Enter to continue...")
            return
        
        print("\n  Available exploits:\n")
        for i, exp in enumerate(exploits, 1):
            print(f"  {i}. {exp['name']} ({exp['category']})")
            print(f"     {exp['description']}")
            print()
        
        choice = input("  Choose exploit (1-{}): ".format(len(exploits))).strip()
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(exploits):
                raise ValueError
            exp = exploits[idx]
        except ValueError:
            print_red("  ⚠️  Invalid choice")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n  [*] Running: {exp['name']}")
        print(f"  [*] Target: {target}:{port or 'default'}\n")
        
        try:
            result = exp['run'](target, port)
            if result:
                print_green("  [+] Exploit completed:\n")
                if isinstance(result, list):
                    for r in result:
                        print(f"    {r}")
                else:
                    print(f"    {result}")
                
                # Save exploit results
                print("\n  Save options:")
                print("  1. JSON (raw data)")
                print("  2. Skip")
                
                save_choice = input("\n  Choose (1-2) [1]: ").strip() or '1'
                
                if save_choice in ('1',):
                    filename = input("  JSON filename [exploit_results.json]: ").strip() or 'exploit_results.json'
                    with open(filename, 'w') as f:
                        json.dump({'exploit': exp['name'], 'target': target, 'port': port, 'result': str(result) if not isinstance(result, (dict, list)) else result}, f, indent=2)
                    print_green(f"  [+] JSON saved to {filename}")
        except Exception as e:
            print_red(f"  ⚠️  Exploit failed: {e}")
    
    except Exception as e:
        print_red(f"  ⚠️  Error: {e}")
        import traceback
        traceback.print_exc()
    
    input("\nPress Enter to continue...")


def list_exploits():
    """List available exploits"""
    clear_screen()
    print_banner()
    print_green("\n📋 AVAILABLE EXPLOITS")
    print("-" * 50)
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from exploits.manager import ExploitManager
        
        manager = ExploitManager()
        exploits = manager.list_exploits()
        
        if not exploits:
            print_yellow("  [+] No exploits available")
        else:
            print(f"\n  {'#':<4} {'Name':<30} {'Category':<15} {'Description'}")
            print("  " + "-" * 70)
            for i, exp in enumerate(exploits, 1):
                print(f"  {i:<4} {exp['name']:<30} {exp['category']:<15} {exp['description'][:30]}")
        
        print(f"\n  Use option 5 to run an exploit")
    
    except Exception as e:
        print_red(f"  ⚠️  Error: {e}")
    
    input("\nPress Enter to continue...")


def generate_report():
    """Generate pentest report"""
    clear_screen()
    print_banner()
    print_green("\n📄 REPORT GENERATOR")
    print("-" * 50)
    
    input_file = input("  Input JSON file [scan_results.json]: ").strip() or 'scan_results.json'
    if not os.path.exists(input_file):
        print_red(f"  ⚠️  File not found: {input_file}")
        input("\nPress Enter to continue...")
        return
    
    print("\n  Report formats:")
    print("  1. HTML (recommended)")
    print("  2. JSON")
    print("  3. PDF")
    
    format_choice = input("  Choose (1-3) [1]: ").strip()
    fmt = 'html' if format_choice in ('1', '') else ('json' if format_choice == '2' else 'pdf')
    
    output = input(f"  Output filename [report.{fmt}]: ").strip() or f"report.{fmt}"
    
    print(f"\n  [*] Generating {fmt.upper()} report...")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from reporting.generator import ReportGenerator
        
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        generator = ReportGenerator()
        generator.generate(data, output, fmt)
        print_green(f"  [+] Report saved to: {output}")
    
    except Exception as e:
        print_red(f"  ⚠️  Error: {e}")
    
    input("\nPress Enter to continue...")


def run_full_pentest():
    """Full automated pentest"""
    clear_screen()
    print_banner()
    print_green("\n🚀 FULL AUTOMATED PENTEST")
    print("-" * 50)
    
    target = input("  Target IP/Domain: ").strip()
    if not target:
        print_red("  ⚠️  Target is required")
        input("\nPress Enter to continue...")
        return
    
    print("\n  Pentest options:")
    print("  1. Quick scan (network only)")
    print("  2. Network + web scan")
    print("  3. Full scan (network + web + dirbust)")
    
    choice = input("  Choose (1-3) [2]: ").strip() or '2'
    
    print(f"\n  [*] Starting full pentest on {target}")
    print(f"  [*] This may take a while...\n")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from scanners.network import NetworkScanner
        from scanners.web import WebScanner
        from scanners.dirbust import DirectoryBuster
        from reporting.generator import ReportGenerator
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scans': {},
            'findings': [],
            'summary': {}
        }
        
        # Phase 1: Network Scan
        print("[*] Phase 1: Network Scanning...")
        scanner = NetworkScanner()
        network_results = scanner.scan(target, 'quick')
        results['scans']['network'] = network_results
        
        open_ports = [p for p in network_results.get('ports', []) if p['state'] == 'open']
        print(f"[+] Found {len(open_ports)} open ports")
        
        # Add findings
        for port in open_ports:
            if port.get('service') in ['http', 'https', 'ssh', 'ftp', 'smtp']:
                results['findings'].append({
                    'severity': 'INFO',
                    'title': f"Open port: {port['service']} on {port['port']}",
                    'url': target,
                    'description': f"Service: {port.get('service')}, Version: {port.get('version', 'unknown')}",
                    'recommendation': 'Verify this service is expected'
                })
        
        # Phase 2: Web Scan
        web_ports = [p for p in open_ports if p['port'] in [80, 443, 8080, 8443]]
        if choice in ('2', '3') and web_ports:
            print("\n[*] Phase 2: Web Application Scanning...")
            web_scanner = WebScanner()
            
            for wp in web_ports[:1]:  # Only first web port
                proto = 'https' if wp['port'] == 443 else 'http'
                url = f"{proto}://{target}:{wp['port']}"
                web_results = web_scanner.audit(url, depth=2, max_pages=20)
                results['scans']['web'] = web_results
                results['findings'].extend(web_results.get('findings', []))
                print(f"[+] Web scan complete: {len(web_results.get('findings', []))} findings")
        else:
            print("\n[+] Skipping web scan (no web ports or option not selected)")
        
        # Phase 3: Directory Busting
        if choice == '3' and web_ports:
            print("\n[*] Phase 3: Directory Enumeration...")
            buster = DirectoryBuster()
            wp = web_ports[0]
            proto = 'https' if wp['port'] == 443 else 'http'
            url = f"{proto}://{target}:{wp['port']}"
            dir_results = buster.bust(url, threads=10)
            results['scans']['dirbust'] = dir_results
            results['findings'].extend([
                {
                    'severity': 'INFO',
                    'title': f"Discovered path: {item['path']}",
                    'url': url,
                    'description': f"Status: {item['status']}, Size: {item['size']}",
                    'recommendation': 'Verify this path is expected'
                }
                for item in dir_results.get('found', [])
            ])
            print(f"[+] Found {len(dir_results.get('found', []))} paths")
        
        # Summary
        vulns = [f for f in results['findings'] if f.get('severity') in ['HIGH', 'CRITICAL']]
        warnings = [f for f in results['findings'] if f.get('severity') == 'MEDIUM']
        info = [f for f in results['findings'] if f.get('severity') in ['INFO', 'LOW']]
        
        results['summary'] = {
            'total_findings': len(results['findings']),
            'critical': len([f for f in vulns if f['severity'] == 'CRITICAL']),
            'high': len([f for f in vulns if f['severity'] == 'HIGH']),
            'medium': len(warnings),
            'low': len([f for f in results['findings'] if f['severity'] == 'LOW']),
            'info': len(info),
            'open_ports': len(open_ports),
        }
        
        # Print summary
        print("\n" + "=" * 50)
        print("  PENTEST SUMMARY")
        print("=" * 50)
        print(f"  Target: {target}")
        print(f"  Open Ports: {len(open_ports)}")
        print(f"  Total Findings: {len(results['findings'])}")
        print(f"    Critical: {results['summary']['critical']}")
        print(f"    High: {results['summary']['high']}")
        print(f"    Medium: {results['summary']['medium']}")
        print(f"    Low: {results['summary']['low']}")
        print(f"    Info: {results['summary']['info']}")
        print("=" * 50)
        
        # Save results
        print("\n  Save options:")
        print("  1. JSON only")
        print("  2. HTML report only")
        print("  3. Both JSON + HTML")
        
        save_choice = input("\n  Choose (1-3) [3]: ").strip() or '3'
        
        if save_choice in ('1', '3'):
            output_json = f"cyberai_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_json, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] Raw results saved to: {output_json}")
        
        if save_choice in ('2', '3'):
            output_html = f"cyberai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            generator = ReportGenerator()
            generator.generate(results, output_html, 'html')
            print_green(f"[+] HTML report saved to: {output_html}")
    
    except Exception as e:
        print_red(f"  ⚠️  Error: {e}")
        import traceback
        traceback.print_exc()
    
    input("\nPress Enter to continue...")


def set_target_option():
    """Set or clear the current target"""
    clear_screen()
    print_banner()
    print_green("\n🎯 TARGET MANAGEMENT")
    print("-" * 50)
    
    current, url = get_target()
    if current:
        print(f"\n  Current target: {current}")
        if url:
            print(f"  Current URL: {url}")
        print()
    
    print("  Options:")
    print("  1. Set a new target (IP or domain)")
    print("  2. Clear current target")
    
    choice = input("\n  Choose (1-2): ").strip()
    
    if choice == '1':
        target = input("  Enter target (IP or domain): ").strip()
        if set_target(target):
            print_green(f"  [+] Target set to: {target}")
        else:
            print_red("  ⚠️  Invalid target")
    elif choice == '2':
        if current:
            clear_target()
            print_green("  [+] Target cleared")
        else:
            print_yellow("  [+] No target to clear")
    else:
        print_red("  ⚠️  Invalid option")
    
    input("\nPress Enter to continue...")


def show_help():
    """Show help information"""
    clear_screen()
    print_banner()
    print_green("\n📖 CYBERAI HELP")
    print("-" * 50)
    
    help_text = """
  CyberAI is a penetration testing toolkit with the following features:

  0. 🎯 SET TARGET - Lock a target domain/IP for all tools
     Use this first, then all tools will auto-fill the target
     Also lets you switch or clear the target

  1. NETWORK SCAN - Port scanning with nmap integration
     Quick scan (top ports), full scan (all ports), or vulnerability scan

  2. WEB AUDIT - Automated web vulnerability scanning
     Checks security headers, XSS, CSRF, SSL/TLS, and more

  3. DIRBUST - Directory brute-forcing
     Finds hidden directories and files on web servers

  4. CVE LOOKUP - Search CVE database for services
     Queries NVD API for known vulnerabilities

  5. EXPLOIT - Run proof-of-concept exploits
     Directory traversal, default credentials, SSL checks, etc.

  6. LIST EXPLOITS - Show available exploits

  7. REPORT - Generate professional pentest reports
     HTML, JSON, or PDF format

  8. FULL PENTEST - Automated multi-phase pentest
     Network + web + directory scanning with report generation

  WORKFLOW:
  1. Press 0 → Set target (e.g., mes.linways.com)
  2. Use tools 1-8 → They auto-use your target
  3. Press 0 again → Change or clear target

  COMMAND LINE MODE:
  cyberai.py -t <target>                    — Set target + menu
  cyberai.py scan <target>                  — Network scan
  cyberai.py web-audit <url>                — Web audit
  cyberai.py dirbust <url>                  — Directory bust
  cyberai.py cve <service>                  — CVE lookup
  cyberai.py exploit <name>                 — Run exploit
  cyberai.py report --input <json>          — Generate report
  cyberai.py pentest <target>               — Full pentest

  SAFETY:
  - All exploits are proof-of-concept only
  - No destructive actions without approval
  - Authorized use only

  For more info, see README.md
"""
    print(help_text)
    input("\nPress Enter to continue...")


def print_banner():
    """Print CyberAI banner"""
    target, url = get_target()
    target_display = target if target else "NOT SET"
    
    print()
    print("╔═══════════════════════════════════════════════════════╗")
    print("║                                                       ║")
    print("║    ███████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗  ║")
    print("║    ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝  ║")
    print("║    ███████╗██║   ██║██████╔╝█████╗  ██████╔╝█████╗    ║")
    print("║    ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██╗██╔══╝    ║")
    print("║    ███████║╚██████╔╝██║  ██║███████╗██║  ██║███████╗  ║")
    print("║    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝  ║")
    print("║                                                       ║")
    print("║          P E N T E S T   T O O L K I T               ║")
    print("║                                                       ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print()
    if target:
        print(f"  🎯 Target: {target_display}")
        if url:
            print(f"  🌐 URL: {url}")
    else:
        print("  🎯 Target: NOT SET (use option 0 to set)")
    print()


def print_menu():
    """Print main menu"""
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │  OPTIONS                                            │")
    print("  ├─────────────────────────────────────────────────────┤")
    print("  │  0. 🎯 Set / Change Target                          │")
    print("  │  1. 📡 Network Port Scan                            │")
    print("  │  2. 🌐 Web Vulnerability Audit                      │")
    print("  │  3. 📂 Directory Brute-Force                        │")
    print("  │  4. 🔍 CVE Lookup                                   │")
    print("  │  5. 💥 Run Exploit                                  │")
    print("  │  6. 📋 List Exploits                                │")
    print("  │  7. 📄 Generate Report                              │")
    print("  │  8. 🚀 Full Automated Pentest                       │")
    print("  │  9. 📖 Help                                         │")
    print("  │                                                     │")
    print("  │  q. Quit                                            │")
    print("  └─────────────────────────────────────────────────────┘")


def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')


def print_green(text):
    """Print green text"""
    print(f"\033[92m{text}\033[0m")


def print_red(text):
    """Print red text"""
    print(f"\033[91m{text}\033[0m")


def print_yellow(text):
    """Print yellow text"""
    print(f"\033[93m{text}\033[0m")


if __name__ == '__main__':
    main()
