"""Network Scanner - Port scanning with nmap integration"""

import subprocess
import json
import re
from datetime import datetime


class NetworkScanner:
    def __init__(self):
        self.nmap_available = self._check_nmap()
    
    def _check_nmap(self):
        """Check if nmap is available"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def scan(self, target, scan_type='quick'):
        """Run network scan on target"""
        if not self.nmap_available:
            return {'error': 'nmap not found', 'ports': []}
        
        print(f"[*] Scanning {target} ({scan_type} mode)...")
        
        if scan_type == 'quick':
            args = ['-sV', '-sC', '-T4', '--top-ports', '100']
        elif scan_type == 'full':
            args = ['-sV', '-sC', '-T4', '-p', '-']
        elif scan_type == 'vuln':
            args = ['-sV', '--script', 'vuln', '-T4']
        else:
            args = ['-sV', '-sC', '-T4']
        
        result = subprocess.run(
            ['nmap'] + args + [target],
            capture_output=True, text=True, timeout=300
        )
        
        return self._parse_nmap_output(result.stdout)
    
    def scan_ports(self, target, ports, scan_type='quick'):
        """Scan specific ports"""
        if not self.nmap_available:
            return {'error': 'nmap not found', 'ports': []}
        
        print(f"[*] Scanning specific ports on {target}...")
        
        result = subprocess.run(
            ['nmap', '-sV', '-T4', '-p', str(ports), target],
            capture_output=True, text=True, timeout=120
        )
        
        return self._parse_nmap_output(result.stdout)
    
    def _parse_nmap_output(self, output):
        """Parse nmap output into structured data"""
        ports = []
        host_os = None
        host_status = 'unknown'
        
        lines = output.split('\n')
        
        for i, line in enumerate(lines):
            # Parse host status
            if 'Host is up' in line:
                match = re.search(r'latency.*?([\d.]+)s', line)
                if match:
                    host_status = 'up'
            
            # Parse OS detection
            if 'OS details:' in line:
                host_os = line.split('OS details:')[1].strip()
            
            # Parse port info
            port_match = re.match(r'(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)', line)
            if port_match:
                port = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5).strip() if port_match.group(5) else ''
                
                # Clean up version
                version = version.split('\n')[0].strip() if version else ''
                
                ports.append({
                    'port': port,
                    'protocol': protocol,
                    'state': state,
                    'service': service,
                    'version': version,
                    'banner': version
                })
        
        return {
            'target': None,  # Will be set by caller
            'scan_type': 'quick',
            'timestamp': datetime.now().isoformat(),
            'host_status': host_status,
            'os_detection': host_os,
            'ports': ports,
            'total_ports': len(ports)
        }
