"""CVE Lookup - Search CVE database for services"""

import subprocess
import json
import re
from datetime import datetime


class CVELookup:
    def __init__():
        self.cve_cache = {}
    
    def search(self, service, max_results=10):
        """Search for CVEs related to a service"""
        # Parse service name and version
        parts = service.strip().split()
        service_name = parts[0].lower() if parts else ''
        version = parts[1] if len(parts) > 1 else ''
        
        cache_key = f"{service_name}:{version}"
        if cache_key in self.cve_cache:
            return self.cve_cache[cache_key]
        
        results = []
        
        # Method 1: Use CVE APIs (cve.org, nvd.nist.gov)
        results.extend(self._search_api(service_name, version))
        
        # Method 2: Use local CVE data if available
        results.extend(self._search_local(service_name, version))
        
        # Dedupe by CVE ID
        seen = set()
        unique_results = []
        for cve in results:
            if cve['id'] not in seen:
                seen.add(cve['id'])
                unique_results.append(cve)
        
        self.cve_cache[cache_key] = unique_results[:max_results]
        return unique_results[:max_results]
    
    def _search_api(self, service_name, version):
        """Search CVE via public APIs"""
        results = []
        
        try:
            # Try NVD API (free, no key needed for basic usage)
            import urllib.request
            import urllib.error
            
            # Build search query
            query = f"{service_name}"
            if version:
                query += f" {version}"
            
            # NVD API v2
            url = f"https://services.nvd.org.cn/2.0/cves?keywordSearch={query}&cpeName=cpe:2.3:a:{service_name}"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'CyberAI/1.0')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                
                if 'vulnerabilities' in data:
                    for vuln in data['vulnerabilities'][:10]:
                        cve_data = vuln.get('cve', {})
                        results.append({
                            'id': cve_data.get('id', 'N/A'),
                            'severity': self._get_severity(cve_data),
                            'description': cve_data.get('descriptions', [{}])[0].get('value', 'N/A')[:200],
                            'url': f"https://nvd.nist.gov/vuln/detail/{cve_data.get('id', '')}",
                            'references': [ref['url'] for ref in cve_data.get('references', [])[:3]],
                            'cvss': self._get_cvss(cve_data),
                            'published': cve_data.get('publishedDate', ''),
                            'modified': cve_data.get('lastModified', '')
                        })
        
        except Exception as e:
            # Fallback to manual CVE lookup
            pass
        
        return results
    
    def _search_local(self, service_name, version):
        """Search local CVE data"""
        results = []
        
        # Check if we have local CVE data
        cve_file = '/home/mihraj/cyberai/data/cves.json'
        try:
            with open(cve_file, 'r') as f:
                local_cves = json.load(f)
            
            for cve in local_cves:
                if service_name.lower() in cve.get('services', []).lower():
                    if not version or version.lower() in cve.get('versions', []).lower():
                        results.append(cve)
        
        except FileNotFoundError:
            pass
        
        return results
    
    def _get_severity(self, cve_data):
        """Extract severity from CVE data"""
        metrics = cve_data.get('metrics', {})
        
        # Check for CVSS v3.1
        if 'cvssMetricV31' in metrics:
            for metric in metrics['cvssMetricV31']:
                return metric.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
        
        # Check for CVSS v3.0
        if 'cvssMetricV30' in metrics:
            for metric in metrics['cvssMetricV30']:
                return metric.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
        
        return 'UNKNOWN'
    
    def _get_cvss(self, cve_data):
        """Extract CVSS score"""
        metrics = cve_data.get('metrics', {})
        
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0)
        if 'cvssMetricV30' in metrics:
            return metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 0)
        
        return 0
