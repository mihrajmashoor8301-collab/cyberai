"""Web Vulnerability Scanner - Automated web security checks"""

import requests
import re
from urllib.parse import urljoin, urlparse
from datetime import datetime
from collections import deque


class WebScanner:
    def __init__(self):
        import warnings
        warnings.filterwarnings('ignore')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.timeout = 10
    
    def audit(self, url, depth=3, max_pages=50, threads=10):
        """Run web vulnerability audit"""
        print(f"[*] Auditing {url}")
        print(f"[*] Depth: {depth}, Max pages: {max_pages}")
        
        findings = []
        visited = set()
        queue = deque([(url, 0)])
        
        while queue and len(visited) < max_pages:
            current_url, current_depth = queue.popleft()
            
            if current_url in visited:
                continue
            
            visited.add(current_url)
            print(f"[*] Crawling: {current_url}")
            
            # Check current page
            page_findings = self.check_page(current_url)
            findings.extend(page_findings)
            
            # Crawl links if depth allows
            if current_depth < depth and len(visited) < max_pages:
                links = self.extract_links(current_url)
                for link in links:
                    if link not in visited:
                        queue.append((link, current_depth + 1))
        
        return {
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'pages_crawled': len(visited),
            'findings': findings,
            'summary': {
                'total': len(findings),
                'critical': len([f for f in findings if f['severity'] == 'CRITICAL']),
                'high': len([f for f in findings if f['severity'] == 'HIGH']),
                'medium': len([f for f in findings if f['severity'] == 'MEDIUM']),
                'low': len([f for f in findings if f['severity'] == 'LOW']),
                'info': len([f for f in findings if f['severity'] == 'INFO']),
            }
        }
    
    def check_page(self, url):
        """Check a single page for vulnerabilities"""
        # Skip static assets
        static_ext = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico', '.map')
        if any(url.lower().endswith(ext) for ext in static_ext):
            return []
        
        findings = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.raise_for_status()
        except Exception as e:
            findings.append({
                'severity': 'INFO',
                'title': 'Page access error',
                'url': url,
                'description': f'Error accessing page: {str(e)}',
                'recommendation': 'Check URL and permissions'
            })
            return findings
        
        # Check security headers
        findings.extend(self.check_security_headers(response, url))
        
        # Check for common vulnerabilities
        findings.extend(self.check_common_vulns(response.text, url))
        
        # Check SSL/TLS
        findings.extend(self.check_ssl(url))
        
        return findings
    
    def check_security_headers(self, response, url):
        """Check for missing security headers"""
        findings = []
        headers = response.headers
        
        missing = {
            'Content-Security-Policy': 'HIGH',
            'X-Content-Type-Options': 'MEDIUM',
            'X-Frame-Options': 'MEDIUM',
            'Strict-Transport-Security': 'HIGH',
            'X-XSS-Protection': 'LOW',
            'Referrer-Policy': 'LOW',
            'Permissions-Policy': 'LOW',
        }
        
        for header, severity in missing.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                findings.append({
                    'severity': severity,
                    'title': f'Missing header: {header}',
                    'url': url,
                    'description': f'Security header "{header}" is not set',
                    'recommendation': f'Add "{header}" header to web server configuration',
                    'header': header
                })
        
        return findings
    
    def check_common_vulns(self, html, url):
        """Check for common web vulnerabilities"""
        findings = []
        
        # Check for exposed tech info
        if 'powered by' in html.lower():
            findings.append({
                'severity': 'INFO',
                'title': 'Technology disclosure',
                'url': url,
                'description': 'Website discloses technology stack (Powered by...)',
                'recommendation': 'Remove or obfuscate technology disclosure'
            })
        
        # Check for debug endpoints
        debug_patterns = ['/debug', '/test', '/backup', '/admin.bak', '/config.php']
        for pattern in debug_patterns:
            if pattern in html.lower():
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'Potential debug endpoint',
                    'url': url,
                    'description': f'Potential debug/test endpoint reference: {pattern}',
                    'recommendation': 'Remove debug endpoints from production'
                })
        
        # Check for inline scripts (XSS risk)
        if re.search(r'<script[^>]*>.*?</script>', html, re.IGNORECASE | re.DOTALL):
            findings.append({
                'severity': 'INFO',
                'title': 'Inline JavaScript found',
                'url': url,
                'description': 'Inline scripts detected (potential XSS vector)',
                'recommendation': 'Use external JavaScript files with CSP'
            })
        
        # Check for form without CSRF protection
        forms = re.findall(r'<form[^>]*>', html, re.IGNORECASE)
        for form in forms:
            if 'csrf' not in form.lower() and 'token' not in form.lower():
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'Form without CSRF token',
                    'url': url,
                    'description': 'Form detected without CSRF protection',
                    'recommendation': 'Add CSRF token to all forms'
                })
                break  # One finding is enough
        
        # Check for HTTP links in HTTPS page (mixed content)
        if url.startswith('https://'):
            http_links = re.findall(r'http://[^"\'>\s]+', html)
            if http_links:
                findings.append({
                    'severity': 'LOW',
                    'title': 'Mixed content detected',
                    'url': url,
                    'description': f'Found {len(http_links)} HTTP links on HTTPS page',
                    'recommendation': 'Convert all links to HTTPS'
                })
        
        return findings
    
    def check_ssl(self, url):
        """Check SSL/TLS configuration"""
        findings = []
        
        try:
            # Only check SSL for HTTPS URLs
            if not url.startswith('https://'):
                return findings
            
            response = self.session.get(url, timeout=self.timeout, verify=True)
            cert = response.raw.connection.sock.getpeercert()
            
            if not cert:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'No SSL certificate',
                    'url': url,
                    'description': 'Target does not present a valid SSL certificate',
                    'recommendation': 'Install and configure SSL certificate'
                })
                return findings
            
            # Check certificate expiry
            if 'notAfter' in cert:
                expiry = cert['notAfter']
                # Parse expiry date
                from datetime import datetime as dt
                try:
                    expiry_date = dt.strptime(expiry, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - dt.utcnow()).days
                    if days_left < 30:
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'SSL certificate expiring soon',
                            'url': url,
                            'description': f'Certificate expires in {days_left} days',
                            'recommendation': 'Renew SSL certificate immediately',
                            'days_until_expiry': days_left
                        })
                except:
                    pass
            
            # Check certificate issuer
            issuer = cert.get('issuer', [])
            if issuer:
                org = str(issuer)
                if 'self-signed' in org.lower():
                    findings.append({
                        'severity': 'MEDIUM',
                        'title': 'Self-signed certificate',
                        'url': url,
                        'description': 'SSL certificate is self-signed',
                        'recommendation': 'Use certificate from trusted CA'
                    })
        
        except Exception as e:
            findings.append({
                'severity': 'HIGH',
                'title': 'SSL/TLS error',
                'url': url,
                'description': f'SSL/TLS check failed: {str(e)}',
                'recommendation': 'Check SSL configuration'
            })
        
        return findings
    
    def extract_links(self, url):
        """Extract links from a page"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            html = response.text
            
            # Simple link extraction (no bs4 dependency)
            links = re.findall(r'href=["\']([^"\']+)["\']', html)
            
            base_url = urlparse(url).netloc
            parsed_links = []
            
            for link in links:
                # Skip external links and anchors
                if link.startswith('http') and base_url not in link:
                    continue
                if link.startswith('#') or link.startswith('javascript:'):
                    continue
                if link.startswith('mailto:') or link.startswith('tel:'):
                    continue
                
                # Make absolute URL
                full_url = urljoin(url, link)
                
                # Only include same domain
                parsed = urlparse(full_url)
                if parsed.netloc == base_url:
                    parsed_links.append(full_url)
            
            return list(set(parsed_links))  # Remove duplicates
        
        except Exception:
            return []
