"""Directory Buster - Web directory brute-forcing"""

import requests
import threading
from queue import Queue
from datetime import datetime


class DirectoryBuster:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.timeout = 10
    
    def bust(self, url, wordlist=None, threads=20, status_codes='200,301,302,403'):
        """Run directory brute-force"""
        print(f"[*] Starting directory bust on {url}")
        print(f"[*] Threads: {threads}")
        
        # Load wordlist
        paths = self._load_wordlist(wordlist)
        print(f"[*] Loaded {len(paths)} paths")
        
        # Parse status codes
        allowed_codes = [int(x.strip()) for x in status_codes.split(',')]
        
        # Results storage
        results = {
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'found': [],
            'total_checked': 0,
            'status_codes': allowed_codes
        }
        
        # Queue for threading
        queue = Queue()
        for path in paths:
            queue.put(path)
        
        # Thread counter
        active_threads = [0]
        lock = threading.Lock()
        
        def worker():
            while not queue.empty():
                try:
                    path = queue.get_nowait()
                except:
                    break
                
                full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
                
                try:
                    response = self.session.get(full_url, timeout=self.timeout, verify=False)
                    
                    if response.status_code in allowed_codes:
                        with lock:
                            results['found'].append({
                                'path': path,
                                'url': full_url,
                                'status': response.status_code,
                                'size': len(response.content)
                            })
                            print(f"[+] {response.status_code} {full_url} ({len(response.content)} bytes)")
                    
                    with lock:
                        results['total_checked'] += 1
                
                except Exception as e:
                    with lock:
                        results['total_checked'] += 1
        
        # Start threads
        thread_list = []
        for _ in range(threads):
            t = threading.Thread(target=worker)
            t.start()
            thread_list.append(t)
        
        # Wait for completion
        for t in thread_list:
            t.join()
        
        # Sort results by status code
        results['found'].sort(key=lambda x: x['status'])
        
        print(f"\n[+] Done! Checked {results['total_checked']} paths")
        print(f"[+] Found {len(results['found'])} valid paths")
        
        return results
    
    def _load_wordlist(self, wordlist=None):
        """Load wordlist from file or use default"""
        if wordlist:
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except FileNotFoundError:
                print(f"[-] Wordlist not found: {wordlist}")
                return self._default_wordlist()
        
        return self._default_wordlist()
    
    def _default_wordlist(self):
        """Return default wordlist paths"""
        default_paths = [
            'admin', 'login', 'dashboard', 'api', 'config',
            'backup', 'test', 'temp', 'upload', 'files',
            'images', 'css', 'js', 'assets', 'public',
            'www', 'mail', 'ftp', 'ssh', 'mysql',
            '.git', '.env', '.htaccess', '.htpasswd',
            'wp-admin', 'wp-login', 'wp-content',
            'administrator', 'console', 'manager',
            'phpmyadmin', 'pma', 'mysql',
            'server-status', 'server-info',
            'robots.txt', 'sitemap.xml',
            'debug', 'trace', 'status',
            'backup.zip', 'backup.sql', 'dump.sql',
            'error.log', 'access.log',
        ]
        return default_paths
