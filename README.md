# CyberAI Calion

A lean, interactive penetration testing toolkit with a menu-driven interface. No complex commands to remember — just pick a number and go.

## What It Does

**8 tools in one toolkit:**

| # | Tool | What it does |
|---|------|-------------|
| 0 | 🎯 Set Target | Lock a domain/IP so you don't retype it |
| 1 | 📡 Network Scan | Port scanning via nmap (quick, full, or vuln scan) |
| 2 | 🌐 Web Audit | Crawls a site, checks security headers, SSL, CSRF, XSS |
| 3 | 📂 Dirbust | Brute-forces hidden directories and files |
| 4 | 🔍 CVE Lookup | Searches NVD API for known vulnerabilities |
| 5 | 💥 Run Exploit | Runs PoC exploits to verify findings |
| 6 | 📋 List Exploits | Shows available exploits |
| 7 | 📄 Generate Report | Turns scan results into HTML/JSON/PDF |
| 8 | 🚀 Full Pentest | Runs everything automatically in sequence |

## Quick Start

```bash
# Interactive menu (recommended)
cyberai

# Or with a target pre-set
cyberai -t mes.linways.com

# CLI mode
cyberai scan 192.168.1.1
cyberai web-audit https://example.com
```

## Installation

**Option 1: User install (no root needed)**
```bash
cd cyberai && python3 install.py --user
```

**Option 2: System install (requires sudo)**
```bash
sudo python3 install.py
```

**Option 3: pip**
```bash
pip3 install cyberai-calion
```

**Uninstall:**
```bash
python3 install.py --uninstall
```

## Usage Workflow

```
1. Press 0 → Set target (e.g., mes.linways.com)
2. Pick a tool (1-8) → Target auto-fills, just press Enter
3. Choose save format → JSON, HTML, Both, or Skip
4. Press 0 again → Switch or clear target
```

## Examples

```bash
# Network scan
cyberai → 1 → mes.linways.com → 1 (quick)

# Web audit
cyberai → 0 → mes.linways.com → 2 (web audit)

# Full pentest
cyberai → 0 → example.com → 8 (full pentest)

# CVE lookup
cyberai → 0 → apache 2.4.49 → 4 (CVE lookup)
```

## Save Options

Every tool lets you choose:
- **1** — JSON (raw data)
- **2** — HTML (formatted report)
- **3** — Both
- **4** — Skip

## Structure

```
cyberai/
├── cyberai.py          # Main CLI + interactive menu
├── install.py          # Self-installer
├── setup.py            # pip setup
├── pyproject.toml      # Modern Python packaging
├── requirements.txt    # Dependencies
├── README.md           # This file
├── .gitignore
│
├── scanners/           # Scanning modules
│   ├── network.py      # nmap port scanner
│   ├── web.py          # Web vulnerability scanner
│   ├── dirbust.py      # Directory brute-forcer
│   └── cve.py          # CVE database lookup
│
├── exploits/           # Exploit framework
│   ├── manager.py      # Exploit registry
│   └── __init__.py
│
├── reporting/          # Report generation
│   ├── generator.py    # HTML/JSON/PDF reports
│   └── __init__.py
│
├── utils/              # Shared utilities
│   └── __init__.py
│
├── config/             # Configuration
│   └── settings.yaml
│
└── tests/              # Test suite
    └── __init__.py
```

## CLI Commands

```bash
cyberai scan <target>              # Network port scan
cyberai web-audit <url>            # Web vulnerability audit
cyberai dirbust <url>              # Directory brute-force
cyberai cve <service>              # CVE lookup (e.g., "apache 2.4.49")
cyberai exploit <name>             # Run an exploit
cyberai list-exploits              # List available exploits
cyberai report --input <file>      # Generate report
cyberai pentest <target>           # Full automated pentest
cyberai -t <target>                # Set target + menu
cyberai --menu                     # Interactive menu
```

## Dependencies

- **Python 3.8+**
- **nmap** (for network scanning)
- Python packages: `requests`, `python-nmap`, `jinja2`, `reportlab`, `beautifulsoup4`, `rich`, `cryptography`

Install dependencies:
```bash
pip3 install -r requirements.txt
```

## Safety

- All exploits are **proof-of-concept only**
- No destructive actions without explicit approval
- Rate limiting on web scanner
- **Authorized use only** — only scan systems you own or have permission to test

## License

MIT
