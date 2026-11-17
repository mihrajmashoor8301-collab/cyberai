# CyberAI Pentest Toolkit

A lean, functional penetration testing toolkit built for speed and real results.

## Features

### Scanners
- **Network Scanner** — Port scanning with service detection (nmap integration)
- **Web Directory Buster** — Brute-force web directories and files
- **Web Vulnerability Scanner** — Automated detection of common web vulns
- **SSL/TLS Scanner** — Certificate analysis and configuration checks

### Exploits
- **CVE Lookup** — Search CVE database for discovered services
- **Proof-of-Concept Generator** — Safe exploit verification
- **Manual Exploit Framework** — Execute custom exploits with safety controls

### Reporting
- **HTML Reports** — Professional pentest reports
- **PDF Export** — Print-ready documentation
- **JSON Export** — Machine-readable results
- **Evidence Collection** — Screenshots and logs

### AI Integration
- **Vulnerability Analysis** — LLM-powered vuln assessment
- **Exploit Suggestions** — AI recommends relevant exploits
- **Report Writing** — Auto-generate findings descriptions

## Quick Start

```bash
# Network scan
python3 cyberai.py scan --target 192.168.1.1

# Web audit
python3 cyberai.py web-audit --url https://example.com

# Full pentest
python3 cyberai.py pentest --target example.com --full

# Generate report
python3 cyberai.py report --input results.json --format html
```

## Installation

```bash
pip install -r requirements.txt
```

## Safety

- All exploits are proof-of-concept only
- Rate limiting enabled by default
- No destructive actions without explicit approval
- Authorized use only

## Structure

```
cyberai/
├── scanners/      # Scanning modules
├── exploits/      # Exploit modules
├── reporting/     # Report generation
├── utils/         # Shared utilities
├── config/        # Configuration
├── tests/         # Test suite
└── data/          # Wordlists, CVE data
```

## License

MIT
