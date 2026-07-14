# Bug Bounty Beast v7.0

A powerful and hardened tool for subdomain and directory enumeration, designed for bug bounty hunting and web application reconnaissance. This script automates the discovery of potential attack vectors through passive and active scanning techniques with 30 new features and 10 system-level hardening improvements.

---

## Features

### Core Enumeration
- **Multi-Source Subdomain Enumeration** (9 sources):
  - **Passive:** DNS, crt.sh, Wayback Machine, Anubis, Hackertarget, Certspotter, Facebook CT
  - **GitHub Leak Search:** Discovers subdomains leaked in public code repositories
  - **Active Bruteforce:** Wordlist-based HTTP bruteforce with wildcard filtering
- **Active Subdomain Probing:** Validates discovered subdomains (HTTP 200) with HTTPS/HTTP fallback
- **Directory Bruteforcing:** Baseline-compared scanning with progress bars
- **Recursive Subdomain Enumeration:** Discovers deeper nesting (`*.api.target.com`)

### Reconnaissance & Analysis (Feature #2-5, #10, #15-17)
- **Wildcard DNS Detection:** Automatically detects and filters wildcard DNS false positives
- **Technology Fingerprinting:** Detects servers, frameworks, CMS, analytics from response headers and HTML
- **IP Resolution & ASN Lookup:** Resolves IPs, identifies cloud provider (AWS/GCP/Azure/Cloudflare)
- **Port Scanning:** Quick connect-scan on top ports (21-50000) for live hosts
- **DNS Record Expansion:** MX, TXT, CNAME, NS, SOA, CAA, SRV record enumeration
- **HTTP Method Fingerprinting:** Tests GET/POST/PUT/DELETE/OPTIONS/TRACE/PATCH/HEAD
- **Virtual Host Detection:** Identifies vhost anomalies and default content
- **Subdomain Takeover Checks:** Detects dangling CNAMEs pointing to 30+ unclaimed services

### Output & Reporting (Feature #4, #12, #19-20)
- **JSON + CSV Export:** Machine-readable output for tool integration
- **Scan Comparison/Diff:** Highlights new/removed subdomains between scans
- **Scan Resume/Checkpoint:** Resume interrupted scans from saved state
- **Multi-Domain Batch Mode:** Process multiple targets from a file concurrently
- **Colored Terminal Output:** ANSI color-coded findings (green=found, red=critical, yellow=warning)
- **Progress Bars with ETA:** Real-time progress indicators for every scan phase

### Hardening (10 System-Level Improvements)
1. **Signal Handling + Clean Shutdown:** Graceful SIGINT/SIGTERM with partial result saving
2. **SSL/TLS Error Resilience:** Handles SSLError, ConnectionReset with backoff
3. **Rate Limit Adaptive Threading:** Auto-backoff on HTTP 429/403 per service
4. **Request Session Pooling:** Connection reuse via `requests.Session` (20-connection pool)
5. **Circuit Breaker:** Stops hammering failing targets after N consecutive failures
6. **Output Atomicity:** Temp-file-then-rename prevents corrupt output files
7. **Duplicate Suppression:** Proper dedup at print AND write layers (fixes CRT.sh spam)
8. **Memory-Bounded Results:** Configurable caps prevent OOM on large targets
9. **Input Validation + Sanitization:** Domain regex validation, path traversal prevention
10. **Exponential Backoff + Jitter:** Proper retry delays replacing fixed random sleeps

---

## Setup & Installation

```bash
git clone <repo>
cd Subdom
pip install -r requirements.txt
```

### Required Libraries
```
requests
beautifulsoup4
dnspython
pyopenssl
cryptography
service-identity
```

---

## Usage

### Basic Examples

```bash
# Run all enumeration steps on a target
python Subdom.py -d example.com --all --verbose

# Run passive subdomain enumeration only
python Subdom.py -d example.com --passive --threads 20

# Full recon with all analysis features
python Subdom.py -d example.com --all --fingerprint --resolve --scan-ports --dns-records --json --verbose

# Check for subdomain takeover
python Subdom.py -d example.com --passive --takeover --verbose

# Directory enumeration on previously discovered targets
python Subdom.py -d example.com --dir --dir-wordlist /path/to/my/dirs.txt

# Compare against a previous scan
python Subdom.py -d example.com --passive --diff bug_bounty_output/previous_scan_passive.txt

# Batch scan multiple domains
python Subdom.py --batch targets.txt --all --json --verbose

# Validate a domain format only
python Subdom.py -d example.com --validate
```

### Command-Line Arguments

| Argument | Description |
|---|---|
| `-d`, `--domain` | Target domain (e.g., `example.com`) |
| `--batch` | File of multiple target domains (one per line) |
| `-t`, `--threads` | Number of threads (default: 10) |
| `--passive` | Run passive subdomain enumeration only |
| `--active` | Run active (bruteforce) subdomain enumeration only |
| `--probe` | Probe for active (HTTP 200) subdomains only |
| `--dir` | Run directory enumeration only |
| `--all` | Run all enumeration steps (default) |
| `--fingerprint` | Enable technology stack fingerprinting |
| `--resolve` | Enable IP resolution & cloud provider detection |
| `--scan-ports` | Enable port scanning on live hosts |
| `--dns-records` | Enumerate full DNS records (MX, TXT, NS, etc.) |
| `--methods` | HTTP method fingerprinting (GET/POST/PUT/DELETE/etc.) |
| `--vhost` | Virtual host anomaly detection |
| `--takeover` | Subdomain takeover checks (30+ services) |
| `--recursive` | Recursive subdomain enumeration |
| `--recursive-depth` | Recursive depth (default: 1) |
| `--diff` | Compare against previous scan file |
| `--resume` | Resume from last checkpoint |
| `--json` | Export results as JSON |
| `--csv` | Export results as CSV |
| `--validate` | Validate input only, don't scan |
| `--sub-wordlist` | Custom subdomain wordlist path |
| `--dir-wordlist` | Custom directory wordlist path |
| `--proxies` | Proxy list file for WAF evasion |
| `--output` | Custom output file prefix |
| `--verbose` | Enable verbose output |
| `--timeout` | Request timeout in seconds (default: 5) |

---

## Output Files

All results are saved in `bug_bounty_output/`:

| File | Description |
|---|---|
| `*_passive.txt` | Passive subdomain enumeration results |
| `*_active.txt` | Active (bruteforce) subdomain results |
| `*_active_200.txt` | Live subdomains (HTTP 200) |
| `*_dirs.txt` | Discovered directories |
| `*_full_report.json` | Complete JSON report |
| `*_report.csv` | CSV export for spreadsheet analysis |
| `*_resolve.json` | IP resolution & ASN data |
| `*_ports.json` | Port scan results |
| `*_tech.json` | Technology fingerprint data |
| `*_dns_records.json` | DNS record enumeration |
| `*_methods.json` | HTTP method fingerprinting |
| `*_vhost.json` | Virtual host detection data |
| `*_takeover.json` | Subdomain takeover findings |
| `.*_checkpoint.json` | Scan state for resume |

---

## WAF Evasion

The tool includes 50+ WAF bypass headers with:
- Randomized User-Agent rotation (10 modern browsers)
- IP spoofing headers (X-Forwarded-For, CF-Connecting-IP, True-Client-IP, etc.)
- Rate limit bypass headers (X-Bypass-WAF, X-Ignore-RateLimit, etc.)
- Proxy rotation support
- Adaptive rate limiting with exponential backoff

---

## License

MIT License
