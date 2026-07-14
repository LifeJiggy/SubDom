# Bug Bounty Beast v8.0

A powerful and hardened tool for subdomain and directory enumeration, designed for bug bounty hunting and web application reconnaissance. 40+ features with 10 system-level hardening fixes.

---

## Features

### Core Enumeration (9 Sources)
- **Passive DNS:** crt.sh, Wayback Machine, Anubis, Hackertarget, Certspotter, Facebook CT
- **GitHub Leak Search:** Discovers subdomains leaked in public code repositories
- **Active Bruteforce:** Wordlist-based HTTP bruteforce with wildcard filtering
- **Active Subdomain Probing:** Validates discovered subdomains (HTTP 200) with HTTPS/HTTP fallback
- **Directory Bruteforcing:** Baseline-compared scanning with progress bars
- **Recursive Subdomain Enumeration:** Discovers deeper nesting (`*.api.target.com`)
- **Subdomain Permutation Engine:** Generates flip/insert/append variations of discovered subdomains

### Reconnaissance & Analysis
- **Wildcard DNS Detection:** Automatically detects and filters wildcard DNS false positives
- **Technology Fingerprinting:** Detects servers, frameworks, CMS, analytics from response headers and HTML
- **Technology Version Extraction:** Gets exact versions (nginx/1.21.6) for CVE matching
- **IP Resolution & ASN Lookup:** Resolves IPs, identifies cloud provider (AWS/GCP/Azure/Cloudflare)
- **Port Scanning:** Quick connect-scan on top ports for live hosts
- **DNS Record Expansion:** MX, TXT, CNAME, NS, SOA, CAA, SRV record enumeration
- **DNS Zone Transfer Testing:** Tests all NS servers for AXFR vulnerability
- **HTTP Method Fingerprinting:** Tests GET/POST/PUT/DELETE/OPTIONS/TRACE/PATCH/HEAD
- **Virtual Host Detection:** Identifies vhost anomalies and default content
- **Subdomain Takeover Checks:** Detects dangling CNAMEs pointing to 30+ unclaimed services
- **SSL/TLS Certificate Intelligence:** Extracts SANs, issuer, expiry, key size, protocol
- **Netblock/CIDR Discovery:** Finds IP ranges associated with the target

### API & Endpoint Discovery
- **JavaScript Endpoint Extraction:** Extracts external, internal, and hidden API endpoints from JS files
- **API Path Probing:** Discovers /api, /graphql, /swagger, /v1, and 60+ common paths
- **robots.txt / sitemap.xml Crawler:** Extracts hidden paths and directories
- **Wayback Machine URL Extraction:** Pulls historical URLs for endpoint discovery
- **Email & Contact Extraction:** Scrapes email addresses and social links from pages

### Security Testing
- **WAF Detection & Fingerprinting:** Identifies Cloudflare, Akamai, AWS WAF, Imperva, and 10+ others
- **WAF Bypass Probing:** Tests known bypass techniques against detected WAFs
- **HTTP Security Header Audit:** Checks 11 security headers with scoring system
- **CORS Misconfiguration Detection:** Tests wildcard, null, and reflect origin misconfigs
- **Information Disclosure Probes:** Tests 40+ sensitive paths (.env, .git, config, debug, etc.)
- **Cookie & Sensitive Header Leak Detection:** Checks for tokens and internal info in response headers
- **HTTP/2 & HTTP/3 Protocol Detection:** Checks protocol support and ALPN negotiation

### Cloud & Infrastructure
- **Cloud Storage Enumeration:** Checks for public S3, Azure Blob, and GCP GCS buckets
- **Custom Header Injection:** Tests with user-provided headers from a file

### Output & Reporting
- **JSON + CSV Export:** Machine-readable output for tool integration
- **Markdown Report Generator:** Professional scan report with all findings
- **Scan Comparison/Diff:** Highlights new/removed subdomains between scans
- **Scan Resume/Checkpoint:** Resume interrupted scans from saved state
- **Multi-Domain Batch Mode:** Process multiple targets from a file concurrently
- **Concurrent Multi-Phase Scanner:** Runs passive + fingerprint + ports + security simultaneously
- **Colored Terminal Output:** ANSI color-coded findings (green=found, red=critical, yellow=warning)
- **Progress Bars with ETA:** Real-time progress indicators for every scan phase
- **Screenshot Capture:** Headless chromium screenshots (requires playwright)

### Hardening (10 System-Level Improvements)
1. **Signal Handling + Clean Shutdown:** Graceful SIGINT/SIGTERM with partial result saving
2. **SSL/TLS Error Resilience:** Handles SSLError, ConnectionReset with backoff
3. **Rate Limit Adaptive Threading:** Auto-backoff on HTTP 429/403 per service
4. **Request Session Pooling:** Connection reuse via `requests.Session` (20-connection pool)
5. **Circuit Breaker:** Stops hammering failing targets after N consecutive failures
6. **Output Atomicity:** Temp-file-then-rename prevents corrupt output files
7. **Duplicate Suppression:** Proper dedup at print AND write layers
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

# Full recon with all features
python Subdom.py -d example.com --all --full-recon --json --verbose

# API endpoint discovery from JavaScript
python Subdom.py -d example.com --active --js-endpoints --verbose

# Check for subdomain takeover
python Subdom.py -d example.com --passive --takeover --verbose

# Security audit (headers + CORS)
python Subdom.py -d example.com --active --security-audit --verbose

# Directory enumeration
python Subdom.py -d example.com --dir --dir-wordlist /path/to/my/dirs.txt

# Compare against a previous scan
python Subdom.py -d example.com --passive --diff bug_bounty_output/previous_scan_passive.txt

# Batch scan multiple domains
python Subdom.py --batch targets.txt --all --json --verbose

# Generate markdown report
python Subdom.py -d example.com --all --report --verbose

# Custom headers injection
python Subdom.py -d example.com --active --custom-headers my_headers.txt
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
| `--full-recon` | Run ALL recon features at once |
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
| `--permute` | Run subdomain permutation engine |
| `--ssl-intel` | SSL/TLS certificate intelligence |
| `--waf-detect` | WAF detection & fingerprinting |
| `--robots` | Crawl robots.txt & sitemaps for hidden paths |
| `--js-endpoints` | Extract API endpoints from JavaScript files |
| `--security-audit` | HTTP security header audit + CORS check |
| `--api-probe` | API path probing (60+ common paths) |
| `--info-leak` | Information disclosure probes (40+ paths) |
| `--emails` | Email & contact extraction |
| `--wayback-urls` | Wayback Machine URL extraction |
| `--zone-transfer` | DNS zone transfer testing |
| `--tech-versions` | Technology version extraction |
| `--netblocks` | Discover IP netblocks |
| `--cloud-buckets` | Cloud storage enumeration (S3/GCS/Azure) |
| `--report` | Generate Markdown scan report |
| `--custom-headers` | Custom headers file (one per line: Name: Value) |
| `--header-leaks` | Detect sensitive header leaks |
| `--protocols` | Detect HTTP/2 & HTTP/3 support |
| `--concurrent` | Run all scan phases concurrently |
| `--screenshots` | Capture screenshots (requires playwright) |
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
| `*_report.md` | Markdown scan report |
| `*_resolve.json` | IP resolution & ASN data |
| `*_ports.json` | Port scan results |
| `*_tech.json` | Technology fingerprint data |
| `*_tech_versions.json` | Technology version data |
| `*_dns_records.json` | DNS record enumeration |
| `*_methods.json` | HTTP method fingerprinting |
| `*_vhost.json` | Virtual host detection data |
| `*_takeover.json` | Subdomain takeover findings |
| `*_ssl.json` | SSL/TLS certificate intelligence |
| `*_waf.json` | WAF detection results |
| `*_robots.txt` | Paths from robots.txt/sitemaps |
| `*_js_endpoints.json` | JavaScript API endpoints |
| `*_api_paths.json` | Discovered API paths |
| `*_info_leak.json` | Information disclosure findings |
| `*_emails.txt` | Extracted email addresses |
| `*_wayback_urls.txt` | Wayback Machine URLs |
| `*_zone_transfer.json` | DNS zone transfer results |
| `*_netblocks.txt` | Discovered IP netblocks |
| `*_cloud_buckets.json` | Cloud storage findings |
| `*_security_headers.json` | Security header audit results |
| `*_cors.json` | CORS misconfiguration results |
| `*_header_leaks.json` | Sensitive header leak results |
| `*_protocols.json` | HTTP/2 & HTTP/3 detection |
| `*_screenshots/` | Screenshots of live subdomains |
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
