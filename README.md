# SUBDOM

```
    _____ ____  _   _ __  __ _____   ____  _____ _   _
   / ____/ ___|| | | |  \/  | ____| / ___|| ____| \ |
  | |   \___ \| | | | |\/| |  _|   \___ \|  _| |  \|
  | |___ ___) | |_| | |  | | |___   ___) | |___| |\_
   \____|____/ \___/|_|  |_|_____| |____/|_____|_| \_\
```

## About

SUBDOM is a Python-based subdomain and directory enumeration tool designed for security researchers and bug bounty hunters. It automates the discovery of subdomains, live hosts, hidden endpoints, and attack surface across a target domain.

### What It Does

- **Subdomain Enumeration** — Discovers subdomains using 12 passive sources (DNS, crt.sh, Wayback, Anubis, Hackertarget, Certspotter, Facebook CT, AlienVault OTX, DNSDumpster, RapidDNS, GitHub, SecurityTrails, VirusTotal) and active bruteforce with wildcard detection.
- **Host Probing** — Validates which subdomains are live (HTTP 200) with HTTPS/HTTP fallback.
- **Directory Discovery** — Scans for hidden paths using multi-method requests, extension fuzzing, recursive scanning, and technology-aware wordlists.
- **Reconnaissance** — SSL/TLS certificate analysis, DNS record enumeration, port scanning, technology fingerprinting, WAF detection, and cloud service enumeration (AWS/GCP/Azure).
- **Security Testing** — HTTP smuggling probes, CORS misconfiguration detection, host header injection, SSRF parameter testing, subdomain takeover checks, and information disclosure scans.
- **API Discovery** — JavaScript endpoint extraction, GraphQL introspection, JWT token detection, OAuth endpoint discovery, and API path probing.
- **Reporting** — Exports results in JSON, CSV, JSONL, and Markdown formats with scan comparison and resume capabilities.

### Key Capabilities

| Capability | Details |
|------------|---------|
| Passive Sources | 12 sources (DNS, CT logs, threat intel, code search) |
| Active Scanning | Bruteforce with wildcard filtering, directory engine with 27 extensions |
| Security Tests | Smuggling, CORS, host injection, SSRF, takeover, info leak |
| Cloud Enum | AWS (S3, Lambda, CloudFront, RDS), GCP (GCS, Cloud Run, Firebase), Azure (Blob, Functions, Cosmos DB) |
| Output Formats | JSON, CSV, JSONL, Markdown reports |
| Scan Profiles | quick, normal, aggressive, stealth, recon, api, security, full |
| Error Handling | Graceful degradation, rate limiting, circuit breakers, atomic writes |

---

## Quick Start

```bash
git clone https://github.com/LifeJiggy/SubDom.git
cd Subdom
pip install -r requirements.txt
python Subdom.py -d example.com --full-recon --verbose
```

---

## Features

### Subdomain Enumeration (12 Passive + Active)
| Source | Auth | Notes |
|--------|------|-------|
| DNS Bruteforce | None | 165+ built-in words |
| crt.sh | None | Certificate Transparency |
| Wayback Machine | None | Historical subdomains |
| Anubis | None | Passive DNS |
| Hackertarget | None | API-based |
| Certspotter | None | CT logs |
| Facebook CT | None | Meta's CT API |
| AlienVault OTX | None | Threat intel |
| DNSDumpster | None | CSRF extraction |
| RapidDNS | None | Fast lookups |
| GitHub | None | Code leak search |
| SecurityTrails | API Key | `SECURITYTRAILS_API_KEY` |
| VirusTotal | API Key | `VIRUSTOTAL_API_KEY` |

### Reconnaissance & Analysis
- **Wildcard DNS Detection** — Auto-filters false positives
- **Subdomain Permutation Engine** — Flip/insert/append variations
- **SSL/TLS Certificate Intelligence** — SANs, issuer, expiry, key size
- **Technology Fingerprinting** — Server, framework, CMS, analytics
- **Technology Version Extraction** — Exact versions for CVE matching
- **IP Resolution & Cloud Detection** — AWS/GCP/Azure/Cloudflare
- **Port Scanning** — Top 34 ports
- **DNS Record Expansion** — A/AAAA/MX/TXT/CNAME/NS/SOA/CAA/SRV
- **DNS Zone Transfer Testing** — AXFR vulnerability check
- **HTTP Method Fingerprinting** — GET/POST/PUT/DELETE/OPTIONS/PATCH
- **Virtual Host Detection** — Anomaly and default content
- **Subdomain Takeover** — 30+ service signatures
- **Netblock/CIDR Discovery** — IP range enumeration

### API & Endpoint Discovery
- **JavaScript Endpoint Extraction** — External, internal, hidden APIs
- **API Path Probing** — 60+ common paths
- **robots.txt / sitemap.xml Crawler** — Hidden paths
- **Wayback Machine URL Extraction** — Historical endpoints
- **GraphQL Introspection** — Full schema extraction
- **JWT Token Detection** — Decode + alg=none check
- **OAuth/OIDC Discovery** — Authorization/token/userinfo endpoints
- **Email & Contact Extraction** — Scrapes emails and social links

### Security Testing
- **WAF Detection & Fingerprinting** — 10 WAF signatures
- **WAF Bypass Probing** — 6 bypass techniques
- **HTTP Security Header Audit** — 11 headers, scoring
- **CORS Misconfiguration** — Wildcard/null/reflect origin
- **HTTP Request Smuggling** — CL.TE/TE.CL probes
- **Host Header Injection** — Password reset poisoning
- **SSRF Parameter Testing** — URL parameter fuzzing
- **WebSocket Endpoint Testing** — Connect + enumerate
- **Information Disclosure** — 40+ sensitive paths (.env, .git, debug, etc.)
- **Cookie & Header Leak Detection** — Sensitive info in responses

### Cloud & Infrastructure
- **AWS Enumeration** — S3 (13 regions), Lambda, CloudFront, EC2, RDS
- **GCP Enumeration** — GCS, Cloud Run, App Engine, Firebase
- **Azure Enumeration** — Blob, Files, Functions, App Service, Cosmos DB

### Directory Engine (dirsearch-killer)
- **Multi-method** — GET/HEAD/PUT/DELETE/OPTIONS/PATCH
- **Extension Fuzzing** — 27 extensions (.php, .bak, .old, .config, etc.)
- **Case Variation** — capitalize/UPPER/lower
- **Recursive Scanning** — Deeper path discovery
- **Tech-Aware Paths** — WordPress/Laravel/Django/Spring/Express/Rails
- **Sensitive Directories** — 40+ always-tested paths
- **Content-Based Dedup** — Eliminates false positives
- **Baseline Comparison** — 3-path smart baseline

### Architecture
- **Scan Profiles** — quick/normal/aggressive/stealth/recon/api/security/full
- **YAML/JSON Config** — Save scan presets
- **Plugin System** — Drop `.py` files into `plugins/`
- **JSONL Streaming** — Live result streaming
- **Batch Mode** — Multi-domain concurrent scanning
- **Concurrent Scanner** — Parallel phase execution
- **Markdown Report** — Professional scan reports
- **Screenshot Capture** — Headless chromium (requires playwright)

### Hardening (15 Fixes)
1. Signal handling + graceful shutdown
2. SSL/TLS error resilience
3. Adaptive rate limiting (429/403 backoff)
4. HTTP session pooling (20 connections)
5. Circuit breaker (fail threshold)
6. Atomic file writes
7. Content fingerprint dedup
8. Memory-bounded results
9. Domain regex validation
10. Exponential backoff + jitter
11. Request jitter (anti-pattern detection)
12. WAF auto-profile (thread/delay adjustment)
13. Tor proxy support
14. Performance monitoring (RPS, error rates)
15. False positive filter (body/title/size analysis)

---

## Usage

For comprehensive usage guides, see [USAGE.md](USAGE.md) with Basic, Professional, and Expert examples.

### Quick Start

```bash
# Passive subdomain enumeration
python Subdom.py -d example.com --passive --verbose

# Full recon with all features
python Subdom.py -d example.com --full-recon --json --verbose

# Use a scan profile
python Subdom.py -d example.com --profile recon

# Directory enumeration
python Subdom.py -d example.com --dir --verbose

# Generate config file
python Subdom.py --gen-config

# Batch scan multiple domains
python Subdom.py --batch targets.txt --all --json
```

### Scan Profiles

```bash
--profile quick       # Fast: passive + probe
--profile normal      # Standard: all steps + fingerprint
--profile aggressive  # Deep: everything + permute + high threads
--profile stealth     # Low and slow: passive only, 3 threads
--profile recon       # Full recon with all analysis
--profile api         # API-focused: endpoints + GraphQL + JWT
--profile security    # Security: headers, CORS, takeover, zone transfer
--profile full        # Maximum: everything enabled
```

### Common Workflows

```bash
# Bug bounty recon
python Subdom.py -d target.com --profile recon --json --report

# Quick subdomain check
python Subdom.py -d target.com --passive --ssl-intel --dns-records

# Deep directory scan
python Subdom.py -d target.com --dir --recursive --verbose

# Security audit
python Subdom.py -d target.com --security-audit --info-leak --takeover

# API discovery
python Subdom.py -d target.com --js-endpoints --api-probe --graphql

# Cloud enumeration
python Subdom.py -d target.com --cloud-buckets --resolve --netblocks
```

### Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `-d`, `--domain` | Target domain |
| `--batch` | File of multiple targets |
| `-t`, `--threads` | Thread count (default: 10) |
| `--passive` | Passive subdomain enum only |
| `--active` | Active bruteforce only |
| `--probe` | Probe for live hosts |
| `--dir` | Directory enumeration |
| `--all` | Run all steps |
| `--full-recon` | Run ALL features |
| `--profile` | Scan profile |
| `--config` | YAML/JSON config file |
| `--gen-config` | Generate default config |
| `--fingerprint` | Tech fingerprinting |
| `--resolve` | IP + cloud detection |
| `--scan-ports` | Port scanning |
| `--dns-records` | Full DNS records |
| `--methods` | HTTP method fingerprinting |
| `--vhost` | Virtual host detection |
| `--takeover` | Subdomain takeover checks |
| `--recursive` | Recursive subdomain enum |
| `--permute` | Subdomain permutation engine |
| `--ssl-intel` | SSL/TLS certificate intel |
| `--waf-detect` | WAF detection + bypass |
| `--robots` | robots.txt/sitemap crawl |
| `--js-endpoints` | JS endpoint extraction |
| `--security-audit` | Headers + CORS audit |
| `--api-probe` | API path probing |
| `--info-leak` | Info disclosure probes |
| `--emails` | Email extraction |
| `--wayback-urls` | Wayback URL extraction |
| `--zone-transfer` | DNS zone transfer test |
| `--tech-versions` | Version extraction |
| `--netblocks` | Netblock discovery |
| `--cloud-buckets` | Cloud storage enum |
| `--graphql` | GraphQL introspection |
| `--jwt` | JWT detection + decode |
| `--oauth` | OAuth endpoint discovery |
| `--smuggle` | HTTP smuggling probes |
| `--ws-test` | WebSocket testing |
| `--host-inject` | Host header injection |
| `--ssrf` | SSRF parameter testing |
| `--shodan` | Shodan passive discovery |
| `--cname-takeover` | Fast CNAME takeover check |
| `--report` | Generate Markdown report |
| `--json` | Export JSON |
| `--csv` | Export CSV |
| `--jsonl` | JSONL streaming output |
| `--screenshots` | Capture screenshots |
| `--plugins` | Load plugins |
| `--diff` | Compare with previous scan |
| `--resume` | Resume from checkpoint |
| `--validate` | Validate input only |
| `--verbose` | Verbose output |
| `--timeout` | Request timeout (default: 5) |

### Output Files

All results saved to `bug_bounty_output/`:

| File | Description |
|------|-------------|
| `*_passive.txt` | Passive subdomains |
| `*_active.txt` | Active subdomains |
| `*_active_200.txt` | Live hosts |
| `*_dirs.txt` | Directories |
| `*_ssl.json` | SSL certificate intel |
| `*_waf.json` | WAF detection |
| `*_dns_records.json` | DNS records |
| `*_tech.json` | Technology stack |
| `*_tech_versions.json` | Versions |
| `*_ports.json` | Port scan |
| `*_methods.json` | HTTP methods |
| `*_vhost.json` | Virtual hosts |
| `*_takeover.json` | Takeover findings |
| `*_graphql.json` | GraphQL schema |
| `*_jwt.json` | JWT tokens |
| `*_oauth.json` | OAuth endpoints |
| `*_js_endpoints.json` | JS API endpoints |
| `*_api_paths.json` | API paths |
| `*_info_leak.json` | Info disclosure |
| `*_emails.txt` | Email addresses |
| `*_wayback_urls.txt` | Wayback URLs |
| `*_zone_transfer.json` | Zone transfer |
| `*_netblocks.txt` | IP ranges |
| `*_cloud_buckets.json` | Cloud storage |
| `*_security_headers.json` | Header audit |
| `*_cors.json` | CORS issues |
| `*_smuggle.json` | Smuggling probes |
| `*_websocket.json` | WebSocket endpoints |
| `*_host_inject.json` | Host injection |
| `*_ssrf.json` | SSRF findings |
| `*_shodan.json` | Shodan data |
| `*_protocols.json` | HTTP/2, HTTP/3 |
| `*_header_leaks.json` | Header leaks |
| `*_report.md` | Markdown report |
| `*_full_report.json` | Complete JSON |
| `*_report.csv` | CSV export |
| `*_screenshots/` | Screenshots |
| `.*_checkpoint.json` | Resume state |

---

## Configuration

```bash
# Generate default config
python Subdom.py --gen-config

# Edit subdom_config.yaml
# Run with config
python Subdom.py -d example.com --config subdom_config.yaml
```

### Environment Variables

```bash
export SHODAN_API_KEY="your-key"
export SECURITYTRAILS_API_KEY="your-key"
export VIRUSTOTAL_API_KEY="your-key"
```

---

## Requirements

```
requests
beautifulsoup4
dnspython
pyopenssl
cryptography
service-identity
```

Optional:
```
playwright      # For screenshots
websocket-client # For WebSocket testing
pyyaml          # For YAML config
```

---

## License

MIT License

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)
