# SUBDOM v9.0

```
  ███████╗██╗   ██╗██████╗  ██████╗ ███████╗███╗   ███╗███████╗███╗   ██╗ ██████╗
  ██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔════╝████╗ ████║██╔════╝████╗  ██║██╔════╝
  ███████╗██║   ██║██████╔╝██║   ██║███████╗██╔████╔██║█████╗  ██╔██╗ ██║██║
  ╚════██║██║   ██║██╔═══╝ ██║   ██║╚════██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║██║
  ███████║╚██████╔╝██║     ╚██████╔╝███████║██║ ╚═╝ ██║███████╗██║ ╚████║╚██████╗
  ╚══════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝
```

**The Ultimate Subdomain & Directory Enumeration Engine** for bug bounty hunting and web application reconnaissance.

70+ features, 15 hardening fixes, 12 passive sources — built to outperform dirsearch, subfinder, and every other recon tool.

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

### Basic Examples

```bash
# Full recon with all features
python Subdom.py -d example.com --full-recon --json --verbose

# Quick scan with profile
python Subdom.py -d example.com --profile quick

# API-focused scan
python Subdom.py -d example.com --profile api

# Security audit
python Subdom.py -d example.com --profile security

# Passive only
python Subdom.py -d example.com --passive --threads 20

# Directory scan with extensions
python Subdom.py -d example.com --dir --verbose

# Generate config file
python Subdom.py --gen-config

# Batch scan
python Subdom.py --batch targets.txt --all --json
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
