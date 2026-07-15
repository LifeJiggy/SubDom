# SUBDOM Usage Guide

Complete usage reference organized by skill level.

---

## Basic Usage

For users getting started with subdomain enumeration.

### First Run

```bash
# Install dependencies
pip install -r requirements.txt

# Generate config file
python Subdom.py --gen-config

# Validate a domain
python Subdom.py -d example.com --validate

# Run all default steps
python Subdom.py -d example.com --all
```

### Subdomain Enumeration

```bash
# Passive only (fast, no direct contact)
python Subdom.py -d example.com --passive

# Active bruteforce only
python Subdom.py -d example.com --active

# Both passive and active
python Subdom.py -d example.com --passive --active

# With wildcard detection
python Subdom.py -d example.com --wildcard --passive
```

### Host Probing

```bash
# Find live hosts (HTTP 200)
python Subdom.py -d example.com --probe

# Probe with custom threads
python Subdom.py -d example.com --probe --threads 30
```

### Directory Enumeration

```bash
# Basic directory scan
python Subdom.py -d example.com --dir

# With verbose output
python Subdom.py -d example.com --dir --verbose

# Custom wordlist
python Subdom.py -d example.com --dir --dir-wordlist my_dirs.txt
```

### Output Options

```bash
# JSON output
python Subdom.py -d example.com --all --json

# CSV output
python Subdom.py -d example.com --all --csv

# Custom output prefix
python Subdom.py -d example.com --all --output myscan
```

### Scan Profiles

```bash
# Quick scan (passive + probe)
python Subdom.py -d example.com --profile quick

# Normal scan (all steps + fingerprint)
python Subdom.py -d example.com --profile normal

# Full recon (everything)
python Subdom.py -d example.com --profile full
```

---

## Professional Usage

For security researchers and bug bounty hunters.

### Targeted Reconnaissance

```bash
# Subdomain + SSL + DNS records
python Subdom.py -d target.com --passive --ssl-intel --dns-records --verbose

# Technology fingerprinting
python Subdom.py -d target.com --fingerprint --tech-versions --resolve

# Port scanning
python Subdom.py -d target.com --probe --scan-ports --verbose
```

### Security Testing

```bash
# Full security audit
python Subdom.py -d target.com --security-audit --info-leak --takeover --zone-transfer

# CORS testing
python Subdom.py -d target.com --security-audit --verbose

# Host header injection
python Subdom.py -d target.com --host-inject --verbose

# SSRF testing
python Subdom.py -d target.com --ssrf --verbose
```

### API Discovery

```bash
# JavaScript endpoint extraction
python Subdom.py -d target.com --js-endpoints --verbose

# GraphQL introspection
python Subdom.py -d target.com --graphql --verbose

# JWT detection
python Subdom.py -d target.com --jwt --verbose

# OAuth discovery
python Subdom.py -d target.com --oauth --verbose

# Combined API recon
python Subdom.py -d target.com --js-endpoints --api-probe --graphql --jwt --oauth
```

### Cloud Enumeration

```bash
# AWS/GCP/Azure bucket enum
python Subdom.py -d target.com --cloud-buckets --verbose

# Netblock discovery
python Subdom.py -d target.com --netblocks --resolve --verbose

# Combined cloud recon
python Subdom.py -d target.com --cloud-buckets --netblocks --resolve
```

### Advanced Subdomain Discovery

```bash
# Permutation engine
python Subdom.py -d target.com --permute --verbose

# Recursive enumeration
python Subdom.py -d target.com --recursive --recursive-depth 2

# GitHub leak search (automatic in passive mode)
python Subdom.py -d target.com --passive --verbose
```

### Report Generation

```bash
# Markdown report
python Subdom.py -d target.com --full-recon --report

# JSON + CSV export
python Subdom.py -d target.com --full-recon --json --csv

# JSONL streaming
python Subdom.py -d target.com --full-recon --jsonl
```

### Scan Comparison

```bash
# Compare with previous scan
python Subdom.py -d target.com --passive --diff bug_bounty_output/old_scan_passive.txt
```

### Batch Operations

```bash
# Scan multiple domains
python Subdom.py --batch targets.txt --all --json --verbose

# Batch with profile
python Subdom.py --batch targets.txt --profile recon --json
```

### Configuration

```bash
# Generate config file
python Subdom.py --gen-config

# Use config file
python Subdom.py -d target.com --config subdom_config.yaml

# Custom headers
python Subdom.py -d target.com --custom-headers my_headers.txt --verbose
```

### Resume & Checkpoint

```bash
# Resume interrupted scan
python Subdom.py -d target.com --all --resume
```

---

## Expert Usage

For advanced red team operations and professional engagements.

### Full Engagement Workflow

```bash
# Phase 1: Reconnaissance
python Subdom.py -d target.com --profile recon --json --report

# Phase 2: Analysis
python Subdom.py -d target.com --fingerprint --resolve --scan-ports --ssl-intel --dns-records

# Phase 3: Discovery
python Subdom.py -d target.com --js-endpoints --graphql --api-probe --robots --wayback-urls

# Phase 4: Security
python Subdom.py -d target.com --security-audit --info-leak --takeover --zone-transfer --smuggle

# Phase 5: Cloud
python Subdom.py -d target.com --cloud-buckets --netblocks --resolve
```

### Aggressive Scan with All Features

```bash
python Subdom.py -d target.com \
  --full-recon \
  --permute \
  --recursive --recursive-depth 2 \
  --ssl-intel \
  --dns-records \
  --scan-ports \
  --fingerprint --tech-versions \
  --waf-detect \
  --robots \
  --js-endpoints \
  --graphql --jwt --oauth \
  --security-audit \
  --api-probe \
  --info-leak \
  --emails \
  --wayback-urls \
  --zone-transfer \
  --netblocks \
  --cloud-buckets \
  --smuggle --ws-test --host-inject --ssrf \
  --cname-takeover \
  --header-leaks --protocols \
  --report --json --csv \
  --verbose \
  --threads 30 \
  --timeout 8
```

### Stealth Scan

```bash
# Low and slow — avoid detection
python Subdom.py -d target.com \
  --passive \
  --ssl-intel --dns-records \
  --profile stealth \
  --timeout 10 \
  --custom-headers stealth_headers.txt
```

### WAF-Aware Scan

```bash
# Detect WAF first, then scan with adjusted settings
python Subdom.py -d target.com --waf-detect --verbose

# If WAF detected, use lower threads
python Subdom.py -d target.com --all --threads 5 --timeout 10
```

### Continuous Monitoring

```bash
# Run every hour via cron
0 * * * * cd /path/to/subdom && python Subdom.py -d target.com --passive --json --output "monitor_$(date +\%Y\%m\%d_\%H)" 2>&1 >> monitor.log
```

### Multi-Target Engagement

```bash
# Create targets file
echo "target1.com" > targets.txt
echo "target2.com" >> targets.txt
echo "target3.com" >> targets.txt

# Scan all targets with full recon
python Subdom.py --batch targets.txt --profile full --json --report
```

### Custom Plugin Development

```python
# plugins/my_scanner.py
PLUGIN_META = {
    "name": "Custom Scanner",
    "description": "Custom security scan",
    "function": lambda target, subdomains, active, proxies, verbose: {
        "custom_findings": []
    }
}
```

```bash
# Run with plugins
python Subdom.py -d target.com --plugins --verbose
```

### Environment Variables

```bash
# Set API keys for enhanced passive sources
export SHODAN_API_KEY="your-key"
export SECURITYTRAILS_API_KEY="your-key"
export VIRUSTOTAL_API_KEY="your-key"

# Now scan with Shodan integration
python Subdom.py -d target.com --shodan --verbose
```

### Proxy Configuration

```bash
# Create proxies.txt
echo "http://proxy1:8080" > proxies.txt
echo "http://proxy2:8080" >> proxies.txt

# Scan through proxies
python Subdom.py -d target.com --all --proxies proxies.txt
```

### Rate Limiting & Throttling

```bash
# Conservative scan (avoid blocking)
python Subdom.py -d target.com --all --threads 3 --timeout 15

# Aggressive scan (fast, may trigger WAF)
python Subdom.py -d target.com --all --threads 50 --timeout 3
```

### Output Analysis

```bash
# View JSON results
cat bug_bounty_output/target.com_full_report.json | python -m json.tool

# View scan diff
cat bug_bounty_output/target.com_diff.txt

# View Markdown report
cat bug_bounty_output/target.com_report.md
```

---

## CLI Reference

### Core Flags

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain |
| `--batch` | File of multiple targets |
| `-t`, `--threads` | Thread count (default: 10) |
| `--timeout` | Request timeout (default: 5) |
| `--verbose` | Verbose output |

### Scan Modes

| Flag | Description |
|------|-------------|
| `--passive` | Passive subdomain enum only |
| `--active` | Active bruteforce only |
| `--probe` | Probe for live hosts |
| `--dir` | Directory enumeration |
| `--all` | Run all steps |
| `--full-recon` | Run ALL features |

### Scan Profiles

| Flag | Description |
|------|-------------|
| `--profile quick` | Fast: passive + probe |
| `--profile normal` | Standard: all + fingerprint |
| `--profile aggressive` | Deep: everything + permute |
| `--profile stealth` | Low: passive only, 3 threads |
| `--profile recon` | Full recon with analysis |
| `--profile api` | API-focused scan |
| `--profile security` | Security-focused scan |
| `--profile full` | Maximum everything |

### Subdomain Features

| Flag | Description |
|------|-------------|
| `--permute` | Subdomain permutation engine |
| `--recursive` | Recursive enumeration |
| `--recursive-depth` | Recursion depth (default: 1) |
| `--wildcard` | Force wildcard detection |
| `--no-wildcard` | Skip wildcard detection |
| `--cname-takeover` | Fast CNAME takeover check |

### Recon Features

| Flag | Description |
|------|-------------|
| `--fingerprint` | Technology fingerprinting |
| `--tech-versions` | Version extraction |
| `--resolve` | IP + cloud detection |
| `--scan-ports` | Port scanning |
| `--dns-records` | Full DNS records |
| `--methods` | HTTP method fingerprinting |
| `--vhost` | Virtual host detection |
| `--ssl-intel` | SSL/TLS certificate intel |
| `--netblocks` | Netblock discovery |
| `--protocols` | HTTP/2 & HTTP/3 detection |

### Security Features

| Flag | Description |
|------|-------------|
| `--waf-detect` | WAF detection + bypass |
| `--security-audit` | Headers + CORS audit |
| `--info-leak` | Info disclosure probes |
| `--takeover` | Subdomain takeover checks |
| `--zone-transfer` | DNS zone transfer test |
| `--smuggle` | HTTP smuggling probes |
| `--host-inject` | Host header injection |
| `--ssrf` | SSRF parameter testing |
| `--header-leaks` | Sensitive header leaks |

### API Features

| Flag | Description |
|------|-------------|
| `--js-endpoints` | JavaScript endpoint extraction |
| `--api-probe` | API path probing |
| `--graphql` | GraphQL introspection |
| `--jwt` | JWT detection + decode |
| `--oauth` | OAuth endpoint discovery |
| `--robots` | robots.txt/sitemap crawl |
| `--emails` | Email extraction |
| `--wayback-urls` | Wayback URL extraction |

### Cloud Features

| Flag | Description |
|------|-------------|
| `--cloud-buckets` | Cloud storage enum |
| `--shodan` | Shodan passive discovery |
| `--shodan-key` | Shodan API key |

### Output Features

| Flag | Description |
|------|-------------|
| `--json` | Export JSON |
| `--csv` | Export CSV |
| `--jsonl` | JSONL streaming |
| `--report` | Generate Markdown report |
| `--screenshots` | Capture screenshots |
| `--diff` | Compare with previous scan |
| `--resume` | Resume from checkpoint |
| `--output` | Custom output prefix |

### Configuration

| Flag | Description |
|------|-------------|
| `--config` | YAML/JSON config file |
| `--gen-config` | Generate default config |
| `--custom-headers` | Custom headers file |
| `--plugins` | Load plugins |
| `--validate` | Validate input only |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SHODAN_API_KEY` | Shodan API key |
| `SECURITYTRAILS_API_KEY` | SecurityTrails API key |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |

---

## Output Files

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
