#!/usr/bin/env python3

import argparse
import os
import time
import random
import requests
import json
import logging
import dns.resolver
from typing import List, Set, Dict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup
import re
import sys
import string
  
  # Default paths (bundled or downloaded on first run)
OUTPUT_DIR = "bug_bounty_output"
TARGET_FILE = "targets.txt"
LOG_FILE = f"{OUTPUT_DIR}/bug_bounty.log"
DEFAULT_SUBDOMAIN_WORDLIST = "subdomains.txt"
DEFAULT_DIR_WORDLIST = "directories.txt"
PROXY_LIST = "proxies.txt"
# Ensure output directory exists
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Logging setup
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Banners
START_BANNER = """
=======================================
    Bug Bounty Beast v6.0
    Powered by ArkhAngelLifeJiggy - March 13, 2025
    Unleash the Hunt!
=======================================
"""
END_BANNER = """
=======================================
   Hunt Conquered! You're a Bug Bounty Legend!
=======================================
"""
SUBDOMAIN_BANNER = """
=======================================
   Subdomain Enumeration
   Tools: DNS, CRT.sh, Wayback, Bruteforce (Built-in)
=======================================
"""
DIR_BANNER = """
=======================================
   Directory Enumeration & Bruteforcing
   Tools: Built-in HTTP Requests
=======================================
"""

# --- ADD THIS BANNER ---
BRUTEFORCE_BANNER = """
=======================================
   Active Subdomain Bruteforce
   Tools: Built-in HTTP Requests
=======================================
"""
# --- END OF NEW BANNER ---


# WAF Bypass Resources
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 12; OnePlus 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; ARM64; rv:122.0) Gecko/20100101 Firefox/122.0"
    
]

WAF_BYPASS_HEADERS = {
    "User-Agent": lambda: random.choice(USER_AGENTS),
    "Referer": lambda: "https://example.com",
    "X-Forwarded-For": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "X-Forwarded-For-Original": lambda: f"{random.randint(1 , 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "Client-IP": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "X-Client-IP": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "X-Remote-IP": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "X-Remote-Addr": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "True-Client-IP": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "X-Host": lambda: random.choice(["127.0.0.1", "localhost", "internal"]),
    "X-Forwarded-Host": lambda: random.choice(["127.0.0.1", "localhost"]),
    "X-Original-URL": "/admin",
    "X-Rewrite-URL": "/admin",
    "Forwarded": lambda: f"for={random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "Forwarded-For": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "X-Forwarded-Server": "localhost",
    "X-Forwarded-Proto": "https",
    "X-Original-Host": "127.0.0.1",
    "X-Forwarded-Scheme": "http",
    "X-Forwarded-Port": "80",
    "X-Forwarded-Protocol": "http",
    "X-HTTP-Host-Override": "127.0.0.1",
    "X-Original-Forwarded-For": "127.0.0.1",
    "X-ATT-DeviceId": "GT-P7320",
    "X-WAP-Profile": "http://wap.samsungmobile.com/uaprof/GT-P7320.xml",
    "X-Requested-With": "XMLHttpRequest",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Forwarded-By": "127.0.0.1",
    "Via": "1.1 localhost",
    "CF-Connecting-IP": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "True-Client-Port": "443",
    "X-Real-URL": "/admin",
    "X-Original-Remote-Addr": "127.0.0.1",
    "X-ProxyUser-Ip": "127.0.0.1",
    "X-Forwarded-For-Original": "127.0.0.1",
    "X-Forwarded": "127.0.0.1",
    "X-Remote-User": "admin",
    "X-Original-Remote-User": "admin",
    "X-Forwarded-User": "admin",
    "X-Forwarded-Login": "admin",
    "X-Forwarded-Access": "admin",
    "X-Forwarded-Authorization": "Basic YWRtaW46YWRtaW4=",
    "X-Api-Version": "1.0",
    "X-Request-ID": lambda: f"{random.randint(100000, 999999)}-{random.randint(1000, 9999)}",
    "X-Forwarded-Token": "test-token",
    "X-Bypass-Cache": "1",
    "X-Bypass-WAF": "true",
    "X-Ignore-WAF": "1",
    "X-Ignore-RateLimit": "true",
    "X-Bypass-RateLimit": "true",
    "X-Forwarded-Path": "/admin",
    "X-Forwarded-Uri": "/admin",
    "X-Forwarded-Request-Uri": "/admin",
    "X-Forwarded-Original-Uri": "/admin"
}

# Default wordlists (embedded for simplicity)
SUBDOMAIN_WORDS = [
    "www", "api", "mail", "dev", "test", "staging", "admin", "login", "secure", "app",
    "portal", "dashboard", "beta", "alpha", "support", "help", "docs", "blog", "news", "media",
    "cdn", "static", "assets", "files", "images", "img", "video", "videos", "download", "uploads",
    "store", "shop", "cart", "checkout", "billing", "payment", "invoice", "account", "user", "users",
    "profile", "profiles", "auth", "oauth", "sso", "signup", "register", "signin", "logout", "forgot",
    "reset", "verify", "2fa", "mfa", "token", "session", "sessions", "cookie", "cookies", "vault",
    "config", "settings", "preferences", "adminpanel", "control", "panel", "console", "manage", "management", "monitor",
    "monitoring", "status", "uptime", "health", "metrics", "analytics", "insights", "reports", "reporting", "logs",
    "log", "debug", "trace", "errors", "error", "alerts", "notifications", "queue", "jobs", "tasks",
    "cron", "scheduler", "pipeline", "ci", "cd", "build", "deploy", "release", "version", "releases",
    "api-v1", "api-v2", "api-v3", "internal", "private", "public", "external", "legacy", "old", "archive",
    "backup", "backups", "dump", "dumps", "db", "database", "sql", "mysql", "pgsql", "mongo",
    "redis", "cache", "sessionstore", "storage", "blob", "bucket", "cdn-edge", "edge", "proxy", "gateway",
    "firewall", "vpn", "ssh", "ftp", "sftp", "smtp", "imap", "pop", "mailserver", "mx",
    "dns", "ns1", "ns2", "ns3", "ns4", "whois", "resolver", "bind", "zone", "records",
    "dev1", "dev2", "test1", "test2", "qa", "uat", "sandbox", "preview", "demo", "examples",
    "sample", "mock", "fake", "dummy", "stubs", "fixtures", "prototype", "experiment", "feature", "flag",
    "toggle", "labs", "research", "innovation", "ideas", "team", "staff", "hr", "careers", "jobs",
    "marketing", "sales", "crm", "leads", "ads", "campaign", "newsletter", "email", "mailing", "subscribe",
    "unsubscribe", "feedback", "survey", "forms", "contact", "connect", "chat", "messenger", "bot", "ai",
    "ml", "nlp", "vision", "speech", "voice", "translate", "transcribe", "ocr", "recognition", "search",
    "engine", "crawler", "spider", "index", "rank", "seo", "sem", "tracking", "pixel", "tag",
    "cdn1", "cdn2", "cdn3", "edge1", "edge2", "edge3", "node1", "node2", "node3", "cluster"
]





DIR_WORDS = [
    "admin", "login", "api", "test", "config", "backup", "docs", "images", "uploads",
    "assets", "static", "css", "js", "fonts", "media", "files", "downloads", "scripts", "includes",
    "lib", "vendor", "modules", "plugins", "themes", "templates", "layouts", "partials", "snippets", "components",
    "core", "engine", "system", "framework", "helpers", "utils", "tools", "functions", "classes", "models",
    "controllers", "routes", "views", "pages", "public", "private", "secure", "internal", "external", "shared",
    "common", "resources", "source", "src", "dist", "build", "release", "version", "archive", "legacy",
    "old", "beta", "alpha", "dev", "development", "prod", "production", "staging", "sandbox", "preview",
    "demo", "example", "samples", "mock", "fake", "testdata", "fixtures", "seed", "data", "db",
    "database", "sql", "sqlite", "mysql", "pgsql", "mongo", "redis", "cache", "session", "sessions",
    "auth", "oauth", "sso", "token", "jwt", "user", "users", "account", "accounts", "profile",
    "profiles", "register", "signup", "signin", "logout", "forgot", "reset", "verify", "2fa", "mfa",
    "adminpanel", "dashboard", "console", "control", "manage", "management", "monitor", "monitoring", "status", "health",
    "uptime", "metrics", "analytics", "insights", "reports", "reporting", "logs", "log", "debug", "trace",
    "errors", "error", "alerts", "notifications", "queue", "jobs", "tasks", "cron", "scheduler", "pipeline",
    "ci", "cd", "deploy", "builds", "releases", "versioning", "api-v1", "api-v2", "api-v3", "v1",
    "v2", "v3", "internal-api", "private-api", "public-api", "graphql", "rest", "rpc", "json", "xml",
    "yaml", "yml", "env", "configurations", "settings", "preferences", "options", "parameters", "secrets", "keys",
    "certs", "ssl", "tls", "crypto", "vault", "keystore", "credentials", "authdata", "access", "permissions",
    "roles", "groups", "teams", "staff", "hr", "careers", "jobsboard", "marketing", "sales", "crm",
    "leads", "ads", "campaigns", "newsletter", "email", "mail", "smtp", "imap", "pop3", "mx",
    "dns", "ns1", "ns2", "whois", "resolver", "bind", "zone", "records", "ftp", "sftp",
    "ssh", "telnet", "vpn", "proxy", "gateway", "firewall", "loadbalancer", "edge", "cdn", "cdn-edge",
    "blob", "bucket", "storage", "filestore", "objectstore", "cloud", "aws", "gcp", "azure", "s3",
    "lambda", "functions", "workers", "microservices", "services", "service", "api-gateway", "webhooks", "hooks", "events",
    "eventbus", "pubsub", "message", "messaging", "mq", "kafka", "rabbitmq", "stream", "streams", "socket",
    "websocket", "signalr", "push", "pull", "polling", "subscribe", "unsubscribe", "callback", "listener", "handler",
    "middleware", "interceptor", "filter", "guard", "resolver", "injector", "context", "sessionstore", "tokenstore", "ratelimit",
    "throttle", "circuitbreaker", "retry", "fallback", "timeout", "queueworker", "jobrunner", "scheduler-task", "cronjob", "heartbeat",
    "ping", "statuspage", "maintenance", "errorpages", "404", "403", "500", "401", "default", "fallback",
    "robots", "sitemap", "manifest", "favicon", "apple-touch-icon", "browserconfig", "crossdomain", "ads", "tracking", "pixel",
    "tag", "gtm", "analyticsjs", "matomo", "plausible", "segment", "mixpanel", "heap", "hotjar", "clarity",
    "abtest", "experiments", "flags", "featureflags", "toggle", "labs", "research", "innovation", "ideas", "prototype",
    "design", "ux", "ui", "styleguide", "branding", "themes-old", "themes-new", "skins", "templates-old", "templates-new"
]




def download_wordlist(url: str, dest: str):
    """Download a wordlist if not present."""
    if not os.path.exists(dest):
        print(f"[*] Downloading wordlist to {dest}")
        try:
            response = requests.get(url, timeout=15, headers={"User-Agent": random.choice(USER_AGENTS)})
            with open(dest, "wb") as f:
                f.write(response.content)
            print(f"[+] Wordlist downloaded: {dest}")
        except Exception as e:
            print(f"[-] Failed to download wordlist: {e}")

def load_wordlist(file_path: str, default: List[str]) -> List[str]:
    """Load wordlist or use default."""
    if os.path.exists(file_path):
        with open(file_path, "r", encoding='utf-8', errors='replace') as f:
            return [line.strip() for line in f if line.strip()]
    return default

def load_proxies(proxy_file: str) -> List[str]:
    """Load proxies for WAF evasion."""
    if not os.path.exists(proxy_file):
        return []
    with open(proxy_file, "r", encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def get_random_proxy(proxies: List[str]) -> str:
    """Return a random proxy."""
    return random.choice(proxies) if proxies else None

def get_waf_bypass_headers() -> Dict[str, str]:
    """Generate random headers for WAF bypass."""
    return {k: v() if callable(v) else v for k, v in WAF_BYPASS_HEADERS.items()}

def normalize_target(target: str) -> str:
    """Normalize target to root domain."""
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    parts = domain.split('.')
    if len(parts) > 2 and parts[0] in ['www', 'mail', 'api']:  # Strip common subdomains
        return '.'.join(parts[1:])
    return domain

def check_http_200(url: str, proxies: List[str], retries: int = 4, verbose: bool = False, timeout: int = 5) -> bool:
    """Validate HTTP 200 with advanced WAF bypass."""
    if not url.startswith("http"):
        url = f"https://{url}"
    for attempt in range(retries):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            headers.update(get_waf_bypass_headers())
            proxy = get_random_proxy(proxies)
            proxies_dict = {"http": proxy, "https": proxy} if proxy else None
            if verbose:
                print(f"[*] Checking {url} (Attempt {attempt + 1}/{retries})")
            response = requests.get(url, headers=headers, proxies=proxies_dict, timeout=timeout, allow_redirects=True)
            if response.status_code == 200:
                if verbose:
                    print(f"[+] {url} validated (HTTP 200)")
                return True
            time.sleep(random.uniform(0.5, 2))
        except requests.RequestException:
            if verbose and attempt == 0:  # Only log first failure
                print(f"[-] Attempt {attempt + 1}/{retries} failed for {url}")
            time.sleep(random.uniform(0.5, 2))
    return False

# Subdomain Enumeration Functions (Built-in)
def run_dns_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via DNS lookups with public resolvers."""
    subdomains = set()
    wordlist = load_wordlist(DEFAULT_SUBDOMAIN_WORDLIST, SUBDOMAIN_WORDS)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Use Google's DNS
    resolver.timeout = 5
    resolver.lifetime = 5
    for sub in wordlist[:100]:  # Limit for speed
        domain = f"{sub}.{target}"
        try:
            answers = resolver.resolve(domain, 'A')
            if answers:
                if domain not in subdomains:
                    subdomains.add(domain)
                if verbose:
                    print(f"[+] DNS found: {domain}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
            continue  # Silently skip failures
        except Exception as e:
            if verbose:
                print(f"[-] DNS error for {domain}: {e}")
    return subdomains

def run_crtsh_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via crt.sh with retries."""
    subdomains = set()
    url = f"https://crt.sh/?q=%.{target}&output=json"
    for attempt in range(3):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "").strip()
                    if name.endswith(f".{target}") and not name.startswith("*"):
                        # Check for uniqueness before printing
                        if name not in subdomains:
                            subdomains.add(name)
                            if verbose:
                                print(f"[+] CRT.sh found: {name}")
                break
            time.sleep(random.uniform(1, 5))
        except Exception as e:
            print(f"[-] CRT.sh error (attempt {attempt + 1}/3): {e}")
            if attempt < 2:
                time.sleep(5)
    return subdomains

def run_wayback_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via Wayback Machine with retries."""
    subdomains = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original"
    for attempt in range(3):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=20)
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header row
                    parsed = urlparse(entry[0])
                    if parsed.netloc and parsed.netloc.endswith(f".{target}"):
                        # Check for uniqueness before printing
                        if parsed.netloc not in subdomains:
                            subdomains.add(parsed.netloc)
                            if verbose:
                                 print(f"[+] Wayback found: {parsed.netloc}")
                break
            time.sleep(random.uniform(1, 5))
        except Exception as e:
            print(f"[-] Wayback error (attempt {attempt + 1}/3): {e}")
            if attempt < 2:
                time.sleep(5)
    return subdomains

# --- REPLACE THE ENTIRE run_bruteforce_enum FUNCTION WITH THIS ---
def run_bruteforce_enum(target: str, wordlist: List[str], verbose: bool, threads: int) -> Set[str]:
    """Bruteforce subdomains with HTTP checks and controlled output."""
    subdomains = set()
    def check_sub(sub):
        domain = f"{sub}.{target}"
        # Call check_http_200 silently by passing verbose=False.
        # We will control the output from here.
        if check_http_200(domain, [], verbose=False):
            if verbose:
                # Only print to the screen if a valid subdomain is found.
                print(f"[+] Active Found: {domain}")
            return domain
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(check_sub, wordlist)
        subdomains.update(sub for sub in results if sub)
    return subdomains
# --- END OF REPLACEMENT ---



# New, improved function
def subdomain_enumeration_passive(target: str, output_file: str, verbose: bool, threads: int) -> Set[str]:
    """Passive subdomain enumeration with deduplication."""
    print(SUBDOMAIN_BANNER)
    subdomains = set()
    tools = [run_dns_enum, run_crtsh_enum, run_wayback_enum]
    
    # Use a smaller number of threads for passive to avoid rate limiting, but still make it configurable
    passive_threads = min(threads, 3)
    with ThreadPoolExecutor(max_workers=passive_threads) as executor:
        futures = {executor.submit(tool, target, verbose): tool for tool in tools}
        for future in futures:
            try:
                subdomains.update(future.result())
            except Exception as e:
                print(f"[-] Error in {futures[future].__name__}: {e}")

    with open(output_file, "w", encoding='utf-8') as f:
        f.write("\n".join(sorted(subdomains)))
    logging.info(f"Passive subdomains saved: {len(subdomains)}")
    if verbose:
        print(f"[+] Passive: Found {len(subdomains)} unique subdomains")
    return subdomains


# New, improved function
def subdomain_enumeration_active(target: str, wordlist: str, output_file: str, verbose: bool, threads: int) -> Set[str]:
    """Active subdomain enumeration with deduplication."""
    print(BRUTEFORCE_BANNER)
    wordlist_data = load_wordlist(wordlist, SUBDOMAIN_WORDS)
    subdomains = run_bruteforce_enum(target, wordlist_data, verbose, threads)
    
    with open(output_file, "w", encoding='utf-8') as f:
        f.write("\n".join(sorted(subdomains)))
    logging.info(f"Active subdomains saved: {len(subdomains)}")
    if verbose:
        print(f"[+] Active: Found {len(subdomains)} unique subdomains")
    return subdomains


def filter_active_subdomains(subdomains: Set[str], output_file: str, proxies: List[str], threads: int, verbose: bool, timeout: int) -> Set[str]:
    """Filter active subdomains with HTTP 200."""
    active_subdomains = set()
    
    def validate_subdomain(sub):
        url = f"https://{sub}"
        if check_http_200(url, proxies, verbose=False, timeout=timeout):
            return sub
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(validate_subdomain, subdomains)
        active_subdomains = {sub for sub in results if sub}

    with open(output_file, "w", encoding='utf-8') as f:
        f.write("\n".join(sorted(active_subdomains)))
    logging.info(f"Active subdomains (HTTP 200): {len(active_subdomains)}")
    if verbose:
        print(f"[+] Filtered: {len(active_subdomains)} active subdomains (HTTP 200)")
    return active_subdomains

# --- REPLACE THE ENTIRE run_dir_bruteforce FUNCTION WITH THIS ---
def run_dir_bruteforce(subdomain: str, wordlist: List[str], proxies: List[str], threads: int, timeout: int) -> Set[str]:
    """
    Bruteforce directories with advanced baseline checks to filter false positives.
    """
    dirs = set()
    baseline_len = None
    
    # 1. Establish a baseline for the "Not Found" page length.
    try:
        # Generate a random path that is highly unlikely to exist.
        random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        baseline_url = f"https://{subdomain}/{random_path}"
        
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        headers.update(get_waf_bypass_headers())
        proxy = get_random_proxy(proxies)
        proxies_dict = {"http": proxy, "https": proxy} if proxy else None

        response = requests.get(baseline_url, headers=headers, proxies=proxies_dict, timeout=timeout, allow_redirects=False)
        if response.status_code == 200:
            baseline_len = len(response.content)
    except requests.RequestException:
        # If we can't establish a baseline, we'll proceed without it.
        pass

    # 2. Check each directory against the baseline.
    def check_dir(dir_path):
        try:
            url = f"https://{subdomain}/{dir_path}"
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            headers.update(get_waf_bypass_headers())
            proxy = get_random_proxy(proxies)
            proxies_dict = {"http": proxy, "https": proxy} if proxy else None

            response = requests.get(url, headers=headers, proxies=proxies_dict, timeout=timeout, allow_redirects=False)
            
            if response.status_code == 200:
                current_len = len(response.content)
                # If the length is different from our baseline, it's a valid finding.
                if baseline_len is None or current_len != baseline_len:
                    return url
        except requests.RequestException:
            return None
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(check_dir, wordlist)
        dirs.update(dir_url for dir_url in results if dir_url)
        
    return dirs


# --- REPLACE THE ENTIRE directory_enumeration FUNCTION WITH THIS ---
def directory_enumeration(subdomains: Set[str], wordlist: str, output_file: str, proxies: List[str], threads: int, verbose: bool, timeout: int):
    """Directory enumeration with deduplication and clean, grouped output."""
    print(DIR_BANNER)
    results = {}
    wordlist_data = load_wordlist(wordlist, DIR_WORDS)

    def enumerate_subdomain(subdomain):
        # The bruteforce function is now silent.
        dirs = run_dir_bruteforce(subdomain, wordlist_data, proxies, threads, timeout)
        
        # We will control the output from here.
        if verbose and dirs:
            # Print a header for the subdomain that has results.
            print(f"\n[+] Directories Found on: https://{subdomain}")
            for dir_url in sorted(dirs):
                print(f"  - {dir_url}")
        
        time.sleep(random.uniform(0.5, 2))
        return subdomain, sorted(dirs)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = dict(executor.map(enumerate_subdomain, subdomains))

    with open(output_file, "w", encoding='utf-8') as f:
        for sub, dirs in results.items():
            if dirs: # Only write subdomains that had results
                f.write(f"{sub}:\n")
                for dir_url in dirs:
                    f.write(f"  {dir_url}\n")
                    
    logging.info(f"Directory enumeration completed for {len(results)} subdomains")
    if verbose:
        print(f"\n[+] Directory results saved to {output_file}")
# --- END OF REPLACEMENT ---

def main():
    parser = argparse.ArgumentParser(description="Bug Bounty - Elite Hunting Tool")
    
    # --- REPLACE WITH THESE TWO LINES ---
    parser.add_argument("-d", "--domain", required=True, help="The target domain (e.g., example.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--passive", action="store_true", help="Run passive subdomain enumeration only")
    parser.add_argument("--active", action="store_true", help="Run active subdomain enumeration only")
    parser.add_argument("--probe", action="store_true", help="Probe for active subdomains only")
    parser.add_argument("--dir", action="store_true", help="Run directory enumeration only")
    parser.add_argument("--all", action="store_true", help="Run all steps")
    parser.add_argument("--sub-wordlist", default=DEFAULT_SUBDOMAIN_WORDLIST, help="Subdomain wordlist path")
    parser.add_argument("--dir-wordlist", default=DEFAULT_DIR_WORDLIST, help="Directory wordlist path")
    parser.add_argument("--proxies", default=PROXY_LIST, help="Proxy list file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", default=None, help="Custom output file prefix")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
    args = parser.parse_args()
    print(START_BANNER)
    logging.info("Hunt started")
    
     # Normalize target to root domain
    target = normalize_target(args.domain)
    if not target:
        print(f"[-] Invalid target: {args.domain}. Please provide a valid domain or URL.")
        logging.error(f"Invalid target provided: {args.domain}")
        return
     
    proxies = load_proxies(args.proxies)
    output_prefix = args.output if args.output else target
    run_all = args.all or not any([args.passive, args.active, args.probe, args.dir])
    # --- END OF PASTED BLOCK ---
    
    
    # Validate target
    if args.verbose:
        print(f"[*] Validating target: {target}")
    if not check_http_200(target, proxies, verbose=args.verbose, timeout=args.timeout):
        print(f"[-] Target {target} not reachable (HTTP 200) after 4 retries. Exiting.")
        logging.error(f"Target {target} unreachable")
        return

    subdomains = set()
    active_subdomains = set()

    # --- REPLACE WITH THIS CORRECTED BLOCK ---
    # Step 1: Subdomain Enumeration
    if run_all or args.passive:
        subdomains.update(subdomain_enumeration_passive(target, f"{OUTPUT_DIR}/{output_prefix}_passive.txt", args.verbose, args.threads))
    if run_all or args.active:
        subdomains.update(subdomain_enumeration_active(target, args.sub_wordlist, f"{OUTPUT_DIR}/{output_prefix}_active.txt", args.verbose, args.threads))
    # --- END OF CORRECTED BLOCK ---

    # Save all subdomains
    if subdomains:
        with open(f"{OUTPUT_DIR}/{TARGET_FILE}", "w", encoding='utf-8') as f:
            f.write("\n".join(sorted(subdomains)))

    # Step 2: Filter Active Subdomains
    if (run_all or args.probe) and subdomains:
        active_subdomains = filter_active_subdomains(subdomains, f"{OUTPUT_DIR}/{output_prefix}_active_200.txt", proxies, args.threads, args.verbose, args.timeout)

        # --- ADD THIS NEW BLOCK ---
    # If running in directory-only mode, load targets from file and probe them.
    if args.dir and not run_all:
        targets_path = f"{OUTPUT_DIR}/{TARGET_FILE}"
        if os.path.exists(targets_path):
            print(f"[*] Directory mode: Loading targets from {targets_path}")
            with open(targets_path, "r", encoding='utf-8') as f:
                subdomains_from_file = {line.strip() for line in f if line.strip()}
            
            if subdomains_from_file:
                # We have targets, now we need to find which are active.
                active_subdomains = filter_active_subdomains(subdomains_from_file, f"{OUTPUT_DIR}/{output_prefix}_active_200.txt", proxies, args.threads, args.verbose, args.timeout)
        else:
            print(f"[-] Directory mode requires a list of targets. Run a scan with --passive or --active first to generate {targets_path}.")
            # active_subdomains will remain empty, and the script will exit gracefully.
    # --- END OF NEW BLOCK ---
    
    # Step 3: Directory Enumeration
    if (run_all or args.dir) and active_subdomains:
        directory_enumeration(active_subdomains, args.dir_wordlist, f"{OUTPUT_DIR}/{output_prefix}_dirs.txt", proxies, args.threads, args.verbose, args.timeout)

    print(END_BANNER)
    logging.info("Hunt completed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Hunt interrupted by user.")