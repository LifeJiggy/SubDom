#!/usr/bin/env python3
"""
Bug Bounty Beast v8.0
Powered by ArkhAngelLifeJiggy
Subdomain + Directory Enumeration with 40+ features & hardening
"""

import argparse
import os
import sys
import time
import random
import signal
import json
import csv
import logging
import hashlib
import socket
import ssl
import string
import re
import tempfile
import traceback
import ipaddress
from datetime import datetime
from typing import List, Set, Dict, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from threading import Lock, Event

import requests
import dns.resolver
  
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

# --- ANSI Color System ---
class C:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

    @staticmethod
    def supports_color():
        if os.name == 'nt':
            return True
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

if not C.supports_color():
    for attr in ['RESET','BOLD','DIM','RED','GREEN','YELLOW','BLUE','MAGENTA','CYAN','WHITE']:
        setattr(C, attr, '')

# --- Global Scan State (Hardening #1: Signal Handling + Clean Shutdown) ---
class ScanState:
    """Thread-safe global scan state with graceful shutdown support."""
    def __init__(self):
        self.shutdown_event = Event()
        self._lock = Lock()
        self._partial_results: Dict[str, Any] = {}
        self._start_time = time.time()

    def request_shutdown(self):
        self.shutdown_event.set()
        print(f"\n{C.YELLOW}[!] Shutdown requested. Finishing current tasks and saving results...{C.RESET}")

    def is_shutdown(self):
        return self.shutdown_event.is_set()

    def save_partial(self, key: str, data):
        with self._lock:
            self._partial_results[key] = data

    def get_partial(self, key: str):
        with self._lock:
            return self._partial_results.get(key)

    def elapsed(self):
        return time.time() - self._start_time

SCAN_STATE = ScanState()

def signal_handler(signum, frame):
    SCAN_STATE.request_shutdown()

# Register signal handlers (Hardening #1)
signal.signal(signal.SIGINT, signal_handler)
if sys.platform != 'win32':
    signal.signal(signal.SIGTERM, signal_handler)

# --- Rate Limiter ---
class RateLimiter:
    """Per-service adaptive rate limiter with backoff on 429/403."""
    def __init__(self):
        self._lock = Lock()
        self._delays: Dict[str, float] = {}
        self._consecutive_fails: Dict[str, int] = {}
        self._backoff_until: Dict[str, float] = {}

    def wait(self, service: str):
        delay = 0
        with self._lock:
            backoff_until = self._backoff_until.get(service, 0)
            if backoff_until > time.time():
                delay = max(delay, backoff_until - time.time())
            delay = max(delay, self._delays.get(service, 0.5))
        if delay > 0:
            time.sleep(delay)

    def record_success(self, service: str):
        with self._lock:
            self._consecutive_fails[service] = 0
            current = self._delays.get(service, 0.5)
            self._delays[service] = max(0.3, current * 0.9)

    def record_failure(self, service: str, status_code: int = 0):
        with self._lock:
            fails = self._consecutive_fails.get(service, 0) + 1
            self._consecutive_fails[service] = fails
            if status_code in (429, 403):
                backoff_seconds = min(300, (2 ** fails) + random.uniform(0, 1))
                self._backoff_until[service] = time.time() + backoff_seconds
                print(f"{C.YELLOW}[!] Rate limited by {service} (HTTP {status_code}). Backing off {backoff_seconds:.1f}s{C.RESET}")
            else:
                current = self._delays.get(service, 0.5)
                self._delays[service] = min(5.0, current * 1.5)

RATE_LIMITER = RateLimiter()

# --- Circuit Breaker (Hardening #5) ---
class CircuitBreaker:
    """Circuit breaker to stop hammering failing targets."""
    def __init__(self, threshold: int = 5, cooldown: int = 60):
        self._lock = Lock()
        self._failures: Dict[str, int] = defaultdict(int)
        self._open_until: Dict[str, float] = {}
        self._threshold = threshold
        self._cooldown = cooldown

    def is_open(self, target: str) -> bool:
        with self._lock:
            open_until = self._open_until.get(target, 0)
            if open_until > time.time():
                return True
            return False

    def record_success(self, target: str):
        with self._lock:
            self._failures[target] = 0
            self._open_until.pop(target, None)

    def record_failure(self, target: str):
        with self._lock:
            self._failures[target] += 1
            if self._failures[target] >= self._threshold:
                self._open_until[target] = time.time() + self._cooldown
                print(f"{C.RED}[!] Circuit breaker tripped for {target}. Pausing for {self._cooldown}s{C.RESET}")

CIRCUIT_BREAKER = CircuitBreaker()

# --- Session Pooling (Hardening #4) ---
_session_pool: Optional[requests.Session] = None

def get_session() -> requests.Session:
    """Get or create a pooled HTTP session."""
    global _session_pool
    if _session_pool is None:
        _session_pool = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=0
        )
        _session_pool.mount('https://', adapter)
        _session_pool.mount('http://', adapter)
    return _session_pool

# --- Exponential Backoff with Jitter (Hardening #10) ---
def backoff_sleep(attempt: int, base: float = 1.0, cap: float = 30.0):
    """Exponential backoff with full jitter."""
    delay = min(cap, base * (2 ** attempt))
    jitter = random.uniform(0, delay)
    time.sleep(jitter)

# --- Atomic Write (Hardening #6) ---
def atomic_write(filepath: str, content: str):
    """Write to temp file then atomically rename to prevent corrupt output."""
    directory = os.path.dirname(filepath) or '.'
    try:
        fd, tmp_path = tempfile.mkstemp(dir=directory, suffix='.tmp')
        with os.fdopen(fd, 'w', encoding='utf-8') as tmp_file:
            tmp_file.write(content)
        if os.name == 'nt':
            if os.path.exists(filepath):
                os.remove(filepath)
        os.rename(tmp_path, filepath)
    except Exception as e:
        print(f"{C.RED}[-] Atomic write failed for {filepath}: {e}{C.RESET}")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

# --- Input Validation (Hardening #9) ---
DOMAIN_REGEX = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
)

def validate_domain(domain: str) -> bool:
    """Validate domain format via regex."""
    return bool(DOMAIN_REGEX.match(domain))

def sanitize_path_component(name: str) -> str:
    """Sanitize a string to be safe for use in file paths."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)

# --- Progress Bar ---
class ProgressBar:
    """Simple progress bar with ETA."""
    def __init__(self, total: int, label: str = ""):
        self.total = max(total, 1)
        self.current = 0
        self.label = label
        self.start_time = time.time()
        self._lock = Lock()

    def update(self, n: int = 1):
        with self._lock:
            self.current += n
            if self.current % max(1, self.total // 20) == 0 or self.current >= self.total:
                self._render()

    def _render(self):
        pct = self.current / self.total
        bar_len = 30
        filled = int(bar_len * pct)
        bar = '█' * filled + '░' * (bar_len - filled)
        elapsed = time.time() - self.start_time
        eta = (elapsed / max(self.current, 1)) * (self.total - self.current) if self.current > 0 else 0
        sys.stdout.write(f"\r{C.CYAN}{self.label}{C.RESET} [{bar}] {self.current}/{self.total} "
                         f"({pct*100:.0f}%) ETA: {eta:.0f}s  ")
        sys.stdout.flush()
        if self.current >= self.total:
            print()

# Banners
START_BANNER = f"""
{C.CYAN}{C.BOLD}=======================================
    Bug Bounty Beast v8.0
    Powered by ArkhAngelLifeJiggy
    40+ Features | 10 Hardening Fixes
    Unleash the Hunt!
======================================={C.RESET}
"""
END_BANNER = f"""
{C.GREEN}{C.BOLD}=======================================
   Hunt Conquered! You're a Bug Bounty Legend!
   Scan completed in {{}} seconds.
======================================={C.RESET}
"""
SUBDOMAIN_BANNER = f"""
{C.CYAN}=======================================
   Subdomain Enumeration
   Sources: DNS, CRT.sh, Wayback, Anubis,
   Hackertarget, GitHub, CT Logs
======================================={C.RESET}
"""
DIR_BANNER = f"""
{C.CYAN}=======================================
   Directory Enumeration & Bruteforcing
   Tools: Built-in HTTP Requests + Baseline
======================================={C.RESET}
"""
BRUTEFORCE_BANNER = f"""
{C.CYAN}=======================================
   Active Subdomain Bruteforce
   Tools: Built-in HTTP Requests
======================================={C.RESET}
"""


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
    "X-Forwarded-For-Original": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
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

# --- Known CNAME takeover targets ---
TAKEOVER_SIGNATURES = {
    "amazonaws.com": ["NoSuchBucket", "No Such Bucket"],
    "herokuapp.com": ["No such app"],
    "github.io": ["There isn't a GitHub Pages site here"],
    "ghost.io": ["The thing you were looking for is no here"],
    "shopify.com": ["Sorry, this shop is currently unavailable"],
    "fastly.net": ["Fastly error: unknown domain"],
    "pantheon.io": ["404 error unknown site"],
    "surge.sh": ["project not found"],
    "bitbucket.io": ["Repository not found"],
    "zendesk.com": ["Help Center Closed"],
    "readme.io": ["Project doesn't exist"],
    "feedpress.me": ["The feed hasn't been found"],
    "helpjuice.com": ["We could not find what you're looking for"],
    "helpscoutdocs.com": ["No settings were found for this company"],
    "cargocollective.com": ["If you're moving your domain away"],
    "statuspage.io": ["Better StatusPage"],
    "uservoice.com": ["This UserVoice subdomain is currently available"],
    "intercom.help": ["This page is reserved for artistic dogs"],
    "landingi.com": ["It looks like you're lost"],
    "netlify.app": ["Not Found - Request ID"],
    "vercel.app": ["The deployment could not be found"],
    "firebaseapp.com": ["Site Not Found"],
    "web.app": ["Site Not Found"],
    "s3.amazonaws.com": ["NoSuchBucket"],
    "cloudfront.net": ["Bad Request"],
    "azurewebsites.net": ["404 Web Site not found"],
    "trafficmanager.net": ["Azure DNS"],
    "blob.core.windows.net": ["Azure Storage"],
    "cloudapp.net": ["Azure Cloud Service"],
}

# --- Tech fingerprint signatures ---
TECH_SIGNATURES = {
    "server": {
        "nginx": re.compile(r'nginx', re.I),
        "Apache": re.compile(r'Apache', re.I),
        "IIS": re.compile(r'Microsoft-IIS', re.I),
        "LiteSpeed": re.compile(r'LiteSpeed', re.I),
        "Caddy": re.compile(r'Caddy', re.I),
        "Cloudflare": re.compile(r'cloudflare', re.I),
    },
    "framework": {
        "React": re.compile(r'react|__NEXT_DATA__|_next/static', re.I),
        "Angular": re.compile(r'ng-version|ng-app|angular', re.I),
        "Vue.js": re.compile(r'vue|__vue__', re.I),
        "Next.js": re.compile(r'__NEXT_DATA__|_next/static', re.I),
        "Nuxt.js": re.compile(r'__NUXT__|_nuxt/', re.I),
        "Django": re.compile(r'csrfmiddlewaretoken|django', re.I),
        "Flask": re.compile(r'werkzeug|flask', re.I),
        "Express": re.compile(r'X-Powered-By.*Express', re.I),
        "Laravel": re.compile(r'laravel|XSRF-TOKEN', re.I),
        "Ruby on Rails": re.compile(r'X-Powered-By.*Phusion Passenger|rails', re.I),
        "Spring": re.compile(r'X-Application-Context|spring', re.I),
        "ASP.NET": re.compile(r'X-Powered-By.*ASP\.NET|__VIEWSTATE', re.I),
    },
    "cms": {
        "WordPress": re.compile(r'wp-content|wp-includes|wordpress', re.I),
        "Drupal": re.compile(r'Drupal\.settings|drupal\.js', re.I),
        "Joomla": re.compile(r'Joomla!|/media/jui/', re.I),
        "Shopify": re.compile(r'cdn\.shopify\.com|Shopify\.theme', re.I),
        "Wix": re.compile(r'wix\.com|X-Wix', re.I),
        "Squarespace": re.compile(r'squarespace', re.I),
        "Ghost": re.compile(r'ghost-', re.I),
        "Hugo": re.compile(r'hugo|Powered by Hugo', re.I),
        "Jekyll": re.compile(r'jekyll|powered by Jekyll', re.I),
    },
    "analytics": {
        "Google Analytics": re.compile(r'google-analytics\.com|gtag|ga\(', re.I),
        "Google Tag Manager": re.compile(r'googletagmanager\.com', re.I),
        "Segment": re.compile(r'segment\.com/analytics', re.I),
        "Mixpanel": re.compile(r'mixpanel\.com', re.I),
        "Hotjar": re.compile(r'hotjar\.com', re.I),
        "Plausible": re.compile(r'plausible\.io', re.I),
    },
}

# --- Common ports for scanning ---
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
             1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9090,
             27017, 50000, 2375, 9200, 9300, 11211, 5601, 10250]

# --- Cloud provider IP ranges for ASN detection ---
CLOUD_RANGES = {
    "AWS": ["52.", "54.", "3.", "18.", "34.", "35.", "44.", "50.", "52.", "99.", "100.", "108.", "143.", "174.", "184.", "204.", "205."],
    "GCP": ["34.", "35.", "130.", "136.", "142.", "146.", "195.", "216."],
    "Azure": ["13.", "20.", "40.", "52.", "64.", "65.", "72.", "104.", "168."],
    "Cloudflare": ["104.", "172.", "173.", "185.", "188.", "190.", "197.", "205.", "216."],
    "Fastly": ["151.", "167.", "199.", "235."],
}

# --- WAF Detection Signatures ---
WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "body": ["cloudflare"]},
    "Akamai": {"headers": ["x-akamai-transformed", "x-akamai-request-id"], "body": ["akamai"]},
    "AWS WAF": {"headers": ["x-amzn-requestid", "x-amzn-trace-id"], "body": ["aws", "amazon"]},
    "Imperva/Incapsula": {"headers": ["x-iinfo", "x-cdn"], "body": ["incapsula", "imperva"]},
    "Sucuri": {"headers": ["x-sucuri-id"], "body": ["sucuri"]},
    "Barracuda": {"headers": [], "body": ["barracuda"]},
    "F5 BIG-IP": {"headers": ["x-cnection", "bigip"], "body": ["big-ip", "bigip"]},
    "ModSecurity": {"headers": [], "body": ["mod_security", "modsecurity"]},
    "FortiWeb": {"headers": [], "body": ["fortiweb"]},
    "Radware": {"headers": ["x-zen"], "body": ["radware"]},
}

# --- Security Headers to Audit ---
SECURITY_HEADERS = {
    "Strict-Transport-Security": {"severity": "HIGH", "desc": "HSTS not set - allows downgrade attacks"},
    "Content-Security-Policy": {"severity": "HIGH", "desc": "CSP not set - XSS risk"},
    "X-Frame-Options": {"severity": "MEDIUM", "desc": "X-Frame-Options missing - clickjacking risk"},
    "X-Content-Type-Options": {"severity": "LOW", "desc": "X-Content-Type-Options missing - MIME sniffing risk"},
    "X-XSS-Protection": {"severity": "LOW", "desc": "X-XSS-Protection missing"},
    "Referrer-Policy": {"severity": "LOW", "desc": "Referrer-Policy missing - info leakage risk"},
    "Permissions-Policy": {"severity": "LOW", "desc": "Permissions-Policy missing"},
    "X-Permitted-Cross-Domain-Policies": {"severity": "LOW", "desc": "Cross-domain policy not restricted"},
    "Cross-Origin-Opener-Policy": {"severity": "LOW", "desc": "COOP not set"},
    "Cross-Origin-Resource-Policy": {"severity": "LOW", "desc": "CORP not set"},
    "Cross-Origin-Embedder-Policy": {"severity": "LOW", "desc": "COEP not set"},
}

# --- API Paths to Probe ---
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v1/health", "/api/v2/health",
    "/graphql", "/graphiql", "/playground", "/_graphql",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/docs", "/redoc",
    "/v1", "/v2", "/v3",
    "/rest", "/rpc", "/service",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
    "/debug", "/trace", "/status", "/info", "/metrics", "/env",
    "/admin", "/administrator", "/manager", "/console",
    "/wp-admin", "/wp-login.php", "/xmlrpc.php",
    "/phpmyadmin", "/adminer", "/db", "/database",
    "/.env", "/.env.bak", "/.env.local", "/.env.production",
    "/config", "/config.json", "/config.yml", "/settings",
    "/backup", "/dump", "/export", "/download",
    "/upload", "/fileupload", "/import",
    "/test", "/testing", "/debug", "/demo",
    "/webhook", "/webhooks", "/callback",
    "/jwt", "/token", "/auth", "/login", "/oauth",
    "/user", "/users", "/profile", "/me", "/account",
    "/search", "/query", "/find",
    "/internal", "/private", "/secret", "/hidden",
    "/health", "/readiness", "/liveness", "/ready",
    "/version", "/build", "/info",
    "/cron", "/jobs", "/tasks", "/scheduler",
    "/email", "/mail", "/send", "/smtp",
    "/payment", "/checkout", "/cart", "/order",
]

# --- Info Disclosure Probe Paths ---
INFO_DISCLOSURE_PATHS = [
    "/.env", "/.env.bak", "/.env.local", "/.env.production", "/.env.staging", "/.env.development",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn/entries", "/.svn/wc.db",
    "/.DS_Store", "/Thumbs.db",
    "/.htaccess", "/.htpasswd",
    "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~",
    "/config.php.bak", "/config.php.old", "/config.php~",
    "/configuration.php.bak", "/configuration.php.old",
    "/web.config", "/crossdomain.xml",
    "/server-status", "/server-info",
    "/trace.axd", "/elmah.axd",
    "/debug/default/view", "/_profiler",
    "/actuator/env", "/actuator/heapdump", "/actuator/configprops",
    "/jolokia", "/jolokia/list",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server.php", "/status.php",
    "/.aws/credentials", "/.aws/config",
    "/id_rsa", "/id_dsa", "/.ssh/authorized_keys",
    "/package.json", "/package-lock.json", "/yarn.lock", "/Gemfile.lock",
    "/composer.json", "/composer.lock",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/Jenkinsfile", "/.travis.yml", ".github/workflows",
    "/dump.sql", "/backup.sql", "/database.sql", "/db.sql",
    "/backup.zip", "/backup.tar.gz", "/backup.tar",
]

# --- Email Extraction Regex ---
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', re.I)



def download_wordlist(url: str, dest: str):
    """Download a wordlist if not present."""
    if not os.path.exists(dest):
        print(f"[*] Downloading wordlist to {dest}")
        try:
            session = get_session()
            response = session.get(url, timeout=15, headers={"User-Agent": random.choice(USER_AGENTS)})
            with open(dest, "wb") as f:
                f.write(response.content)
            print(f"{C.GREEN}[+] Wordlist downloaded: {dest}{C.RESET}")
        except Exception as e:
            print(f"{C.RED}[-] Failed to download wordlist: {e}{C.RESET}")

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

def normalize_target(target: str) -> str:
    """Normalize target to root domain."""
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    # Strip protocol and trailing slashes
    domain = domain.split('/')[0]
    # Strip port
    domain = domain.split(':')[0]
    parts = domain.split('.')
    if len(parts) > 2 and parts[0] in ['www', 'mail', 'api']:
        return '.'.join(parts[1:])
    return domain

# --- Session-based HTTP request with hardened retry (Hardening #2 + #4 + #10) ---
def hardened_request(url: str, proxies: List[str] = None, timeout: int = 10,
                     retries: int = 3, verbose: bool = False, service: str = "default") -> Optional[requests.Response]:
    """Make an HTTP request with session pooling, exponential backoff, SSL resilience, and rate limit awareness."""
    if not url.startswith("http"):
        url = f"https://{url}"

    session = get_session()
    for attempt in range(retries):
        if SCAN_STATE.is_shutdown():
            return None
        RATE_LIMITER.wait(service)
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            proxy = get_random_proxy(proxies) if proxies else None
            proxies_dict = {"http": proxy, "https": proxy} if proxy else None

            response = session.get(url, headers=headers, proxies=proxies_dict,
                                   timeout=timeout, allow_redirects=True,
                                   verify=True)
            if response.status_code == 200:
                RATE_LIMITER.record_success(service)
                CIRCUIT_BREAKER.record_success(url)
                return response
            elif response.status_code in (429, 403):
                RATE_LIMITER.record_failure(service, response.status_code)
                backoff_sleep(attempt, base=3.0, cap=60.0)
            else:
                RATE_LIMITER.record_success(service)
                return response  # Return non-200 responses for analysis
        except ssl.SSLError as e:
            if verbose and attempt == 0:
                print(f"{C.YELLOW}[-] SSL error for {url}: {e}{C.RESET}")
            backoff_sleep(attempt)
        except (requests.ConnectionError, requests.Timeout) as e:
            CIRCUIT_BREAKER.record_failure(url)
            if verbose and attempt == 0:
                print(f"{C.YELLOW}[-] Connection error for {url}: {type(e).__name__}{C.RESET}")
            backoff_sleep(attempt)
        except requests.RequestException as e:
            if verbose and attempt == 0:
                print(f"{C.YELLOW}[-] Request error for {url}: {e}{C.RESET}")
            backoff_sleep(attempt)
        except Exception as e:
            if verbose and attempt == 0:
                print(f"{C.RED}[-] Unexpected error for {url}: {e}{C.RESET}")
            break
    return None

# --- Wildcard DNS Detection ---
def detect_wildcard_dns(target: str, verbose: bool = False) -> Optional[str]:
    """Detect if target uses wildcard DNS by querying a random non-existent subdomain.
    Returns the wildcard IP if detected, None otherwise."""
    random_subs = [
        ''.join(random.choices(string.ascii_lowercase + string.digits, k=16)) for _ in range(3)
    ]
    wildcard_ips = set()
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    resolver.timeout = 5
    resolver.lifetime = 5

    for sub in random_subs:
        domain = f"{sub}.{target}"
        try:
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                wildcard_ips.add(str(rdata))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
            pass
        except Exception:
            pass

    if len(wildcard_ips) >= 2:
        wildcard_ip = list(wildcard_ips)[0]
        if verbose:
            print(f"{C.YELLOW}[!] Wildcard DNS detected for {target} -> {wildcard_ip} (will filter false positives){C.RESET}")
        return wildcard_ip
    return None

# --- IP Resolution & ASN Lookup ---
def resolve_ip_and_asn(subdomain: str, verbose: bool = False) -> Dict[str, str]:
    """Resolve subdomain to IP, identify cloud provider."""
    result = {"ip": "", "cloud": "Unknown"}
    try:
        answers = dns.resolver.resolve(subdomain, 'A')
        ip = str(list(answers)[0])
        result["ip"] = ip
        # Identify cloud provider by IP prefix
        for provider, prefixes in CLOUD_RANGES.items():
            for prefix in prefixes:
                if ip.startswith(prefix):
                    result["cloud"] = provider
                    break
            if result["cloud"] != "Unknown":
                break
        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)
            result["hostname"] = hostname[0]
        except (socket.herror, socket.gaierror):
            pass
    except Exception:
        pass
    return result

# --- Technology Fingerprinting ---
def fingerprint_tech(url: str, proxies: List[str] = None, timeout: int = 8) -> Dict[str, List[str]]:
    """Fingerprint technology stack from HTTP response."""
    tech = {"server": [], "framework": [], "cms": [], "analytics": [], "headers": []}
    response = hardened_request(url, proxies=proxies, timeout=timeout, retries=2, service="fingerprint")
    if response is None:
        return tech

    # Header-based detection
    server = response.headers.get('Server', '')
    if server:
        tech["server"].append(server)
    powered_by = response.headers.get('X-Powered-By', '')
    if powered_by:
        tech["headers"].append(f"X-Powered-By: {powered_by}")

    # Body-based detection
    body = response.text[:50000]  # First 50KB
    for category, signatures in TECH_SIGNATURES.items():
        for name, pattern in signatures.items():
            # Check headers first
            for h_name, h_val in response.headers.items():
                if pattern.search(f"{h_name}: {h_val}"):
                    if name not in tech.get(category, []):
                        tech.setdefault(category, []).append(name)
            # Check body
            if pattern.search(body):
                if name not in tech.get(category, []):
                    tech.setdefault(category, []).append(name)

    return tech

# --- Port Scanning ---
def scan_ports(subdomain: str, ports: List[int] = None, timeout: float = 1.0) -> List[int]:
    """Quick connect-scan on specified ports."""
    if ports is None:
        ports = TOP_PORTS
    open_ports = []
    try:
        ip = socket.gethostbyname(subdomain)
    except socket.gaierror:
        return open_ports

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=min(50, len(ports))) as executor:
        futures = {executor.submit(check_port, p): p for p in ports}
        for future in as_completed(futures):
            if SCAN_STATE.is_shutdown():
                break
            port = future.result()
            if port:
                open_ports.append(port)
    return sorted(open_ports)

# --- DNS Record Expansion ---
def dns_record_expansion(target: str, verbose: bool = False) -> Dict[str, List[str]]:
    """Enumerate MX, TXT, CNAME, NS, SOA, CAA, SRV records."""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'CAA', 'SRV']
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
            if verbose and records[rtype]:
                print(f"{C.GREEN}[+] DNS {rtype}: {', '.join(records[rtype][:5])}{C.RESET}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
            pass
        except Exception:
            pass
    return records

# --- HTTP Method Fingerprinting ---
def http_method_fingerprint(url: str, proxies: List[str] = None, timeout: int = 5) -> Dict[str, int]:
    """Test HTTP methods and return status codes."""
    methods = {}
    session = get_session()
    for method in ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH', 'HEAD']:
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            proxy = get_random_proxy(proxies) if proxies else None
            proxies_dict = {"http": proxy, "https": proxy} if proxy else None
            response = session.request(method, url, headers=headers, proxies=proxies_dict,
                                       timeout=timeout, allow_redirects=False, verify=False)
            methods[method] = response.status_code
        except Exception:
            methods[method] = 0
    return methods

# --- Virtual Host Detection ---
def detect_vhost(subdomain: str, proxies: List[str] = None, timeout: int = 5) -> Dict[str, Any]:
    """Detect if virtual host differs from target (potential vhost takeover)."""
    result = {"vhost_different": False, "title": "", "status": 0, "content_length": 0}
    session = get_session()
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        proxy = get_random_proxy(proxies) if proxies else None
        proxies_dict = {"http": proxy, "https": proxy} if proxy else None
        url = f"https://{subdomain}"
        response = session.get(url, headers=headers, proxies=proxies_dict,
                               timeout=timeout, allow_redirects=True, verify=False)
        result["status"] = response.status_code
        result["content_length"] = len(response.content)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.title and soup.title.string:
            result["title"] = soup.title.string.strip()
        # Check for default/generic content
        generic_titles = ["Default Web Site", "Welcome", "Index of /", "Apache Default", "IIS Default"]
        for gt in generic_titles:
            if gt.lower() in result["title"].lower():
                result["vhost_different"] = True
                break
    except Exception:
        pass
    return result

# --- Subdomain Takeover Check ---
def check_subdomain_takeover(subdomain: str, verbose: bool = False) -> Optional[Dict[str, str]]:
    """Check if subdomain has dangling CNAME pointing to unclaimed service."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        resolver.timeout = 5
        resolver.lifetime = 5

        try:
            cname_answers = resolver.resolve(subdomain, 'CNAME')
            cname_target = str(list(cname_answers)[0]).rstrip('.')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
            return None
        except Exception:
            return None

        # Check if CNAME target matches known takeover signatures
        for service, signatures in TAKEOVER_SIGNATURES.items():
            if service in cname_target:
                # Verify by fetching the page
                response = hardened_request(f"https://{subdomain}", retries=2, timeout=8, service="takeover")
                if response:
                    for sig in signatures:
                        if sig.lower() in response.text.lower():
                            if verbose:
                                print(f"{C.RED}[!] TAKEOVER POSSIBLE: {subdomain} -> {cname_target} ({service}){C.RESET}")
                            return {"subdomain": subdomain, "cname": cname_target, "service": service, "signature": sig}
    except Exception:
        pass
    return None

# --- Scan Comparison/Diff ---
def scan_diff(current_file: str, previous_file: str) -> Dict[str, Set[str]]:
    """Compare current scan results against previous scan."""
    result = {"new": set(), "removed": set(), "common": set()}
    if not os.path.exists(previous_file):
        return result
    with open(current_file, 'r', encoding='utf-8', errors='replace') as f:
        current = {line.strip() for line in f if line.strip()}
    with open(previous_file, 'r', encoding='utf-8', errors='replace') as f:
        previous = {line.strip() for line in f if line.strip()}
    result["new"] = current - previous
    result["removed"] = previous - current
    result["common"] = current & previous
    return result

# --- Scan Checkpoint/Resume ---
def save_checkpoint(target: str, state: Dict[str, Any]):
    """Save scan state to disk for resume capability."""
    checkpoint_path = f"{OUTPUT_DIR}/.{sanitize_path_component(target)}_checkpoint.json"
    state["timestamp"] = datetime.now().isoformat()
    state["elapsed"] = SCAN_STATE.elapsed()
    atomic_write(checkpoint_path, json.dumps(state, indent=2, default=str))

def load_checkpoint(target: str) -> Optional[Dict[str, Any]]:
    """Load previous scan checkpoint."""
    checkpoint_path = f"{OUTPUT_DIR}/.{sanitize_path_component(target)}_checkpoint.json"
    if os.path.exists(checkpoint_path):
        try:
            with open(checkpoint_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return None

# --- Output Formatting ---
def export_json(data: Any, filepath: str):
    """Export data as JSON."""
    atomic_write(filepath, json.dumps(data, indent=2, default=str))

def export_csv(rows: List[Dict], filepath: str):
    """Export data as CSV."""
    if not rows:
        return
    import io
    keys = rows[0].keys()
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=keys)
    writer.writeheader()
    writer.writerows(rows)
    atomic_write(filepath, buf.getvalue())

# --- Recursive Subdomain Enumeration ---
def recursive_subdomain_enum(subdomains: Set[str], wordlist: List[str], verbose: bool,
                             threads: int, depth: int = 1) -> Set[str]:
    """Recursively enumerate subdomains of discovered subdomains."""
    all_subdomains = set(subdomains)
    current_level = set(subdomains)

    for d in range(depth):
        if SCAN_STATE.is_shutdown():
            break
        next_level = set()
        print(f"{C.CYAN}[*] Recursive depth {d+1}: Checking {len(current_level)} subdomains...{C.RESET}")

        def check_recursive_sub(sub):
            if SCAN_STATE.is_shutdown():
                return set()
            found = set()
            for word in wordlist[:50]:  # Limit per subdomain
                candidate = f"{word}.{sub}"
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = ['8.8.8.8']
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    answers = resolver.resolve(candidate, 'A')
                    if answers:
                        found.add(candidate)
                        if verbose:
                            print(f"{C.GREEN}[+] Recursive found: {candidate}{C.RESET}")
                except Exception:
                    pass
            return found

        with ThreadPoolExecutor(max_workers=min(threads, 5)) as executor:
            futures = {executor.submit(check_recursive_sub, sub): sub for sub in current_level}
            for future in as_completed(futures):
                if SCAN_STATE.is_shutdown():
                    break
                result = future.result()
                next_level.update(result - all_subdomains)

        all_subdomains.update(next_level)
        current_level = next_level

    return all_subdomains


# --- Subdomain Permutation Engine ---
def subdomain_permutations(subdomains: Set[str], target: str, verbose: bool = False) -> Set[str]:
    """Generate and DNS-resolve permutations of discovered subdomains.
    Techniques: flip, insert, append, hyphen, number suffix, case variants."""
    permutations = set()
    prefixes = ["dev", "test", "staging", "prod", "api", "internal", "new", "old", "v2", "v3",
                "admin", "app", "web", "mail", "ftp", "ssh", "vpn", "cdn", "static", "media",
                "backup", "db", "sql", "redis", "cache", "auth", "sso", "oauth", "login"]
    suffixes = ["01", "02", "03", "1", "2", "3", "a", "b", "c", "-new", "-old", "-backup",
                "-test", "-dev", "-staging", "-prod", "-live", "-beta", "-alpha"]

    # Extract subdomain prefixes from discovered subs
    known_prefixes = set()
    for sub in subdomains:
        prefix = sub.replace(f".{target}", "").strip()
        if prefix:
            known_prefixes.add(prefix)

    for prefix in known_prefixes:
        # Number suffix permutations
        for s in suffixes[:8]:
            candidate = f"{prefix}{s}.{target}"
            if candidate not in subdomains:
                permutations.add(candidate)
        # Hyphen permutations
        for s in suffixes:
            candidate = f"{prefix}{s}.{target}"
            if candidate not in subdomains:
                permutations.add(candidate)
        # Prefix with common labels
        for p in prefixes[:10]:
            candidate = f"{p}-{prefix}.{target}"
            if candidate not in subdomains:
                permutations.add(candidate)
            candidate = f"{p}{prefix}.{target}"
            if candidate not in subdomains:
                permutations.add(candidate)

    # DNS resolve permutations
    found = set()
    if permutations:
        print(f"{C.CYAN}[*] Testing {len(permutations)} subdomain permutations...{C.RESET}")
        progress = ProgressBar(len(permutations), f"{C.CYAN}Permute{C.RESET}")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        resolver.timeout = 3
        resolver.lifetime = 3

        def resolve_perm(domain):
            if SCAN_STATE.is_shutdown():
                return None
            try:
                resolver.resolve(domain, 'A')
                return domain
            except Exception:
                progress.update()
                return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(resolve_perm, p): p for p in permutations}
            for future in as_completed(futures):
                if SCAN_STATE.is_shutdown():
                    break
                result = future.result()
                if result:
                    found.add(result)
                    if verbose:
                        print(f"{C.GREEN}[+] Permutation found: {result}{C.RESET}")
                progress.update()

    print(f"{C.GREEN}[+] Permutation engine found {len(found)} new subdomains{C.RESET}")
    return found
# --- SSL/TLS Certificate Intelligence ---
def ssl_cert_intel(target: str, verbose: bool = False) -> Dict[str, Any]:
    """Extract SSL/TLS certificate details: SANs, issuer, expiry, protocol, key size."""
    result = {"sans": [], "issuer": "", "subject": "", "not_before": "", "not_after": "",
              "serial": "", "version": "", "key_size": 0, "protocol": "", "expired": False}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result["protocol"] = ssock.version()
                result["cipher"] = f"{cipher[0]} {cipher[1]}bit" if cipher else ""

                # Extract SANs
                for entry in cert.get("subjectAltName", ()):
                    if entry[0] == "DNS":
                        san = entry[1].strip("*.")
                        result["sans"].append(entry[1])

                # Extract issuer
                issuer_parts = []
                for rdn in cert.get("issuer", ()):
                    for attr in rdn:
                        if attr[0] in ("organizationName", "commonName"):
                            issuer_parts.append(attr[1])
                result["issuer"] = " / ".join(issuer_parts)

                # Extract subject
                subject_parts = []
                for rdn in cert.get("subject", ()):
                    for attr in rdn:
                        if attr[0] == "commonName":
                            subject_parts.append(attr[1])
                result["subject"] = " / ".join(subject_parts)

                # Dates
                result["not_before"] = cert.get("notBefore", "")
                result["not_after"] = cert.get("notAfter", "")
                result["serial"] = cert.get("serialNumber", "")

                # Check expiry
                from datetime import datetime
                try:
                    expiry = datetime.strptime(result["not_after"], "%b %d %H:%M:%S %Y %Z")
                    result["expired"] = expiry < datetime.now()
                except Exception:
                    pass

                # Key size from public key
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import serialization
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        x509_cert = x509.load_der_x509_certificate(der_cert)
                        result["key_size"] = x509_cert.public_key().key_size
                except Exception:
                    pass

                if verbose:
                    print(f"{C.GREEN}[+] SSL for {target}: {result['protocol']} | {result['issuer'][:50]} | "
                          f"SANs: {len(result['sans'])} | Key: {result['key_size']}bit{C.RESET}")
    except Exception as e:
        if verbose:
            print(f"{C.YELLOW}[-] SSL error for {target}: {e}{C.RESET}")
    return result

# --- Extract subdomains from SAN lists (CT mining) ---
def cert_san_mining(target: str, verbose: bool = False) -> Set[str]:
    """Extract unique subdomains from SSL certificate SAN lists of discovered hosts."""
    subs = set()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                for entry in cert.get("subjectAltName", ()):
                    if entry[0] == "DNS":
                        san = entry[1].lower()
                        if san.endswith(f".{target}") and not san.startswith("*"):
                            subs.add(san)
                            if verbose:
                                print(f"{C.GREEN}[+] SAN found: {san}{C.RESET}")
    except Exception:
        pass
    return subs


# --- WAF Detection & Fingerprinting ---
def detect_waf(url: str, proxies: List[str] = None, verbose: bool = False) -> Optional[Dict[str, str]]:
    """Identify WAF/CDN by analyzing response headers and body."""
    session = get_session()
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        proxy = get_random_proxy(proxies) if proxies else None
        proxies_dict = {"http": proxy, "https": proxy} if proxy else None
        response = session.get(url, headers=headers, proxies=proxies_dict,
                               timeout=10, allow_redirects=True, verify=False)
        headers_dict = {k.lower(): v for k, v in response.headers.items()}
        body = response.text[:10000].lower()

        for waf_name, sigs in WAF_SIGNATURES.items():
            # Check headers
            for header in sigs.get("headers", []):
                if header.lower() in headers_dict:
                    if verbose:
                        print(f"{C.GREEN}[+] WAF detected: {waf_name} (header: {header}){C.RESET}")
                    return {"name": waf_name, "evidence": f"header:{header}"}
            # Check body
            for pattern in sigs.get("body", []):
                if pattern.lower() in body:
                    if verbose:
                        print(f"{C.GREEN}[+] WAF detected: {waf_name} (body match){C.RESET}")
                    return {"name": waf_name, "evidence": f"body:{pattern}"}
    except Exception:
        pass
    if verbose:
        print(f"{C.YELLOW}[-] No WAF detected for {url}{C.RESET}")
    return None

# --- Auto-bypass detected WAF ---
def waf_bypass_probe(url: str, waf_name: str, proxies: List[str] = None) -> Dict[str, Any]:
    """When a WAF is detected, try known bypass techniques and report which work."""
    results = {"waf": waf_name, "bypasses_tried": 0, "bypasses_worked": 0, "techniques": []}
    techniques = [
        {"name": "Case variation", "headers": {}, "path_mod": lambda p: p.upper()},
        {"name": "URL encoding", "headers": {}, "path_mod": lambda p: p.replace("/", "%2f")},
        {"name": "Double encoding", "headers": {}, "path_mod": lambda p: p.replace("/", "%252f")},
        {"name": "HTTP/1.0", "headers": {}, "path_mod": None, "version": (1, 0)},
        {"name": "Null byte", "headers": {}, "path_mod": lambda p: p + "%00"},
        {"name": "X-Original-URL", "headers": {"X-Original-URL": "/admin"}, "path_mod": None},
        {"name": "X-Rewrite-URL", "headers": {"X-Rewrite-URL": "/admin"}, "path_mod": None},
    ]
    for tech in techniques:
        try:
            session = get_session()
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            headers.update(tech["headers"])
            test_url = url
            if tech["path_mod"]:
                parsed = urlparse(url)
                test_url = f"{parsed.scheme}://{parsed.netloc}{tech['path_mod'](parsed.path)}"
            response = session.get(test_url, headers=headers, timeout=8, verify=False)
            results["bypasses_tried"] += 1
            if response.status_code == 200:
                results["bypasses_worked"] += 1
                results["techniques"].append({"name": tech["name"], "status": response.status_code})
        except Exception:
            continue
    return results


# --- robots.txt / sitemap.xml Crawler ---
def crawl_robots_sitemap(url: str, proxies: List[str] = None, verbose: bool = False) -> List[str]:
    """Parse robots.txt and sitemap.xml for hidden paths and directories."""
    paths = set()
    session = get_session()
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    proxy = get_random_proxy(proxies) if proxies else None
    proxies_dict = {"http": proxy, "https": proxy} if proxy else None
    base = f"https://{url}" if not url.startswith("http") else url.rstrip("/")

    # Crawl robots.txt
    try:
        response = session.get(f"{base}/robots.txt", headers=headers, proxies=proxies_dict,
                               timeout=8, verify=False)
        if response.status_code == 200:
            for line in response.text.split('\n'):
                line = line.strip()
                if line.lower().startswith(('allow:', 'disallow:')):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/' and '*' not in path:
                        paths.add(path)
                        if verbose:
                            print(f"{C.GREEN}[+] robots.txt: {path}{C.RESET}")
                elif line.lower().startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    if sitemap_url:
                        paths.add(f"__sitemap__:{sitemap_url}")
    except Exception:
        pass

    # Crawl sitemaps
    sitemap_urls = {p.split(':', 1)[1] for p in paths if p.startswith("__sitemap__:")}
    paths = {p for p in paths if not p.startswith("__sitemap__:")}
    sitemap_urls.add(f"{base}/sitemap.xml")

    for surl in sitemap_urls:
        try:
            response = session.get(surl, headers=headers, proxies=proxies_dict,
                                   timeout=10, verify=False)
            if response.status_code == 200:
                for match in re.finditer(r'<loc>(.*?)</loc>', response.text, re.I):
                    loc = match.group(1)
                    parsed = urlparse(loc)
                    if parsed.path and parsed.path != '/':
                        paths.add(parsed.path)
                        if verbose:
                            print(f"{C.GREEN}[+] sitemap: {parsed.path}{C.RESET}")
        except Exception:
            continue

    if paths:
        print(f"{C.GREEN}[+] Found {len(paths)} paths from robots.txt/sitemaps{C.RESET}")
    return sorted(paths)



# --- JavaScript Endpoint & Secret Extraction ---
JS_SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[:=]\s*["\']([^"\']{8,})["\']', "API Key/Secret"),
    (r'(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']([A-Z0-9]{20})["\']', "AWS Access Key"),
    (r'(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS Secret Key"),
    (r'(?:token|bearer|auth[_-]?token|jwt)\s*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']', "Auth Token"),
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']', "Password"),
    (r'["\']([A-Za-z0-9]{32,})["\']', "Possible Hash/Token"),
    (r'(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{36,}', "GitHub PAT"),
    (r'sk-[A-Za-z0-9]{20,}', "OpenAI API Key"),
    (r'xox[bpsa]-[A-Za-z0-9\-]+', "Slack Token"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?:mongodb|postgres|mysql|redis)://[^\s"\']+', "Database Connection String"),
]

def extract_js_secrets(url: str, proxies: List[str] = None, verbose: bool = False) -> List[Dict[str, str]]:
    """Fetch JavaScript files from a page and extract endpoints, secrets, and API keys."""
    findings = []
    session = get_session()
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    proxy = get_random_proxy(proxies) if proxies else None
    proxies_dict = {"http": proxy, "https": proxy} if proxy else None

    try:
        response = session.get(url, headers=headers, proxies=proxies_dict,
                               timeout=10, verify=False)
        if response.status_code != 200:
            return findings

        # Find JS file URLs
        js_urls = set()
        # From script tags
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', response.text, re.I):
            js_url = match.group(1)
            if js_url.startswith("//"):
                js_url = "https:" + js_url
            elif js_url.startswith("/"):
                parsed = urlparse(url)
                js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
            js_urls.add(js_url)

        # Check current page for secrets too
        for pattern, name in JS_SECRET_PATTERNS:
            for match in re.finditer(pattern, response.text):
                secret = match.group(1) if match.lastindex else match.group(0)
                # Truncate long secrets
                display = secret[:30] + "..." if len(secret) > 30 else secret
                findings.append({"type": name, "value": display, "source": url})
                if verbose:
                    print(f"{C.RED}[!] Secret found: {name} in {url}: {display}{C.RESET}")

        # Fetch and scan each JS file
        for js_url in list(js_urls)[:20]:  # Limit to 20 JS files
            if SCAN_STATE.is_shutdown():
                break
            try:
                js_resp = session.get(js_url, headers=headers, proxies=proxies_dict,
                                      timeout=8, verify=False)
                if js_resp.status_code == 200:
                    js_text = js_resp.text[:500000]  # First 500KB
                    # Extract API endpoints
                    for match in re.finditer(r'["\']/(api|v[1-9]|graphql|rest|service)/[^"\']{3,}["\']', js_text):
                        endpoint = match.group(0).strip('"\'')
                        findings.append({"type": "API Endpoint", "value": endpoint, "source": js_url})
                        if verbose:
                            print(f"{C.GREEN}[+] API endpoint: {endpoint} in {js_url}{C.RESET}")

                    # Extract secrets
                    for pattern, name in JS_SECRET_PATTERNS:
                        for match in re.finditer(pattern, js_text):
                            secret = match.group(1) if match.lastindex else match.group(0)
                            display = secret[:30] + "..." if len(secret) > 30 else secret
                            findings.append({"type": name, "value": display, "source": js_url})
                            if verbose:
                                print(f"{C.RED}[!] Secret: {name} in {js_url}: {display}{C.RESET}")
            except Exception:
                continue

    except Exception:
        pass
    return findings



# --- HTTP Security Header Audit ---
def audit_security_headers(url: str, proxies: List[str] = None, verbose: bool = False) -> Dict[str, Any]:
    """Audit HTTP security headers and report missing/insecure configurations."""
    result = {"url": url, "missing": [], "present": [], "insecure": [], "score": 0}
    session = get_session()
    try:
        headers_req = {"User-Agent": random.choice(USER_AGENTS)}
        proxy = get_random_proxy(proxies) if proxies else None
        proxies_dict = {"http": proxy, "https": proxy} if proxy else None
        response = session.get(url, headers=headers_req, proxies=proxies_dict,
                               timeout=8, verify=False, allow_redirects=True)
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        total = len(SECURITY_HEADERS)
        score = total
        for header, info in SECURITY_HEADERS.items():
            header_lower = header.lower()
            if header_lower in resp_headers:
                result["present"].append(header)
                # Check for insecure values
                val = resp_headers[header_lower]
                if header == "Strict-Transport-Security":
                    if "max-age=0" in val:
                        result["insecure"].append(f"{header}: max-age=0 (HSTS disabled)")
                        score -= 1
                elif header == "X-Frame-Options":
                    if val.upper() not in ("DENY", "SAMEORIGIN"):
                        result["insecure"].append(f"{header}: {val} (should be DENY/SAMEORIGIN)")
                        score -= 1
                elif header == "Content-Security-Policy":
                    if "unsafe-inline" in val or "unsafe-eval" in val:
                        result["insecure"].append(f"{header}: contains unsafe-inline/unsafe-eval")
            else:
                result["missing"].append(header)
                if info["severity"] in ("HIGH", "MEDIUM"):
                    score -= 1
                if verbose:
                    print(f"{C.YELLOW}[!] Missing {info['severity']} header: {header} - {info['desc']}{C.RESET}")

        result["score"] = max(0, round((score / total) * 100))
        if verbose:
            print(f"{C.GREEN}[+] Security header score: {result['score']}% "
                  f"({len(result['present'])} present, {len(result['missing'])} missing){C.RESET}")
    except Exception:
        pass
    return result


# --- CORS Misconfiguration Detection ---
def detect_cors_misconfig(url: str, proxies: List[str] = None, verbose: bool = False) -> Dict[str, Any]:
    """Test for CORS misconfigurations: wildcard origin, null origin, reflect origin."""
    result = {"url": url, "misconfigs": []}
    session = get_session()
    test_origins = [
        ("https://evil.com", "External Origin"),
        ("null", "Null Origin"),
        (f"https://{urlparse(url).netloc}.evil.com", "Subdomain of Target"),
        ("https://attacker.com", "Attacker Origin"),
    ]

    for origin, desc in test_origins:
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS), "Origin": origin}
            proxy = get_random_proxy(proxies) if proxies else None
            proxies_dict = {"http": proxy, "https": proxy} if proxy else None
            response = session.get(url, headers=headers, proxies=proxies_dict,
                                   timeout=8, verify=False)
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                result["misconfigs"].append({"type": "Wildcard Origin", "acao": acao})
                if verbose:
                    print(f"{C.RED}[!] CORS wildcard: {url} allows all origins{C.RESET}")
            elif acao == origin and origin not in (f"https://{urlparse(url).netloc}",):
                result["misconfigs"].append({"type": desc, "acao": acao, "credentials": acac})
                if verbose:
                    print(f"{C.RED}[!] CORS reflect: {url} reflects {desc} origin ({origin}){C.RESET}")
        except Exception:
            continue
    return result



# --- API Path Probing ---
def probe_api_paths(url: str, proxies: List[str] = None, verbose: bool = False) -> List[Dict[str, Any]]:
    """Probe common API paths and report interesting findings."""
    findings = []
    session = get_session()
    headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "application/json, text/html, */*"}
    proxy = get_random_proxy(proxies) if proxies else None
    proxies_dict = {"http": proxy, "https": proxy} if proxy else None
    base = f"https://{url}" if not url.startswith("http") else url.rstrip("/")

    def check_path(path):
        if SCAN_STATE.is_shutdown():
            return None
        try:
            full_url = f"{base}{path}"
            response = session.get(full_url, headers=headers, proxies=proxies_dict,
                                   timeout=6, verify=False, allow_redirects=False)
            if response.status_code not in (404, 405, 501, 502, 503):
                is_interesting = (
                    response.status_code in (200, 301, 302, 307, 401, 403) or
                    "json" in response.headers.get("content-type", "").lower() or
                    response.status_code < 500
                )
                if is_interesting:
                    return {"path": path, "status": response.status_code,
                            "size": len(response.content),
                            "content_type": response.headers.get("content-type", "")[:50]}
        except Exception:
            pass
        return None

    progress = ProgressBar(len(API_PATHS), f"{C.CYAN}API Probe{C.RESET}")
    with ThreadPoolExecutor(max_workers=min(15, len(API_PATHS))) as executor:
        futures = {executor.submit(check_path, p): p for p in API_PATHS}
        for future in as_completed(futures):
            if SCAN_STATE.is_shutdown():
                break
            result = future.result()
            progress.update()
            if result:
                findings.append(result)
                if verbose:
                    print(f"{C.GREEN}[+] API: {result['path']} -> HTTP {result['status']}{C.RESET}")

    if findings:
        print(f"{C.GREEN}[+] Found {len(findings)} accessible API paths{C.RESET}")
    return findings


# --- Info Disclosure Probes ---
def probe_info_disclosure(url: str, proxies: List[str] = None, verbose: bool = False) -> List[Dict[str, Any]]:
    """Probe for sensitive files and info disclosure endpoints."""
    findings = []
    session = get_session()
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    proxy = get_random_proxy(proxies) if proxies else None
    proxies_dict = {"http": proxy, "https": proxy} if proxy else None
    base = f"https://{url}" if not url.startswith("http") else url.rstrip("/")

    def check_path(path):
        if SCAN_STATE.is_shutdown():
            return None
        try:
            full_url = f"{base}{path}"
            response = session.get(full_url, headers=headers, proxies=proxies_dict,
                                   timeout=6, verify=False, allow_redirects=False)
            if response.status_code == 200 and len(response.content) > 50:
                body = response.text[:500].lower()
                # Confirm it's real content, not a generic page
                false_positives = ['404', 'not found', 'page not found', 'does not exist']
                if not any(fp in body for fp in false_positives):
                    return {"path": path, "status": response.status_code,
                            "size": len(response.content), "snippet": response.text[:200]}
        except Exception:
            pass
        return None

    progress = ProgressBar(len(INFO_DISCLOSURE_PATHS), f"{C.CYAN}InfoLeak{C.RESET}")
    with ThreadPoolExecutor(max_workers=min(15, len(INFO_DISCLOSURE_PATHS))) as executor:
        futures = {executor.submit(check_path, p): p for p in INFO_DISCLOSURE_PATHS}
        for future in as_completed(futures):
            if SCAN_STATE.is_shutdown():
                break
            result = future.result()
            progress.update()
            if result:
                findings.append(result)
                print(f"{C.RED}[!] Info disclosure: {result['path']} (HTTP {result['status']}, {result['size']} bytes){C.RESET}")

    if findings:
        print(f"{C.RED}[!] Found {len(findings)} potential info disclosure endpoints{C.RESET}")
    return findings



# --- Email & Contact Extraction ---
def extract_emails(url: str, proxies: List[str] = None, verbose: bool = False) -> Set[str]:
    """Scrape email addresses from live web pages."""
    emails = set()
    social_links = []
    session = get_session()
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    proxy = get_random_proxy(proxies) if proxies else None
    proxies_dict = {"http": proxy, "https": proxy} if proxy else None
    base = f"https://{url}" if not url.startswith("http") else url

    try:
        response = session.get(base, headers=headers, proxies=proxies_dict,
                               timeout=10, verify=False)
        if response.status_code == 200:
            # Extract emails
            for match in EMAIL_REGEX.finditer(response.text):
                email = match.group(0).lower()
                # Filter out common false positives
                if not email.endswith(('.png', '.jpg', '.gif', '.svg', '.css', '.js')):
                    emails.add(email)
                    if verbose:
                        print(f"{C.GREEN}[+] Email found: {email}{C.RESET}")

            # Extract social links
            social_patterns = [
                (r'linkedin\.com/in/([a-zA-Z0-9\-_]+)', "LinkedIn"),
                (r'github\.com/([a-zA-Z0-9\-_]+)', "GitHub"),
                (r'twitter\.com/([a-zA-Z0-9_]+)', "Twitter/X"),
            ]
            for pattern, platform in social_patterns:
                for match in re.finditer(pattern, response.text):
                    social_links.append({"platform": platform, "handle": match.group(1)})
    except Exception:
        pass

    if emails:
        print(f"{C.GREEN}[+] Extracted {len(emails)} email addresses{C.RESET}")
    if social_links:
        print(f"{C.GREEN}[+] Found {len(social_links)} social links{C.RESET}")
    return emails


# --- Wayback Machine URL Extraction ---
def wayback_url_extraction(target: str, verbose: bool = False) -> Set[str]:
    """Extract historical URLs from Wayback Machine for endpoint discovery."""
    urls = set()
    api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit=5000"
    for attempt in range(3):
        if SCAN_STATE.is_shutdown():
            break
        try:
            session = get_session()
            RATE_LIMITER.wait("wayback_urls")
            response = session.get(api_url, timeout=30, headers={"User-Agent": random.choice(USER_AGENTS)})
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    for entry in data[1:]:
                        url = entry[0] if isinstance(entry, list) else entry
                        parsed = urlparse(url)
                        if parsed.path and parsed.path != '/':
                            urls.add(parsed.path)
                            if verbose and len(urls) <= 50:
                                print(f"{C.GREEN}[+] Wayback URL: {parsed.path}{C.RESET}")
                RATE_LIMITER.record_success("wayback_urls")
                break
        except Exception:
            RATE_LIMITER.record_failure("wayback_urls")
            if attempt < 2:
                backoff_sleep(attempt)
    print(f"{C.GREEN}[+] Extracted {len(urls)} unique URLs from Wayback Machine{C.RESET}")
    return urls


# --- DNS Zone Transfer Testing ---
def test_zone_transfer(target: str, verbose: bool = False) -> Dict[str, Any]:
    """Test all discovered NS servers for DNS zone transfer (AXFR) vulnerability."""
    result = {"target": target, "vulnerable": False, "nameservers": [], "zone_records": []}
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        resolver.timeout = 5
        resolver.lifetime = 5

        # Get NS records
        try:
            ns_records = resolver.resolve(target, 'NS')
            result["nameservers"] = [str(rdata).rstrip('.') for rdata in ns_records]
        except Exception:
            return result

        for ns in result["nameservers"]:
            if SCAN_STATE.is_shutdown():
                break
            try:
                # Attempt zone transfer
                ns_resolver = dns.resolver.Resolver()
                ns_resolver.nameservers = [ns]
                ns_resolver.timeout = 10
                ns_resolver.lifetime = 10

                # Try AXFR
                import dns.query
                import dns.zone
                response = dns.query.xfr(ns, target, lifetime=10)
                zone = dns.zone.from_xfr(response)
                names = list(zone.nodes.keys())
                result["vulnerable"] = True
                result["zone_records"] = [f"{name}.{target}" for name in names[:100]]
                print(f"{C.RED}[!] ZONE TRANSFER VULNERABLE on {ns}! {len(names)} records leaked{C.RESET}")
                break
            except dns.exception.FormError:
                if verbose:
                    print(f"{C.GREEN}[+] {ns}: Zone transfer refused (secure){C.RESET}")
            except Exception as e:
                if verbose:
                    print(f"{C.YELLOW}[-] {ns}: {e}{C.RESET}")
    except Exception as e:
        if verbose:
            print(f"{C.YELLOW}[-] Zone transfer test error: {e}{C.RESET}")
    return result



# --- Technology Version Extraction ---
def extract_tech_versions(url: str, proxies: List[str] = None, verbose: bool = False) -> List[Dict[str, str]]:
    """Extract specific technology versions from headers and body for CVE matching."""
    versions = []
    session = get_session()
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        proxy = get_random_proxy(proxies) if proxies else None
        proxies_dict = {"http": proxy, "https": proxy} if proxy else None
        response = session.get(url, headers=headers, proxies=proxies_dict,
                               timeout=8, verify=False)

        # Header-based version extraction
        header_patterns = [
            ("Server", r'([\w\-]+)/(\d+[\d.]+)', "Server"),
            ("X-Powered-By", r'([\w\-]+)/(\d+[\d.]+)', "Framework"),
            ("X-AspNet-Version", r'([\d.]+)', "ASP.NET"),
            ("X-Generator", r'([\w\-]+)/?(\d+[\d.]*)', "CMS"),
        ]
        for header, pattern, category in header_patterns:
            val = response.headers.get(header, "")
            match = re.search(pattern, val)
            if match:
                tech = match.group(1)
                ver = match.group(2) if match.lastindex >= 2 else ""
                versions.append({"tech": tech, "version": ver, "source": f"header:{header}", "category": category})
                if verbose:
                    print(f"{C.GREEN}[+] Version: {tech} {ver} (from {header}){C.RESET}")

        # Body-based version patterns
        body_patterns = [
            (r'nginx[/ ](\d+\.\d+\.\d+)', "nginx", "Web Server"),
            (r'Apache/(\d+\.\d+\.\d+)', "Apache", "Web Server"),
            (r'Microsoft-IIS/(\d+\.\d+)', "IIS", "Web Server"),
            (r'PHP/(\d+\.\d+\.\d+)', "PHP", "Language"),
            (r'X-Powered-By.*Express', "Express", "Framework"),
            (r'wp-content/themes/([a-z0-9\-]+)', None, "WordPress Theme"),
            (r'wp-includes/js/jquery/jquery\.(\d+\.\d+\.\d+)', "jQuery", "Library"),
            (r'react@(\d+\.\d+\.\d+)', "React", "Library"),
            (r'vue@(\d+\.\d+\.\d+)', "Vue.js", "Library"),
            (r'angular[/.-](\d+[\d.]*)', "Angular", "Framework"),
            (r'bootstrap@(\d+\.\d+\.\d+)', "Bootstrap", "CSS Framework"),
        ]
        for pattern, tech_name, category in body_patterns:
            match = re.search(pattern, response.text[:100000], re.I)
            if match:
                tech = tech_name or match.group(1)
                ver = match.group(1) if tech_name and match.lastindex >= 1 else ""
                versions.append({"tech": tech, "version": ver, "source": "body", "category": category})
                if verbose:
                    print(f"{C.GREEN}[+] Version: {tech} {ver} ({category}){C.RESET}")
    except Exception:
        pass
    return versions


# --- Netblock/CIDR Discovery ---
def discover_netblocks(target: str, verbose: bool = False) -> Set[str]:
    """Discover IP ranges (CIDR) associated with the target via DNS and WHOIS-like queries."""
    cidrs = set()
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    resolver.timeout = 5
    resolver.lifetime = 5

    # Resolve all known subdomains to IPs
    try:
        # Get A records
        for rtype in ['A', 'AAAA']:
            try:
                answers = resolver.resolve(target, rtype)
                for rdata in answers:
                    ip = str(rdata)
                    # Calculate /24 network
                    parts = ip.split('.')
                    if len(parts) == 4:
                        cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                        cidrs.add(cidr)
                        if verbose:
                            print(f"{C.GREEN}[+] Netblock: {cidr} (from {ip}){C.RESET}")
            except Exception:
                pass
    except Exception:
        pass

    # Try to discover via MX records
    try:
        mx_records = resolver.resolve(target, 'MX')
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            try:
                mx_ips = resolver.resolve(mx_host, 'A')
                for ip in mx_ips:
                    parts = str(ip).split('.')
                    if len(parts) == 4:
                        cidrs.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
            except Exception:
                pass
    except Exception:
        pass

    # Try NS records
    try:
        ns_records = resolver.resolve(target, 'NS')
        for ns in ns_records:
            ns_host = str(ns).rstrip('.')
            try:
                ns_ips = resolver.resolve(ns_host, 'A')
                for ip in ns_ips:
                    parts = str(ip).split('.')
                    if len(parts) == 4:
                        cidrs.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
            except Exception:
                pass
    except Exception:
        pass

    print(f"{C.GREEN}[+] Discovered {len(cidrs)} netblocks{C.RESET}")
    return cidrs


# --- Cloud Storage Enumeration ---
def enumerate_cloud_storage(target: str, verbose: bool = False) -> List[Dict[str, str]]:
    """Check for public AWS S3, Azure Blob, and GCP GCS buckets."""
    findings = []
    session = get_session()
    headers = {"User-Agent": random.choice(USER_AGENTS)}

    # AWS S3 bucket patterns
    s3_patterns = [
        f"https://{target}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{target}",
        f"https://s3-ap-southeast-1.amazonaws.com/{target}",
        f"https://s3-us-west-2.amazonaws.com/{target}",
    ]

    # GCP GCS patterns
    gcs_patterns = [
        f"https://storage.googleapis.com/{target}",
        f"https://storage.googleapis.com/{target}-backup",
    ]

    # Azure Blob patterns
    azure_patterns = [
        f"https://{target}.blob.core.windows.net",
        f"https://{target}-backup.blob.core.windows.net",
    ]

    all_patterns = [("AWS S3", p) for p in s3_patterns] + \
                   [("GCP GCS", p) for p in gcs_patterns] + \
                   [("Azure Blob", p) for p in azure_patterns]

    for cloud, url in all_patterns:
        if SCAN_STATE.is_shutdown():
            break
        try:
            response = session.get(url, headers=headers, timeout=8, verify=False)
            if response.status_code == 200:
                # Confirm it's real data, not a generic error
                if any(keyword in response.text.lower() for keyword in ['<contents>', '<key>', 'listing', 'bucket']):
                    findings.append({"cloud": cloud, "url": url, "status": response.status_code})
                    print(f"{C.RED}[!] Public {cloud} bucket: {url}{C.RESET}")
            elif response.status_code == 403:
                # 403 means bucket exists but is private — still interesting
                if verbose:
                    print(f"{C.YELLOW}[+] {cloud} bucket exists (private): {url}{C.RESET}")
        except Exception:
            continue

    if findings:
        print(f"{C.RED}[!] Found {len(findings)} public cloud storage buckets!{C.RESET}")
    return findings


# --- Markdown Report Generator ---
def generate_report(target: str, results: Dict[str, Any], output_dir: str) -> str:
    """Generate a comprehensive Markdown report from all scan results."""
    lines = [
        f"# Bug Bounty Beast Scan Report",
        f"",
        f"**Target:** `{target}`",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Duration:** {SCAN_STATE.elapsed():.1f}s",
        f"",
        f"---",
        f"",
    ]

    # Summary
    lines.append("## Summary")
    lines.append("")
    if "subdomains" in results:
        lines.append(f"- **Total Subdomains:** {len(results['subdomains'])}")
    if "active" in results:
        lines.append(f"- **Active Hosts:** {len(results['active'])}")
    if "wildcard_ip" in results and results["wildcard_ip"]:
        lines.append(f"- **Wildcard DNS:** `{results['wildcard_ip']}`")
    lines.append("")

    # Subdomains
    if "subdomains" in results and results["subdomains"]:
        lines.append("## Subdomains")
        lines.append("")
        for sub in sorted(results["subdomains"]):
            lines.append(f"- `{sub}`")
        lines.append("")

    # Active hosts
    if "active" in results and results["active"]:
        lines.append("## Active Hosts")
        lines.append("")
        for sub in sorted(results["active"]):
            lines.append(f"- `{sub}`")
        lines.append("")

    # WAF
    if "waf" in results and results["waf"]:
        lines.append("## WAF Detection")
        lines.append("")
        for item in results["waf"]:
            lines.append(f"- `{item.get('subdomain', '')}`: **{item.get('waf', 'Unknown')}**")
        lines.append("")

    # Security Headers
    if "security_headers" in results and results["security_headers"]:
        lines.append("## Security Headers")
        lines.append("")
        for item in results["security_headers"]:
            score = item.get("score", 0)
            emoji = "+" if score >= 80 else "!" if score >= 50 else "-"
            lines.append(f"- `{item.get('url', '')}`: Score **{score}%**")
            for m in item.get("missing", []):
                lines.append(f"  - Missing: `{m}`")
        lines.append("")

    # CORS
    if "cors" in results and results["cors"]:
        lines.append("## CORS Issues")
        lines.append("")
        for item in results["cors"]:
            if item.get("misconfigs"):
                lines.append(f"- `{item['url']}`:")
                for mc in item["misconfigs"]:
                    lines.append(f"  - **{mc['type']}**: `{mc.get('acao', '')}`")
        lines.append("")

    # Info Disclosure
    if "info_disclosure" in results and results["info_disclosure"]:
        lines.append("## Information Disclosure")
        lines.append("")
        for item in results["info_disclosure"]:
            lines.append(f"- `{item['path']}`: HTTP {item['status']} ({item['size']} bytes)")
        lines.append("")

    # API Paths
    if "api_paths" in results and results["api_paths"]:
        lines.append("## API Endpoints")
        lines.append("")
        for item in results["api_paths"]:
            lines.append(f"- `{item['path']}`: HTTP {item['status']}")
        lines.append("")

    # Emails
    if "emails" in results and results["emails"]:
        lines.append("## Email Addresses")
        lines.append("")
        for email in sorted(results["emails"]):
            lines.append(f"- `{email}`")
        lines.append("")

    # Zone Transfer
    if "zone_transfer" in results and results["zone_transfer"].get("vulnerable"):
        lines.append("## DNS Zone Transfer Vulnerability")
        lines.append("")
        lines.append(f"**CRITICAL:** Zone transfer is possible!")
        for record in results["zone_transfer"].get("zone_records", [])[:50]:
            lines.append(f"- `{record}`")
        lines.append("")

    # Port Scan
    if "ports" in results and results["ports"]:
        lines.append("## Port Scan Results")
        lines.append("")
        for sub, ports in sorted(results["ports"].items()):
            if ports:
                lines.append(f"- `{sub}`: {', '.join(map(str, ports))}")
        lines.append("")

    # Technology
    if "tech" in results and results["tech"]:
        lines.append("## Technology Stack")
        lines.append("")
        for sub, tech in sorted(results["tech"].items()):
            all_tech = []
            for cat, items in tech.items():
                if items:
                    all_tech.extend(items)
            if all_tech:
                lines.append(f"- `{sub}`: {', '.join(all_tech)}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by Bug Bounty Beast*")

    report = "\n".join(lines)
    report_path = os.path.join(output_dir, f"{sanitize_path_component(target)}_report.md")
    atomic_write(report_path, report)
    print(f"{C.GREEN}[+] Report saved to {report_path}{C.RESET}")
    return report_path



# --- Custom Header Injection ---
def load_custom_headers(filepath: str) -> Dict[str, str]:
    """Load custom headers from a file (one header per line, format: Name: Value)."""
    headers = {}
    if not os.path.exists(filepath):
        return headers
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if ':' in line and line and not line.startswith('#'):
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
    print(f"{C.GREEN}[+] Loaded {len(headers)} custom headers from {filepath}{C.RESET}")
    return headers


# --- Cookie & Sensitive Header Leak Detection ---
def detect_header_leaks(url: str, proxies: List[str] = None, verbose: bool = False) -> List[Dict[str, str]]:
    """Check for sensitive information leaked in HTTP response headers."""
    leaks = []
    sensitive_headers = [
        "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "x-generator", "x-drupal-cache", "x-debug-token",
        "x-ratelimit-limit", "x-ratelimit-remaining",
        "x-backend-server", "x-upstream-server", "x-real-ip",
        "x-varnish", "x-cache", "x-cached-by",
        "set-cookie",
    ]
    session = get_session()
    try:
        headers_req = {"User-Agent": random.choice(USER_AGENTS)}
        proxy = get_random_proxy(proxies) if proxies else None
        proxies_dict = {"http": proxy, "https": proxy} if proxy else None
        response = session.get(url, headers=headers_req, proxies=proxies_dict,
                               timeout=8, verify=False)
        for header in sensitive_headers:
            val = response.headers.get(header, "")
            if val:
                leaks.append({"header": header, "value": val[:100]})
                if verbose:
                    print(f"{C.YELLOW}[!] Header leak: {header}: {val[:80]}{C.RESET}")
        # Check for server version disclosure
        server = response.headers.get("Server", "")
        if server and re.search(r'\d+\.\d+', server):
            leaks.append({"header": "Server", "value": server})
            if verbose:
                print(f"{C.YELLOW}[!] Server version disclosed: {server}{C.RESET}")
    except Exception:
        pass
    return leaks


# --- HTTP/2 & HTTP/3 Protocol Detection ---
def detect_protocols(url: str, verbose: bool = False) -> Dict[str, Any]:
    """Detect HTTP/2 and HTTP/3 support on the target."""
    result = {"http1": True, "http2": False, "alpn": [], "tls_version": ""}
    session = get_session()
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        # Test HTTP/2
        response = session.get(url, headers=headers, timeout=8, verify=False)
        if hasattr(response, 'raw') and response.raw.version == 20:
            result["http2"] = True
        # Check via httpx-style header
        if response.headers.get("x-http2") or "h2" in response.headers.get("alt-svc", ""):
            result["http2"] = True
    except Exception:
        pass

    # Check ALPN via SSL
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection((urlparse(url).hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=urlparse(url).hostname) as ssock:
                result["alpn"] = [ssock.selected_alpn_protocol()] if ssock.selected_alpn_protocol() else []
                result["tls_version"] = ssock.version()
                if "h2" in result["alpn"]:
                    result["http2"] = True
                if verbose:
                    print(f"{C.GREEN}[+] Protocols for {url}: HTTP/2={result['http2']}, "
                          f"ALPN={result['alpn']}, TLS={result['tls_version']}{C.RESET}")
    except Exception:
        pass

    # HTTP/3 detection via Alt-Svc header
    try:
        response = session.get(url, headers=headers, timeout=5, verify=False)
        alt_svc = response.headers.get("Alt-Svc", "")
        if "h3" in alt_svc.lower():
            result["http3"] = True
            if verbose:
                print(f"{C.GREEN}[+] HTTP/3 supported on {url}{C.RESET}")
    except Exception:
        pass

    return result


# --- Concurrent Multi-Phase Scanner ---
def concurrent_scan_phases(target: str, proxies: List[str], threads: int,
                           verbose: bool, timeout: int) -> Dict[str, Any]:
    """Run multiple scan phases concurrently for speed (passive + fingerprint + ports + security)."""
    results = {}
    print(f"{C.CYAN}[*] Running concurrent scan phases...{C.RESET}")

    # Phase 1: Passive subdomain enum
    def phase_passive():
        return subdomain_enumeration_passive(target, f"{OUTPUT_DIR}/{target}_passive.txt", verbose, threads)

    # Phase 2: SSL cert intel
    def phase_ssl():
        return ssl_cert_intel(target, verbose)

    # Phase 3: DNS records
    def phase_dns():
        return dns_record_expansion(target, verbose)

    # Phase 4: robots.txt
    def phase_robots():
        return crawl_robots_sitemap(f"https://{target}", proxies, verbose)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(phase_passive): "passive",
            executor.submit(phase_ssl): "ssl",
            executor.submit(phase_dns): "dns",
            executor.submit(phase_robots): "robots",
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                print(f"{C.RED}[-] Phase {name} failed: {e}{C.RESET}")
                results[name] = {} if name != "passive" else set()

    # Phase 2: Use results from phase 1 for active scanning
    if "passive" in results and results["passive"]:
        active_subs = results["passive"]
        # Phase 5: Probe active
        def phase_probe():
            return filter_active_subdomains(active_subs, f"{OUTPUT_DIR}/{target}_active_200.txt",
                                            proxies, threads, verbose, timeout)

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            futures[executor.submit(phase_probe)] = "active"

            # Phase 6: WAF detection on target
            def phase_waf():
                return detect_waf(f"https://{target}", proxies, verbose)
            futures[executor.submit(phase_waf)] = "waf"

            # Phase 7: Zone transfer test
            def phase_zonetransfer():
                return test_zone_transfer(target, verbose)
            futures[executor.submit(phase_zonetransfer)] = "zone_transfer"

            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    print(f"{C.RED}[-] Phase {name} failed: {e}{C.RESET}")

        # Phase 8: Security headers on active hosts
        if "active" in results and results["active"]:
            security_results = []
            for sub in list(results["active"])[:20]:  # Limit to 20 hosts
                try:
                    audit = audit_security_headers(f"https://{sub}", proxies, verbose)
                    if audit:
                        security_results.append(audit)
                except Exception:
                    continue
            results["security_headers"] = security_results

    print(f"{C.GREEN}[+] Concurrent scan phases completed{C.RESET}")
    return results


def run_dns_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via DNS lookups with public resolvers."""
    subdomains = set()
    wordlist = load_wordlist(DEFAULT_SUBDOMAIN_WORDLIST, SUBDOMAIN_WORDS)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']
    resolver.timeout = 5
    resolver.lifetime = 5
    for sub in wordlist[:150]:
        if SCAN_STATE.is_shutdown():
            break
        domain = f"{sub}.{target}"
        try:
            answers = resolver.resolve(domain, 'A')
            if answers:
                subdomains.add(domain)
                if verbose:
                    print(f"{C.GREEN}[+] DNS found: {domain}{C.RESET}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
            continue
        except Exception:
            continue
    RATE_LIMITER.record_success("dns")
    return subdomains

def run_crtsh_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via crt.sh with proper dedup (Hardening #7)."""
    subdomains = set()
    url = f"https://crt.sh/?q=%.{target}&output=json"
    for attempt in range(3):
        if SCAN_STATE.is_shutdown():
            break
        try:
            session = get_session()
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            RATE_LIMITER.wait("crtsh")
            response = session.get(url, headers=headers, timeout=20)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "").strip()
                    # Handle multi-line name_value entries (the source of the dedup bug in working.txt)
                    for sub in name.split('\n'):
                        sub = sub.strip()
                        if sub.endswith(f".{target}") and not sub.startswith("*"):
                            subdomains.add(sub)
                            if verbose:
                                print(f"{C.GREEN}[+] CRT.sh found: {sub}{C.RESET}")
                RATE_LIMITER.record_success("crtsh")
                break
            elif response.status_code in (429, 403):
                RATE_LIMITER.record_failure("crtsh", response.status_code)
                backoff_sleep(attempt, base=5.0)
            else:
                break
        except Exception as e:
            print(f"{C.YELLOW}[-] CRT.sh error (attempt {attempt + 1}/3): {e}{C.RESET}")
            RATE_LIMITER.record_failure("crtsh")
            if attempt < 2:
                backoff_sleep(attempt, base=3.0)
    return subdomains

def run_wayback_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via Wayback Machine with retries."""
    subdomains = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original"
    for attempt in range(3):
        if SCAN_STATE.is_shutdown():
            break
        try:
            session = get_session()
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            RATE_LIMITER.wait("wayback")
            response = session.get(url, headers=headers, timeout=25)
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    for entry in data[1:]:
                        try:
                            parsed = urlparse(entry[0])
                            if parsed.netloc and parsed.netloc.endswith(f".{target}"):
                                subdomains.add(parsed.netloc)
                                if verbose:
                                    print(f"{C.GREEN}[+] Wayback found: {parsed.netloc}{C.RESET}")
                        except Exception:
                            continue
                RATE_LIMITER.record_success("wayback")
                break
            elif response.status_code in (429, 403):
                RATE_LIMITER.record_failure("wayback", response.status_code)
                backoff_sleep(attempt, base=5.0)
        except Exception as e:
            RATE_LIMITER.record_failure("wayback")
            if attempt < 2:
                backoff_sleep(attempt, base=3.0)
    return subdomains

# --- Anubis Passive Source ---
def run_anubis_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via Anubis-Subfinder API."""
    subdomains = set()
    url = f"https://jldc.me/anubis/subdomains/{target}"
    for attempt in range(3):
        if SCAN_STATE.is_shutdown():
            break
        try:
            session = get_session()
            RATE_LIMITER.wait("anubis")
            response = session.get(url, timeout=15, headers={"User-Agent": random.choice(USER_AGENTS)})
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for sub in data:
                        if isinstance(sub, str) and sub.endswith(f".{target}"):
                            subdomains.add(sub)
                            if verbose:
                                print(f"{C.GREEN}[+] Anubis found: {sub}{C.RESET}")
                RATE_LIMITER.record_success("anubis")
                break
        except Exception as e:
            RATE_LIMITER.record_failure("anubis")
            if attempt < 2:
                backoff_sleep(attempt)
    return subdomains

# --- Hackertarget Passive Source ---
def run_hackertarget_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via Hackertarget API."""
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={target}"
    for attempt in range(3):
        if SCAN_STATE.is_shutdown():
            break
        try:
            session = get_session()
            RATE_LIMITER.wait("hackertarget")
            response = session.get(url, timeout=15, headers={"User-Agent": random.choice(USER_AGENTS)})
            if response.status_code == 200:
                for line in response.text.strip().split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip()
                        if sub.endswith(f".{target}") or sub == target:
                            subdomains.add(sub)
                            if verbose:
                                print(f"{C.GREEN}[+] Hackertarget found: {sub}{C.RESET}")
                RATE_LIMITER.record_success("hackertarget")
                break
        except Exception as e:
            RATE_LIMITER.record_failure("hackertarget")
            if attempt < 2:
                backoff_sleep(attempt)
    return subdomains

# --- Certspotter CT Source ---
def run_certspotter_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via Certspotter Certificate Transparency."""
    subdomains = set()
    url = f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names"
    for attempt in range(3):
        if SCAN_STATE.is_shutdown():
            break
        try:
            session = get_session()
            RATE_LIMITER.wait("certspotter")
            response = session.get(url, timeout=15, headers={"User-Agent": random.choice(USER_AGENTS)})
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    for dns_name in cert.get("dns_names", []):
                        if dns_name.endswith(f".{target}") and not dns_name.startswith("*"):
                            subdomains.add(dns_name)
                            if verbose:
                                print(f"{C.GREEN}[+] Certspotter found: {dns_name}{C.RESET}")
                RATE_LIMITER.record_success("certspotter")
                break
        except Exception:
            RATE_LIMITER.record_failure("certspotter")
            if attempt < 2:
                backoff_sleep(attempt)
    return subdomains

# --- Facebook CT Source ---
def run_fbct_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via Facebook CT API."""
    subdomains = set()
    url = f"https://graph.facebook.com/certificates?query={{\"domain\":\"{target}\"}}&fields=name_value&limit=1000"
    for attempt in range(2):
        if SCAN_STATE.is_shutdown():
            break
        try:
            session = get_session()
            RATE_LIMITER.wait("fbct")
            response = session.get(url, timeout=15, headers={"User-Agent": random.choice(USER_AGENTS)})
            if response.status_code == 200:
                data = response.json()
                for entry in data.get("data", []):
                    for name in entry.get("name_value", "").split('\n'):
                        name = name.strip()
                        if name.endswith(f".{target}") and not name.startswith("*"):
                            subdomains.add(name)
                            if verbose:
                                print(f"{C.GREEN}[+] FB CT found: {name}{C.RESET}")
                RATE_LIMITER.record_success("fbct")
                break
        except Exception:
            RATE_LIMITER.record_failure("fbct")
            if attempt < 2:
                backoff_sleep(attempt)
    return subdomains

# --- GitHub Subdomain Leak Search ---
def run_github_enum(target: str, verbose: bool) -> Set[str]:
    """Search GitHub for leaked subdomain patterns."""
    subdomains = set()
    # Search for domain patterns in code
    queries = [f'"{target}"', f'site:{target}']
    pattern = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+' + re.escape(target), re.I)

    for query in queries:
        if SCAN_STATE.is_shutdown():
            break
        try:
            url = f"https://api.github.com/search/code?q={query}&per_page=100"
            session = get_session()
            RATE_LIMITER.wait("github")
            headers = {"User-Agent": "Mozilla/5.0 (compatible; SubdomBot/7.0)", "Accept": "application/vnd.github.v3+json"}
            response = session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("items", []):
                    text = item.get("text_matches", [])
                    for match in text:
                        fragment = match.get("fragment", "")
                        found = pattern.findall(fragment)
                        for sub in found:
                            sub = sub.strip().lower()
                            if sub.endswith(f".{target}") and sub != target:
                                subdomains.add(sub)
                                if verbose:
                                    print(f"{C.GREEN}[+] GitHub found: {sub}{C.RESET}")
                RATE_LIMITER.record_success("github")
            elif response.status_code == 403:
                RATE_LIMITER.record_failure("github", 403)
                if verbose:
                    print(f"{C.YELLOW}[-] GitHub API rate limited. Skipping...{C.RESET}")
                break
        except Exception:
            RATE_LIMITER.record_failure("github")
    return subdomains

def run_bruteforce_enum(target: str, wordlist: List[str], verbose: bool, threads: int,
                         wildcard_ip: Optional[str] = None) -> Set[str]:
    """Bruteforce subdomains with HTTP checks, wildcard filtering, and progress bar."""
    subdomains = set()
    progress = ProgressBar(len(wordlist), f"{C.CYAN}Bruteforcing{C.RESET}")

    def check_sub(sub):
        if SCAN_STATE.is_shutdown():
            return None
        domain = f"{sub}.{target}"
        # Skip if this resolves to wildcard IP
        if wildcard_ip:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ['8.8.8.8']
                resolver.timeout = 3
                resolver.lifetime = 3
                answers = resolver.resolve(domain, 'A')
                for rdata in answers:
                    if str(rdata) == wildcard_ip:
                        progress.update()
                        return None
            except Exception:
                progress.update()
                return None

        response = hardened_request(domain, retries=2, timeout=5, service="bruteforce")
        progress.update()
        if response and response.status_code == 200:
            if verbose:
                print(f"{C.GREEN}[+] Active Found: {domain}{C.RESET}")
            return domain
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_sub, sub): sub for sub in wordlist}
        for future in as_completed(futures):
            if SCAN_STATE.is_shutdown():
                break
            result = future.result()
            if result:
                subdomains.add(result)
    return subdomains


def subdomain_enumeration_passive(target: str, output_file: str, verbose: bool, threads: int) -> Set[str]:
    """Passive subdomain enumeration with all sources and proper dedup (Hardening #7)."""
    print(SUBDOMAIN_BANNER)
    subdomains = set()
    tools = [run_dns_enum, run_crtsh_enum, run_wayback_enum, run_anubis_enum,
             run_hackertarget_enum, run_certspotter_enum, run_fbct_enum]

    passive_threads = min(threads, len(tools))
    with ThreadPoolExecutor(max_workers=passive_threads) as executor:
        futures = {executor.submit(tool, target, verbose): tool for tool in tools}
        for future in as_completed(futures):
            if SCAN_STATE.is_shutdown():
                break
            try:
                result = future.result()
                new_count = len(result - subdomains)
                subdomains.update(result)
                tool_name = futures[future].__name__
                if verbose:
                    print(f"{C.BLUE}[*] {tool_name} contributed {new_count} new subdomains{C.RESET}")
            except Exception as e:
                print(f"{C.RED}[-] Error in {futures[future].__name__}: {e}{C.RESET}")

    # GitHub search (run separately to avoid API rate limits)
    if not SCAN_STATE.is_shutdown():
        github_subs = run_github_enum(target, verbose)
        subdomains.update(github_subs)

    # Atomic write (Hardening #6)
    atomic_write(output_file, "\n".join(sorted(subdomains)))
    logging.info(f"Passive subdomains saved: {len(subdomains)}")
    print(f"{C.GREEN}[+] Passive: Found {len(subdomains)} unique subdomains{C.RESET}")
    SCAN_STATE.save_partial("passive", subdomains)
    return subdomains


def subdomain_enumeration_active(target: str, wordlist: str, output_file: str, verbose: bool,
                                  threads: int, wildcard_ip: Optional[str] = None) -> Set[str]:
    """Active subdomain enumeration with deduplication and wildcard filtering."""
    print(BRUTEFORCE_BANNER)
    wordlist_data = load_wordlist(wordlist, SUBDOMAIN_WORDS)
    subdomains = run_bruteforce_enum(target, wordlist_data, verbose, threads, wildcard_ip)

    atomic_write(output_file, "\n".join(sorted(subdomains)))
    logging.info(f"Active subdomains saved: {len(subdomains)}")
    print(f"{C.GREEN}[+] Active: Found {len(subdomains)} unique subdomains{C.RESET}")
    SCAN_STATE.save_partial("active", subdomains)
    return subdomains


def filter_active_subdomains(subdomains: Set[str], output_file: str, proxies: List[str],
                              threads: int, verbose: bool, timeout: int) -> Set[str]:
    """Filter active subdomains with HTTP 200, using session pooling."""
    active_subdomains = set()
    progress = ProgressBar(len(subdomains), f"{C.CYAN}Probing{C.RESET}")

    def validate_subdomain(sub):
        if SCAN_STATE.is_shutdown():
            return None
        url = f"https://{sub}"
        response = hardened_request(url, proxies=proxies, verbose=False, timeout=timeout, retries=2, service="probe")
        progress.update()
        if response and response.status_code == 200:
            return sub
        # Try HTTP if HTTPS fails
        url = f"http://{sub}"
        response = hardened_request(url, proxies=proxies, verbose=False, timeout=timeout, retries=1, service="probe")
        if response and response.status_code == 200:
            return sub
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(validate_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            if SCAN_STATE.is_shutdown():
                break
            result = future.result()
            if result:
                active_subdomains.add(result)

    atomic_write(output_file, "\n".join(sorted(active_subdomains)))
    logging.info(f"Active subdomains (HTTP 200): {len(active_subdomains)}")
    print(f"{C.GREEN}[+] Filtered: {len(active_subdomains)} active subdomains (HTTP 200){C.RESET}")
    SCAN_STATE.save_partial("active_200", active_subdomains)
    return active_subdomains

def run_dir_bruteforce(subdomain: str, wordlist: List[str], proxies: List[str], threads: int, timeout: int) -> Set[str]:
    """Bruteforce directories with hardened HTTP requests, baseline checks, and progress bar."""
    dirs = set()
    baseline_len = None
    baseline_body = ""

    # Try up to 2 random paths to establish a baseline
    for _ in range(2):
        random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        baseline_url = f"https://{subdomain}/{random_path}"
        try:
            response = hardened_request(baseline_url, proxies=proxies, timeout=timeout,
                                        retries=1, service="dirbrute")
            if response and response.status_code == 200:
                baseline_len = len(response.content)
                baseline_body = response.text[:2000].lower()
                break
        except Exception:
            continue

    if baseline_len is None:
        print(f"{C.YELLOW}[!] Could not establish baseline for {subdomain} — using redirect-only mode{C.RESET}")

    progress = ProgressBar(len(wordlist), f"{C.CYAN}DirBrute:{subdomain[:30]}{C.RESET}")

    def check_dir(dir_path):
        if SCAN_STATE.is_shutdown():
            return None
        try:
            url = f"https://{subdomain}/{dir_path}"
            response = hardened_request(url, proxies=proxies, timeout=timeout,
                                        retries=1, service="dirbrute")
            progress.update()
            if response and response.status_code == 200:
                current_len = len(response.content)
                # If baseline exists, compare lengths
                if baseline_len is not None and current_len == baseline_len:
                    return None
                # If no baseline, check body for common 404 patterns to reduce false positives
                if baseline_len is None:
                    body_lower = response.text[:2000].lower()
                    false_positive_hints = ['not found', '404', 'page not found', 'does not exist',
                                            'no page', 'nothing here', 'oops']
                    if any(hint in body_lower for hint in false_positive_hints):
                        return None
                return url
            elif response and response.status_code in (301, 302, 303, 307, 308):
                return url
        except Exception:
            progress.update()
            return None
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_dir, dw): dw for dw in wordlist}
        for future in as_completed(futures):
            if SCAN_STATE.is_shutdown():
                break
            result = future.result()
            if result:
                dirs.add(result)

    return dirs


# --- Directory Enumeration ---
def directory_enumeration(subdomains: Set[str], wordlist: str, output_file: str, proxies: List[str], threads: int, verbose: bool, timeout: int):
    """Directory enumeration with deduplication, progress bars, and atomic output."""
    print(DIR_BANNER)
    results = {}
    wordlist_data = load_wordlist(wordlist, DIR_WORDS)

    def enumerate_subdomain(subdomain):
        if SCAN_STATE.is_shutdown():
            return subdomain, []
        dirs = run_dir_bruteforce(subdomain, wordlist_data, proxies, threads, timeout)
        if verbose and dirs:
            print(f"\n{C.GREEN}[+] Directories Found on: https://{subdomain}{C.RESET}")
            for dir_url in sorted(dirs):
                print(f"  {C.CYAN}-{C.RESET} {dir_url}")
        return subdomain, sorted(dirs)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(enumerate_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            if SCAN_STATE.is_shutdown():
                break
            try:
                sub, dirs_list = future.result()
                results[sub] = dirs_list
            except Exception as e:
                print(f"{C.RED}[-] Error in directory enumeration: {e}{C.RESET}")

    # Atomic write (Hardening #6)
    output_lines = []
    for sub, dirs_list in results.items():
        if dirs_list:
            output_lines.append(f"{sub}:")
            for dir_url in dirs_list:
                output_lines.append(f"  {dir_url}")
    atomic_write(output_file, "\n".join(output_lines))

    logging.info(f"Directory enumeration completed for {len(results)} subdomains")
    print(f"{C.GREEN}[+] Directory results saved to {output_file}{C.RESET}")


# --- Screenshot Capture (lazy playwright import) ---
def capture_screenshots(subdomains: Set[str], output_dir: str, verbose: bool = False):
    """Capture screenshots of live subdomains using playwright (graceful fallback)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(f"{C.YELLOW}[!] Screenshots require playwright. Install: pip install playwright && playwright install chromium{C.RESET}")
        return

    screenshot_dir = os.path.join(output_dir, "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)

    print(f"{C.CYAN}[*] Capturing screenshots of {len(subdomains)} subdomains...{C.RESET}")
    progress = ProgressBar(len(subdomains), f"{C.CYAN}Screenshot{C.RESET}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=True,
            user_agent=random.choice(USER_AGENTS)
        )

        for sub in sorted(subdomains):
            if SCAN_STATE.is_shutdown():
                break
            try:
                page = context.new_page()
                url = f"https://{sub}"
                page.goto(url, timeout=15000, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)  # Let page render
                filename = sanitize_path_component(sub) + ".png"
                filepath = os.path.join(screenshot_dir, filename)
                page.screenshot(path=filepath, full_page=False)
                page.close()
                if verbose:
                    print(f"{C.GREEN}[+] Screenshot: {sub} -> {filepath}{C.RESET}")
            except Exception as e:
                if verbose:
                    print(f"{C.YELLOW}[-] Screenshot failed for {sub}: {e}{C.RESET}")
            progress.update()

        browser.close()

    print(f"{C.GREEN}[+] Screenshots saved to {screenshot_dir}{C.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description=f"{C.CYAN}Bug Bounty Beast v8.0 - Elite Hunting Tool{C.RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{C.CYAN}Examples:
  python Subdom.py -d example.com --all --verbose
  python Subdom.py -d example.com --passive --threads 20
  python Subdom.py -d example.com --scan-ports --fingerprint
  python Subdom.py --batch targets.txt --all --json
{C.RESET}"""
    )

    # Core arguments
    parser.add_argument("-d", "--domain", help="The target domain (e.g., example.com)")
    parser.add_argument("--batch", help="File of multiple target domains")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")

    # Scan modes
    parser.add_argument("--passive", action="store_true", help="Run passive subdomain enumeration only")
    parser.add_argument("--active", action="store_true", help="Run active subdomain enumeration only")
    parser.add_argument("--probe", action="store_true", help="Probe for active subdomains only")
    parser.add_argument("--dir", action="store_true", help="Run directory enumeration only")
    parser.add_argument("--all", action="store_true", help="Run all steps")

    # File options
    parser.add_argument("--sub-wordlist", default=DEFAULT_SUBDOMAIN_WORDLIST, help="Subdomain wordlist path")
    parser.add_argument("--dir-wordlist", default=DEFAULT_DIR_WORDLIST, help="Directory wordlist path")
    parser.add_argument("--proxies", default=PROXY_LIST, help="Proxy list file")
    parser.add_argument("--output", default=None, help="Custom output file prefix")

    # Feature flags
    parser.add_argument("--fingerprint", action="store_true", help="Enable technology fingerprinting")
    parser.add_argument("--resolve", action="store_true", help="Enable IP resolution & ASN lookup")
    parser.add_argument("--scan-ports", action="store_true", help="Enable port scanning on live hosts")
    parser.add_argument("--dns-records", action="store_true", help="Enumerate full DNS records")
    parser.add_argument("--methods", action="store_true", help="HTTP method fingerprinting")
    parser.add_argument("--vhost", action="store_true", help="Virtual host detection")
    parser.add_argument("--takeover", action="store_true", help="Subdomain takeover checks")
    parser.add_argument("--recursive", action="store_true", help="Recursive subdomain enumeration")
    parser.add_argument("--recursive-depth", type=int, default=1, help="Recursive depth (default: 1)")
    parser.add_argument("--diff", help="Compare against previous scan file")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")

    # Output options
    parser.add_argument("--json", action="store_true", help="Export results as JSON")
    parser.add_argument("--csv", action="store_true", help="Export results as CSV")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")

    # Validation
    parser.add_argument("--validate", action="store_true", help="Validate input only, don't scan")
    parser.add_argument("--screenshots", action="store_true", help="Capture screenshots of live subdomains (requires playwright)")

    # New recon features
    parser.add_argument("--permute", action="store_true", help="Run subdomain permutation engine")
    parser.add_argument("--ssl-intel", action="store_true", help="SSL/TLS certificate intelligence")
    parser.add_argument("--waf-detect", action="store_true", help="WAF detection & fingerprinting")
    parser.add_argument("--robots", action="store_true", help="Crawl robots.txt & sitemaps")
    parser.add_argument("--js-secrets", action="store_true", help="JavaScript endpoint & secret extraction")
    parser.add_argument("--security-audit", action="store_true", help="HTTP security header audit + CORS check")
    parser.add_argument("--api-probe", action="store_true", help="API path probing")
    parser.add_argument("--info-leak", action="store_true", help="Information disclosure probes")
    parser.add_argument("--emails", action="store_true", help="Email & contact extraction")
    parser.add_argument("--wayback-urls", action="store_true", help="Wayback Machine URL extraction")
    parser.add_argument("--zone-transfer", action="store_true", help="DNS zone transfer testing")
    parser.add_argument("--tech-versions", action="store_true", help="Technology version extraction")
    parser.add_argument("--netblocks", action="store_true", help="Discover IP netblocks")
    parser.add_argument("--cloud-buckets", action="store_true", help="Cloud storage enumeration")
    parser.add_argument("--report", action="store_true", help="Generate Markdown scan report")
    parser.add_argument("--custom-headers", default=None, help="Custom headers file (one per line: Name: Value)")
    parser.add_argument("--header-leaks", action="store_true", help="Detect sensitive header leaks")
    parser.add_argument("--protocols", action="store_true", help="Detect HTTP/2 & HTTP/3 support")
    parser.add_argument("--concurrent", action="store_true", help="Run all scan phases concurrently")
    parser.add_argument("--full-recon", action="store_true", help="Run ALL recon features at once")

    args = parser.parse_args()

    # Validate that at least one target is specified
    if not args.domain and not args.batch:
        parser.error("Either -d/--domain or --batch is required")

    print(START_BANNER)
    logging.info("Hunt started")

    # --- Batch Mode ---
    targets = []
    if args.batch:
        if not os.path.exists(args.batch):
            print(f"{C.RED}[-] Batch file not found: {args.batch}{C.RESET}")
            return
        with open(args.batch, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"{C.BLUE}[*] Loaded {len(targets)} targets from {args.batch}{C.RESET}")
    else:
        targets = [args.domain]

    # Process each target
    for target_raw in targets:
        target = normalize_target(target_raw)
        if not target:
            print(f"{C.RED}[-] Invalid target: {target_raw}. Skipping.{C.RESET}")
            continue

        # Hardening #9: Input Validation
        if not validate_domain(target):
            print(f"{C.RED}[-] Invalid domain format: {target}. Skipping.{C.RESET}")
            logging.error(f"Invalid domain format: {target}")
            continue

        print(f"\n{C.BOLD}{C.CYAN}{'='*50}{C.RESET}")
        print(f"{C.BOLD}  Targeting: {target}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}{'='*50}{C.RESET}\n")

        if args.validate:
            print(f"{C.GREEN}[+] Domain {target} is valid.{C.RESET}")
            continue

        proxies = load_proxies(args.proxies)
        output_prefix = args.output if args.output else target
        run_all = args.all or not any([args.passive, args.active, args.probe, args.dir])

        # Auto-download wordlists if not present
        if not os.path.exists(args.sub_wordlist):
            download_wordlist("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
                              args.sub_wordlist)
        if not os.path.exists(args.dir_wordlist):
            download_wordlist("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
                              args.dir_wordlist)

        # --- Wildcard DNS Detection ---
        wildcard_ip = detect_wildcard_dns(target, args.verbose)
        if wildcard_ip:
            print(f"{C.YELLOW}[!] Wildcard IP: {wildcard_ip} — will be filtered from results{C.RESET}")

        # --- Resume from checkpoint ---
        if args.resume:
            checkpoint = load_checkpoint(target)
            if checkpoint:
                print(f"{C.BLUE}[*] Resuming from checkpoint ({checkpoint.get('timestamp', 'unknown')}){C.RESET}")

        # Validate target
        if args.verbose:
            print(f"{C.BLUE}[*] Validating target: {target}{C.RESET}")
        if not check_http_200(target, proxies, verbose=args.verbose, timeout=args.timeout):
            print(f"{C.YELLOW}[!] Target {target} not reachable (HTTP 200) after retries. Continuing anyway...{C.RESET}")
            logging.error(f"Target {target} unreachable")

        subdomains = set()
        active_subdomains = set()
        resolve_results = {}
        port_results = {}
        tech_results = {}

        # Step 1: Subdomain Enumeration
        if run_all or args.passive:
            subdomains.update(subdomain_enumeration_passive(target, f"{OUTPUT_DIR}/{output_prefix}_passive.txt", args.verbose, args.threads))
        if run_all or args.active:
            subdomains.update(subdomain_enumeration_active(target, args.sub_wordlist, f"{OUTPUT_DIR}/{output_prefix}_active.txt", args.verbose, args.threads, wildcard_ip))

        # --- Recursive Enumeration ---
        if args.recursive and subdomains:
            print(f"{C.CYAN}[*] Starting recursive enumeration (depth={args.recursive_depth})...{C.RESET}")
            wordlist_data = load_wordlist(args.sub_wordlist, SUBDOMAIN_WORDS)
            recursive_subs = recursive_subdomain_enum(subdomains, wordlist_data, args.verbose, args.threads, args.recursive_depth)
            new_subs = recursive_subs - subdomains
            subdomains.update(recursive_subs)
            print(f"{C.GREEN}[+] Recursive enumeration found {len(new_subs)} additional subdomains{C.RESET}")

        # Save all subdomains
        if subdomains:
            atomic_write(f"{OUTPUT_DIR}/{TARGET_FILE}", "\n".join(sorted(subdomains)))

        # --- Scan Diff ---
        if args.diff and os.path.exists(args.diff):
            diff_result = scan_diff(f"{OUTPUT_DIR}/{output_prefix}_passive.txt", args.diff)
            if diff_result["new"]:
                print(f"\n{C.GREEN}[+] NEW subdomains ({len(diff_result['new'])}):{C.RESET}")
                for sub in sorted(diff_result["new"]):
                    print(f"  {C.GREEN}+ {sub}{C.RESET}")
            if diff_result["removed"]:
                print(f"\n{C.YELLOW}[-] REMOVED subdomains ({len(diff_result['removed'])}):{C.RESET}")
                for sub in sorted(diff_result["removed"]):
                    print(f"  {C.YELLOW}- {sub}{C.RESET}")
            print(f"\n{C.BLUE}[*] Common: {len(diff_result['common'])} subdomains{C.RESET}")

        # Step 2: Filter Active Subdomains
        if (run_all or args.probe) and subdomains:
            active_subdomains = filter_active_subdomains(subdomains, f"{OUTPUT_DIR}/{output_prefix}_active_200.txt", proxies, args.threads, args.verbose, args.timeout)

        # Directory-only mode
        if args.dir and not run_all:
            targets_path = f"{OUTPUT_DIR}/{TARGET_FILE}"
            if os.path.exists(targets_path):
                print(f"{C.BLUE}[*] Directory mode: Loading targets from {targets_path}{C.RESET}")
                with open(targets_path, "r", encoding='utf-8') as f:
                    subdomains_from_file = {line.strip() for line in f if line.strip()}
                if subdomains_from_file:
                    active_subdomains = filter_active_subdomains(subdomains_from_file, f"{OUTPUT_DIR}/{output_prefix}_active_200.txt", proxies, args.threads, args.verbose, args.timeout)
            else:
                print(f"{C.RED}[-] Directory mode requires targets. Run --passive or --active first.{C.RESET}")

        # --- IP Resolution & ASN ---
        if args.resolve and active_subdomains:
            print(f"\n{C.CYAN}[*] Resolving IPs and identifying cloud providers...{C.RESET}")
            resolve_results = {}
            progress = ProgressBar(len(active_subdomains), f"{C.CYAN}Resolving{C.RESET}")
            for sub in active_subdomains:
                resolve_results[sub] = resolve_ip_and_asn(sub, False)
                progress.update()
            for sub, info in sorted(resolve_results.items()):
                cloud = f" ({C.MAGENTA}{info['cloud']}{C.RESET})" if info['cloud'] != 'Unknown' else ""
                hostname = f" [{info.get('hostname', '')}]" if info.get('hostname') else ""
                print(f"  {C.GREEN}{sub}{C.RESET} -> {info['ip']}{cloud}{hostname}")
            export_json(resolve_results, f"{OUTPUT_DIR}/{output_prefix}_resolve.json")

        # --- Port Scanning ---
        if args.scan_ports and active_subdomains:
            print(f"\n{C.CYAN}[*] Scanning top ports on live hosts...{C.RESET}")
            port_results = {}
            progress = ProgressBar(len(active_subdomains), f"{C.CYAN}PortScan{C.RESET}")
            for sub in active_subdomains:
                open_ports = scan_ports(sub)
                port_results[sub] = open_ports
                progress.update()
            for sub, ports in sorted(port_results.items()):
                if ports:
                    print(f"  {C.GREEN}{sub}{C.RESET}: {C.YELLOW}{', '.join(map(str, ports))}{C.RESET}")
            export_json(port_results, f"{OUTPUT_DIR}/{output_prefix}_ports.json")

        # --- Technology Fingerprinting ---
        if args.fingerprint and active_subdomains:
            print(f"\n{C.CYAN}[*] Fingerprinting technology stacks...{C.RESET}")
            tech_results = {}
            progress = ProgressBar(len(active_subdomains), f"{C.CYAN}Fingerprint{C.RESET}")
            for sub in active_subdomains:
                tech_results[sub] = fingerprint_tech(f"https://{sub}", proxies)
                progress.update()
            for sub, tech in sorted(tech_results.items()):
                all_tech = []
                for cat, items in tech.items():
                    if items:
                        all_tech.extend(items)
                if all_tech:
                    print(f"  {C.GREEN}{sub}{C.RESET}: {C.CYAN}{', '.join(all_tech)}{C.RESET}")
            export_json(tech_results, f"{OUTPUT_DIR}/{output_prefix}_tech.json")

        # --- DNS Record Expansion ---
        if args.dns_records:
            print(f"\n{C.CYAN}[*] Enumerating DNS records for {target}...{C.RESET}")
            records = dns_record_expansion(target, verbose=True)
            export_json(records, f"{OUTPUT_DIR}/{output_prefix}_dns_records.json")

        # --- HTTP Method Fingerprinting ---
        if args.methods and active_subdomains:
            print(f"\n{C.CYAN}[*] Testing HTTP methods on live hosts...{C.RESET}")
            method_results = {}
            progress = ProgressBar(len(active_subdomains), f"{C.CYAN}HTTP Methods{C.RESET}")
            for sub in active_subdomains:
                methods = http_method_fingerprint(f"https://{sub}", proxies)
                method_results[sub] = methods
                progress.update()
            for sub, methods in sorted(method_results.items()):
                interesting = {m: s for m, s in methods.items() if s not in (0, 405, 501)}
                if interesting:
                    method_str = ", ".join(f"{m}:{s}" for m, s in interesting.items())
                    print(f"  {C.GREEN}{sub}{C.RESET}: {C.CYAN}{method_str}{C.RESET}")
            export_json(method_results, f"{OUTPUT_DIR}/{output_prefix}_methods.json")

        # --- Virtual Host Detection ---
        if args.vhost and active_subdomains:
            print(f"\n{C.CYAN}[*] Detecting virtual host anomalies...{C.RESET}")
            vhost_results = {}
            progress = ProgressBar(len(active_subdomains), f"{C.CYAN}VHost{C.RESET}")
            for sub in active_subdomains:
                vhost_results[sub] = detect_vhost(sub, proxies)
                progress.update()
            for sub, info in sorted(vhost_results.items()):
                if info.get("vhost_different") or info.get("title"):
                    flag = f"{C.RED}[VHOST]{C.RESET}" if info.get("vhost_different") else ""
                    print(f"  {C.GREEN}{sub}{C.RESET} {flag} title=\"{info.get('title', '')}\"")
            export_json(vhost_results, f"{OUTPUT_DIR}/{output_prefix}_vhost.json")

        # --- Subdomain Takeover Checks ---
        if args.takeover and active_subdomains:
            print(f"\n{C.CYAN}[*] Checking for subdomain takeover opportunities...{C.RESET}")
            takeover_results = []
            progress = ProgressBar(len(active_subdomains), f"{C.CYAN}Takeover{C.RESET}")
            for sub in active_subdomains:
                result = check_subdomain_takeover(sub, verbose=False)
                if result:
                    takeover_results.append(result)
                    print(f"  {C.RED}[!] TAKEOVER: {result['subdomain']} -> {result['cname']} ({result['service']}){C.RESET}")
                progress.update()
            if not takeover_results:
                print(f"  {C.GREEN}[+] No takeover opportunities found{C.RESET}")
            export_json(takeover_results, f"{OUTPUT_DIR}/{output_prefix}_takeover.json")

        # Step 3: Directory Enumeration
        if (run_all or args.dir) and active_subdomains:
            directory_enumeration(active_subdomains, args.dir_wordlist, f"{OUTPUT_DIR}/{output_prefix}_dirs.txt", proxies, args.threads, args.verbose, args.timeout)

        # --- Screenshot Capture ---
        if args.screenshots and active_subdomains:
            capture_screenshots(active_subdomains, OUTPUT_DIR, args.verbose)

        # --- v7.1 Recon Features ---

        # Subdomain permutation engine
        if args.permute or args.full_recon:
            perm_subs = subdomain_permutations(subdomains, target, args.verbose)
            subdomains.update(perm_subs)
            if perm_subs:
                atomic_write(f"{OUTPUT_DIR}/{output_prefix}_passive.txt", "\n".join(sorted(subdomains)))

        # SSL/TLS certificate intelligence
        if args.ssl_intel or args.full_recon:
            ssl_results = ssl_cert_intel(target, verbose=True)
            if ssl_results.get("sans"):
                # Extract subdomains from SANs
                san_subs = cert_san_mining(target, args.verbose)
                subdomains.update(san_subs)
                print(f"{C.GREEN}[+] Found {len(san_subs)} subdomains from SSL SANs{C.RESET}")
            export_json(ssl_results, f"{OUTPUT_DIR}/{output_prefix}_ssl.json")

        # WAF detection
        if args.waf_detect or args.full_recon:
            waf_result = detect_waf(f"https://{target}", proxies, verbose=True)
            if waf_result:
                print(f"{C.GREEN}[+] WAF: {waf_result['name']} ({waf_result['evidence']}){C.RESET}")
                # Try bypass techniques
                bypass_result = waf_bypass_probe(f"https://{target}", waf_result['name'], proxies)
                if bypass_result["bypasses_worked"] > 0:
                    print(f"{C.YELLOW}[!] {bypass_result['bypasses_worked']}/{bypass_result['bypasses_tried']} bypass techniques worked{C.RESET}")
                export_json({"waf": waf_result, "bypasses": bypass_result}, f"{OUTPUT_DIR}/{output_prefix}_waf.json")

        # robots.txt & sitemaps
        if args.robots or args.full_recon:
            robots_paths = crawl_robots_sitemap(f"https://{target}", proxies, args.verbose)
            if robots_paths:
                atomic_write(f"{OUTPUT_DIR}/{output_prefix}_robots.txt", "\n".join(robots_paths))

        # JavaScript secrets & endpoints
        if args.js_secrets and active_subdomains:
            all_js_findings = []
            for sub in sorted(active_subdomains)[:20]:
                findings = extract_js_secrets(f"https://{sub}", proxies, args.verbose)
                all_js_findings.extend(findings)
            if all_js_findings:
                print(f"{C.RED}[!] Found {len(all_js_findings)} JS secrets/endpoints across {min(20, len(active_subdomains))} hosts{C.RESET}")
                export_json(all_js_findings, f"{OUTPUT_DIR}/{output_prefix}_js_secrets.json")

        # Security header audit + CORS
        if args.security_audit or args.full_recon:
            all_security = []
            all_cors = []
            targets_to_audit = active_subdomains if active_subdomains else {target}
            for sub in sorted(targets_to_audit)[:20]:
                url = f"https://{sub}" if "." in sub else f"https://{sub}"
                audit = audit_security_headers(url, proxies, args.verbose)
                if audit:
                    all_security.append(audit)
                cors = detect_cors_misconfig(url, proxies, args.verbose)
                if cors and cors.get("misconfigs"):
                    all_cors.append(cors)
            if all_security:
                export_json(all_security, f"{OUTPUT_DIR}/{output_prefix}_security_headers.json")
            if all_cors:
                print(f"{C.RED}[!] Found {len(all_cors)} CORS misconfigurations{C.RESET}")
                export_json(all_cors, f"{OUTPUT_DIR}/{output_prefix}_cors.json")

        # API path probing
        if args.api_probe or args.full_recon:
            targets_to_probe = active_subdomains if active_subdomains else {target}
            all_api_findings = []
            for sub in sorted(targets_to_probe)[:10]:
                findings = probe_api_paths(f"https://{sub}", proxies, args.verbose)
                all_api_findings.extend(findings)
            if all_api_findings:
                export_json(all_api_findings, f"{OUTPUT_DIR}/{output_prefix}_api_paths.json")

        # Info disclosure probes
        if args.info_leak or args.full_recon:
            targets_to_leak = active_subdomains if active_subdomains else {target}
            all_leak_findings = []
            for sub in sorted(targets_to_leak)[:10]:
                findings = probe_info_disclosure(f"https://{sub}", proxies, args.verbose)
                all_leak_findings.extend(findings)
            if all_leak_findings:
                print(f"{C.RED}[!] Found {len(all_leak_findings)} potential info disclosure endpoints{C.RESET}")
                export_json(all_leak_findings, f"{OUTPUT_DIR}/{output_prefix}_info_leak.json")

        # Email extraction
        if args.emails or args.full_recon:
            all_emails = set()
            targets_to_email = active_subdomains if active_subdomains else {target}
            for sub in sorted(targets_to_email)[:20]:
                emails = extract_emails(f"https://{sub}", proxies, args.verbose)
                all_emails.update(emails)
            if all_emails:
                atomic_write(f"{OUTPUT_DIR}/{output_prefix}_emails.txt", "\n".join(sorted(all_emails)))

        # Wayback URLs
        if args.wayback_urls or args.full_recon:
            wayback_urls = wayback_url_extraction(target, args.verbose)
            if wayback_urls:
                atomic_write(f"{OUTPUT_DIR}/{output_prefix}_wayback_urls.txt", "\n".join(sorted(wayback_urls)))

        # DNS zone transfer
        if args.zone_transfer or args.full_recon:
            zt_result = test_zone_transfer(target, args.verbose)
            if zt_result.get("vulnerable"):
                print(f"{C.RED}[!] CRITICAL: Zone transfer vulnerable!{C.RESET}")
            export_json(zt_result, f"{OUTPUT_DIR}/{output_prefix}_zone_transfer.json")

        # Technology version extraction
        if args.tech_versions or args.full_recon:
            all_versions = []
            targets_to_version = active_subdomains if active_subdomains else {target}
            for sub in sorted(targets_to_version)[:20]:
                versions = extract_tech_versions(f"https://{sub}", proxies, args.verbose)
                all_versions.extend(versions)
            if all_versions:
                export_json(all_versions, f"{OUTPUT_DIR}/{output_prefix}_tech_versions.json")

        # Netblock discovery
        if args.netblocks or args.full_recon:
            cidrs = discover_netblocks(target, args.verbose)
            if cidrs:
                atomic_write(f"{OUTPUT_DIR}/{output_prefix}_netblocks.txt", "\n".join(sorted(cidrs)))

        # Cloud storage enumeration
        if args.cloud_buckets or args.full_recon:
            buckets = enumerate_cloud_storage(target, args.verbose)
            if buckets:
                export_json(buckets, f"{OUTPUT_DIR}/{output_prefix}_cloud_buckets.json")

        # Custom header injection
        if args.custom_headers:
            custom_h = load_custom_headers(args.custom_headers)
            if custom_h:
                print(f"{C.BLUE}[*] Testing with {len(custom_h)} custom headers...{C.RESET}")
                targets_to_test = active_subdomains if active_subdomains else {target}
                for sub in sorted(targets_to_test)[:5]:
                    session = get_session()
                    try:
                        resp = session.get(f"https://{sub}", headers=custom_h, timeout=8, verify=False)
                        print(f"{C.GREEN}[+] {sub}: HTTP {resp.status_code}{C.RESET}")
                    except Exception as e:
                        print(f"{C.YELLOW}[-] {sub}: {e}{C.RESET}")

        # Header leak detection
        if args.header_leaks or args.full_recon:
            all_leaks = []
            targets_to_leak_h = active_subdomains if active_subdomains else {target}
            for sub in sorted(targets_to_leak_h)[:20]:
                leaks = detect_header_leaks(f"https://{sub}", proxies, args.verbose)
                all_leaks.extend(leaks)
            if all_leaks:
                export_json(all_leaks, f"{OUTPUT_DIR}/{output_prefix}_header_leaks.json")

        # Protocol detection
        if args.protocols or args.full_recon:
            proto_results = {}
            targets_to_proto = active_subdomains if active_subdomains else {target}
            for sub in sorted(targets_to_proto)[:10]:
                proto_results[sub] = detect_protocols(f"https://{sub}", args.verbose)
            export_json(proto_results, f"{OUTPUT_DIR}/{output_prefix}_protocols.json")

        # --- Export JSON/CSV ---
        if args.json:
            scan_data = {
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "elapsed_seconds": SCAN_STATE.elapsed(),
                "total_subdomains": len(subdomains),
                "active_subdomains": len(active_subdomains),
                "wildcard_detected": wildcard_ip is not None,
                "wildcard_ip": wildcard_ip,
                "subdomains": sorted(subdomains),
                "active": sorted(active_subdomains),
            }
            json_path = f"{OUTPUT_DIR}/{output_prefix}_full_report.json"
            export_json(scan_data, json_path)
            print(f"{C.GREEN}[+] JSON report saved to {json_path}{C.RESET}")

        if args.csv and active_subdomains:
            csv_rows = []
            for sub in sorted(active_subdomains):
                row = {"subdomain": sub}
                if args.resolve and sub in resolve_results:
                    row.update(resolve_results[sub])
                if args.scan_ports and sub in port_results:
                    row["open_ports"] = ",".join(map(str, port_results[sub]))
                if args.fingerprint and sub in tech_results:
                    for cat, items in tech_results[sub].items():
                        row[f"tech_{cat}"] = ",".join(items)
                csv_rows.append(row)
            csv_path = f"{OUTPUT_DIR}/{output_prefix}_report.csv"
            export_csv(csv_rows, csv_path)
            print(f"{C.GREEN}[+] CSV report saved to {csv_path}{C.RESET}")

        # --- Save checkpoint ---
        save_checkpoint(target, {
            "subdomains": sorted(subdomains),
            "active_subdomains": sorted(active_subdomains),
            "wildcard_ip": wildcard_ip,
        })

    elapsed = SCAN_STATE.elapsed()
    print(END_BANNER.format(f"{elapsed:.1f}"))
    logging.info(f"Hunt completed in {elapsed:.1f}s")


def check_http_200(url: str, proxies: List[str], retries: int = 4, verbose: bool = False, timeout: int = 5) -> bool:
    """Validate HTTP 200 - backward compatible wrapper around hardened_request."""
    response = hardened_request(url, proxies=proxies, timeout=timeout, retries=retries, verbose=verbose, service="http200")
    return response is not None and response.status_code == 200


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        SCAN_STATE.request_shutdown()
        print(f"\n{C.YELLOW}[!] Hunt interrupted by user. Saving partial results...{C.RESET}")
    except SystemExit:
        pass
    except Exception as e:
        print(f"\n{C.RED}[!] Fatal error: {e}{C.RESET}")
        traceback.print_exc()
        logging.error(f"Fatal error: {e}\n{traceback.format_exc()}")
    finally:
        # Clean up session pool
        if _session_pool:
            _session_pool.close()
        elapsed = SCAN_STATE.elapsed()
        if elapsed > 0:
            print(f"{C.DIM}[*] Total runtime: {elapsed:.1f}s{C.RESET}")