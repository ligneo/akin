# CSRF-Aware Brute Force Engine v2.2

> **⚠️ AUTHORIZED PENETRATION TESTING USE ONLY**
> Unauthorized access to computer systems is illegal. Ensure you have **written authorization** before testing.

## Overview

A Python-based penetration testing tool that bypasses **Anti-CSRF (Cross-Site Request Forgery)** token mechanisms to perform brute-force authentication attacks. Designed for **DVWA (Damn Vulnerable Web Application)** and similar CSRF-protected login forms.

### Framework Alignment

| Framework | Mapping |
|-----------|---------|
| **MITRE ATT&CK** | T1110.001 (Brute Force), T1090.002 (Proxy Rotation), T1036.005 (UA Masquerading) |
| **Cyber Kill Chain** | Phase 5 — Exploitation |
| **PTES** | Exploitation Phase |

## Algorithm Architecture

```
┌─────────────────────────────────────────────────────────┐
│  STEP 0: DVWA Auth (auto-login or cookie injection)     │
│  ↓                                                      │
│  STEP 1: Session Init (PHPSESSID + security cookie)     │
│  ↓                                                      │
│  STEP 2: GET Request (fetch login page HTML)       ←──┐ │
│  ↓                                                    │ │
│  STEP 3: DOM Parse (extract CSRF token via regex)     │ │
│  ↓                                                    │ │
│  STEP 4: Payload Build (creds + token + form params)  │ │
│  ↓                                                    │ │
│  STEP 5: Execute + Evasion (jitter, UA, proxy rot.)   │ │
│  ↓                                                    │ │
│  STEP 6: Response Analysis (status + body scan)       │ │
│  ↓                                                    │ │
│  STEP 7: Reset token → Loop back to Step 2 ──────────┘ │
│  (Token is single-use nonce, MUST re-fetch each cycle)  │
└─────────────────────────────────────────────────────────┘
```

## Installation

```bash
# Only dependency
pip install requests
```

## Quick Start

### Simplest Usage (Auto-Login)

The script **automatically logs into DVWA** using the default credentials (`admin` / `password`), then attacks the brute force challenge. No cookies needed:

```bash
python3 csrf_brute.py \
    -t http://localhost/DVWA/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt
```

### With Explicit Security Level

```bash
python3 csrf_brute.py \
    -t http://localhost/DVWA/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt \
    --security high
```

### With Browser Cookies (Manual Injection)

If you've already logged into DVWA in your browser, copy your cookies from **DevTools → Application → Cookies** and pass them:

```bash
python3 csrf_brute.py \
    -t http://localhost/DVWA/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt \
    --cookie "PHPSESSID=abc123def456; security=low"
```

### DVWA Main Login Page (POST)

The `/login.php` page uses POST. Specify with `-m POST`:

```bash
python3 csrf_brute.py \
    -t http://localhost/DVWA/login.php \
    -u admin \
    -w wordlists/sample.txt \
    -m POST
```

### Impossible Mode (Lockout Bypass with Proxy Rotation)

```bash
python3 csrf_brute.py \
    -t http://localhost/DVWA/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt \
    --security impossible \
    --proxy-list proxies.txt \
    --lockout-after 2
```

### With rockyou.txt + Fast Jitter

```bash
python3 csrf_brute.py \
    -t http://localhost/DVWA/vulnerabilities/brute/ \
    -u admin \
    -w /usr/share/wordlists/rockyou.txt \
    --jitter-min 0.1 --jitter-max 0.3 \
    --security high -v
```

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | **Full** target URL to attack | *required* |
| `-u, --username` | Target username | *required* |
| `-w, --wordlist` | Password wordlist file path | *required* |
| `-m, --method` | HTTP method: `GET` or `POST` | `GET` |
| `-c, --cookie` | Inject browser cookies (`"PHPSESSID=x; security=low"`) | None (auto-login) |
| `-s, --security` | DVWA security level: `low` `medium` `high` `impossible` | None |
| `--token-name` | CSRF token field name | `user_token` |
| `--failure` | Failure indicator string | `Username and/or password incorrect` |
| `--success-path` | Redirect path for success detection | `/dashboard` |
| `--jitter-min` | Min delay between requests (seconds) | `0.5` |
| `--jitter-max` | Max delay between requests (seconds) | `2.0` |
| `--no-ua-rotate` | Disable User-Agent rotation | off |
| `--proxy` | Single HTTP proxy URL | None |
| `--proxy-list` | Proxy list file for IP rotation | None |
| `--lockout-after` | Rotate proxy after N attempts | `2` |
| `-o, --output` | File to append cracked credentials | None |
| `-v, --verbose` | Show step-level debug output | off |

## Key Concepts

### Why DVWA Requires Authentication First

DVWA's vulnerability pages (`/vulnerabilities/*`) are behind a login wall. You must be authenticated to DVWA before you can access the brute force challenge. The tool handles this in two ways:

1. **Auto-login (default)**: The script automatically logs into DVWA at `/login.php` using the default credentials (`admin`/`password`), then uses that authenticated session.

2. **Cookie injection (`-c`)**: If you've already logged in via your browser, you can copy your `PHPSESSID` and `security` cookies and inject them directly.

### Why GET, Not POST?

The DVWA brute force page (`/vulnerabilities/brute/`) uses `<form method="GET">`. Credentials are sent as **URL query parameters**, not in the POST body. Using POST means the server completely ignores the payload.

| DVWA Page | HTTP Method | Usage |
|-----------|-------------|-------|
| `/vulnerabilities/brute/` | **GET** | `-m GET` (default) |
| `/login.php` | **POST** | `-m POST` |

### Token Handling — 100% Dynamic & Automated

The CSRF token (`user_token`) is **never static or hardcoded**. Every iteration:

1. **GET** → Fresh HTML fetched from the server
2. **Regex** → New `user_token` nonce extracted from `<input type="hidden">`
3. **Inject** → Token placed into the payload
4. **Consume** → Server validates and invalidates the token
5. **Discard** → Old token deleted, loop restarts

### Proxy Rotation — Impossible Mode Lockout Bypass

DVWA's Impossible level locks accounts after 3 failed attempts per IP (15-minute cooldown). The `ProxyPool` defeats this by rotating source IPs:

```bash
# Fetch fresh free proxies
curl -s "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=no&anonymity=elite" > proxies.txt

# Or use TOR
echo "socks5://127.0.0.1:9050" > proxies.txt
```

### Terminal UI

- **` PASS  `** (red background) — Failed login attempt
- **` FOUND `** (green background) — Cracked credential
- Progress bar with `█░` fill and percentage
- Box-drawn summary table on exit (always, including Ctrl+C)
- **🔓 CRACKED CREDENTIALS** section listing all caught logins

## Project Structure

```
brute/
├── csrf_brute.py          # Main engine (all 7 algorithm steps)
├── proxies.txt            # Proxy list template (for lockout bypass)
├── wordlists/
│   └── sample.txt         # Sample wordlist (includes DVWA default)
└── README.md              # This file
```

## Version History

### v2.2 (Current)
- **Added**: Auto-login to DVWA (no more manual cookie copying needed)
- **Added**: `--cookie` flag for injecting browser cookies
- **Added**: `--security` flag for DVWA security level
- **Fixed**: Authentication issue — script was hitting login redirect instead of brute force page

### v2.1
- Fixed: DVWA brute page uses GET, not POST — added `-m/--method`
- Fixed: Default failure string matches DVWA's actual response
- Added: Proxy rotation via `--proxy-list` for Impossible mode lockout bypass
- Added: `--lockout-after` threshold control

### v2.0
- Full URL flexibility (`-t` accepts complete URL)
- Rich colorized terminal output (PASS/FOUND indicators, progress bar)
- Results cache with summary table on exit
- Graceful Ctrl+C with credential summary

### v1.0
- Initial 7-step CSRF bypass algorithm implementation

## Legal Notice

This tool is provided for **educational and authorized security testing purposes only**.
