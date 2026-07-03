# CSRF-Aware Brute Force Engine v2.1

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
│  STEP 1: Session Init (PHPSESSID binding)               │
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

### DVWA Brute Force Page (Low/Medium/High Security)

The DVWA brute force page uses **GET method**. This is the default:

```bash
python3 csrf_brute.py \
    -t http://192.168.1.100/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt
```

### DVWA Main Login Page (`/login.php`)

The login page uses **POST method**. Specify with `-m POST`:

```bash
python3 csrf_brute.py \
    -t http://192.168.1.100/login.php \
    -u admin \
    -w wordlists/sample.txt \
    -m POST
```

### DVWA Impossible Mode (Lockout Bypass with Proxy Rotation)

The Impossible level locks accounts after 3 failed attempts per IP.
Use `--proxy-list` to rotate source IPs:

```bash
python3 csrf_brute.py \
    -t http://192.168.1.100/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt \
    --proxy-list proxies.txt \
    --lockout-after 2
```

### Custom Application

```bash
python3 csrf_brute.py \
    -t http://target.local/auth/login \
    -u admin \
    -w /usr/share/wordlists/rockyou.txt \
    -m POST \
    --token-name csrf_token \
    --failure "Invalid credentials"
```

### With Burp Suite Proxy + Verbose

```bash
python3 csrf_brute.py \
    -t http://192.168.1.100/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt \
    --proxy http://127.0.0.1:8080 -v
```

### Maximum Stealth

```bash
python3 csrf_brute.py \
    -t http://target/login \
    -u admin \
    -w wordlists/sample.txt \
    --jitter-min 3.0 --jitter-max 10.0
```

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | **Full** target URL to attack | *required* |
| `-u, --username` | Target username | *required* |
| `-w, --wordlist` | Password wordlist file path | *required* |
| `-m, --method` | HTTP method: `GET` or `POST` | `GET` |
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

### Why GET, Not POST?

The DVWA brute force page (`/vulnerabilities/brute/`) uses `<form method="GET">`. The credentials are sent as **URL query parameters**, not in the POST body. Using POST against this page means the server completely ignores the payload — it never sees your login attempt.

| DVWA Page | HTTP Method | Usage |
|-----------|-------------|-------|
| `/vulnerabilities/brute/` | **GET** | `-m GET` (default) |
| `/login.php` | **POST** | `-m POST` |

### Token Handling — 100% Dynamic & Automated

The CSRF token (`user_token`) is **never static or hardcoded**. Every single iteration:

1. **GET** → Fresh HTML fetched from the server
2. **Regex** → New `user_token` nonce extracted from `<input type="hidden">`
3. **Inject** → Token placed into the payload alongside credentials
4. **Consume** → Server validates and invalidates the token
5. **Discard** → Old token deleted from memory, loop restarts at step 1

You never need to manually handle tokens. The automation handles the full CSRF bypass cycle.

### Proxy Rotation — Impossible Mode Lockout Bypass

DVWA's Impossible level implements per-IP account lockout after 3 failed attempts (15-minute cooldown). The `ProxyPool` class defeats this by:

1. Loading proxies from `proxies.txt`
2. Randomizing the pool order (OpSec)
3. Tracking attempts per proxy
4. Rotating to the next proxy after `--lockout-after` attempts
5. Re-initializing the HTTP session with the new source IP
6. Marking dead/unreachable proxies and removing them from rotation

**Sources for fresh proxies:**

```bash
# Free proxy API (elite anonymity, HTTP)
curl -s "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=no&anonymity=elite" > proxies.txt

# TOR (local SOCKS5)
echo "socks5://127.0.0.1:9050" > proxies.txt

# For serious engagements: use a VPS fleet or residential proxy service
```

### Terminal UI

The output uses rich ANSI colors:

- **` PASS  `** (red background) — Failed login attempt
- **` FOUND `** (green background) — Cracked credential!
- Progress bar with `█░` fill and percentage
- Box-drawn summary table on exit
- Proxy address shown per attempt when using pool rotation

### Exit Summary

On **any** exit condition — success, Ctrl+C, or wordlist exhaustion — the tool prints a session summary including:

- Total attempts, duration, request rate
- **🔓 CRACKED CREDENTIALS** section with all caught logins
- Timestamps and attempt numbers for each crack

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

### v2.1 (Current)
- **Fixed**: DVWA brute page uses GET, not POST — added `-m/--method` flag
- **Fixed**: Default failure string now matches DVWA's actual response
- **Added**: Proxy rotation via `--proxy-list` for Impossible mode lockout bypass
- **Added**: `--lockout-after` threshold control

### v2.0
- Full URL flexibility (`-t` accepts complete URL, no static path appending)
- Rich colorized terminal output (PASS/FOUND indicators, progress bar)
- Results cache with summary table on exit
- Graceful Ctrl+C with credential summary
- Signal-safe loop control

### v1.0
- Initial implementation of 7-step CSRF bypass algorithm
- Session management, token extraction, payload construction
- User-Agent rotation and jitter evasion

## Legal Notice

This tool is provided for **educational and authorized security testing purposes only**.
The authors are not responsible for misuse. Always obtain proper authorization.
