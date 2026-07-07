# CSRF-Aware Brute Force Engine v3.0

> **⚠️ AUTHORIZED PENETRATION TESTING USE ONLY**
> Unauthorized access to computer systems is illegal. Ensure you have **written authorization** before testing.

## Overview

A Python-based penetration testing tool that bypasses **Anti-CSRF token mechanisms** to perform brute-force authentication attacks. Built for **DVWA (Damn Vulnerable Web Application)** with full security-level awareness.

### Framework Alignment

| Framework | Mapping |
|-----------|---------|
| **MITRE ATT&CK** | T1110.001 (Brute Force), T1090.002 (Proxy Rotation), T1036.005 (UA Masquerading) |
| **Cyber Kill Chain** | Phase 5 — Exploitation |
| **PTES** | Exploitation Phase |

---

## DVWA Security Level Analysis

### Level Matrix (Verified Against Live DVWA)

| Level | HTTP Method | CSRF Token | Server Delay | Lockout | Brute-Force Viable? |
|-------|:-----------:|:----------:|:------------:|:-------:|:-------------------:|
| **Low** | `GET` | ❌ None | None | None | ✅ Yes — trivial |
| **Medium** | `GET` | ❌ None | `sleep(2)` | None | ✅ Yes — just slower |
| **High** | `GET` | ✅ `user_token` | `sleep(0-3)` random | None | ✅ Yes — token is trivially automated |
| **Impossible** | `POST` | ✅ `user_token` | None | 3 failures → 15 min lock | ❌ No — wrong attack vector |

### Low — No Protection
- **Defense**: None
- **What to learn**: Basic brute-force mechanics — wordlist iteration, HTTP request construction, success/failure detection
- **Bypass**: Direct GET request with `username` + `password` + `Login` parameters

### Medium — Server-Side Rate Limiting
- **Defense**: `sleep(2)` on every failed login attempt (server-side)
- **What to learn**: How speed/rate-based defenses work. The delay is server-side and **cannot be bypassed** from the client. Conceptually, parallel sessions from different IPs could help.
- **Bypass**: Identical to Low, just 2 seconds slower per attempt. With 14M passwords (rockyou.txt), this turns a days-long attack into a months-long one.

### High — CSRF Token (False Sense of Security)
- **Defense**: Anti-CSRF token (`user_token`) embedded as a hidden form field + `sleep(rand(0,3))`
- **What to learn**: The CSRF token is **NOT a real brute-force barrier**. It's a defense against Cross-Site Request Forgery (a different attack), not against direct brute-forcing. Since the attacker can simply GET the page, read the token, and include it in their request, it's trivially automated.
- **Bypass**: Fetch fresh token per request (GET → regex extract → inject into payload). This is the level best suited to the "penetration" scenario — a genuine vulnerability exists behind a false sense of security.

### Impossible — Account Lockout (Proper Defense)
- **Defense**: Account lockout after 3 failed attempts (15-minute cooldown), CSRF token, POST method, PDO prepared statements (no SQLi)
- **What to learn**: This is a **properly defended** brute-force mechanism. The lockout is tied to the **account**, not just the source IP — proxy rotation can't bypass it.
- **Why brute-force is wrong here**: Even with 1000 proxies, the account itself locks after 3 failures. You'd need to wait 15 minutes between every 3 attempts. With rockyou.txt that's **~70 years**.
- **Better approach**: Analyze for **DoS potential** — can an attacker intentionally lock a legitimate user's account by sending 3 bad attempts? That's a denial-of-service vulnerability in the lockout mechanism itself.

---

## Quick Start Commands

### Low Level
```bash
python3 csrf_brute.py \
    -t http://127.0.0.1:4280/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt \
    -s low
```

### Medium Level
```bash
# Same as Low but expect ~2s per failed attempt (server-side delay)
python3 csrf_brute.py \
    -t http://127.0.0.1:4280/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt \
    -s medium
```

### High Level (CSRF Token Bypass)
```bash
# Token is auto-extracted and injected per request
python3 csrf_brute.py \
    -t http://127.0.0.1:4280/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt \
    -s high
```

### Impossible Level (Educational — Will Fail)
```bash
# ⚠ Brute-force is the WRONG attack vector here
python3 csrf_brute.py \
    -t http://127.0.0.1:4280/vulnerabilities/brute/ \
    -u admin \
    -w wordlists/sample.txt \
    -s impossible
```

### Other Examples
```bash
# With browser cookies (copy from DevTools → Application → Cookies)
python3 csrf_brute.py \
    -t http://127.0.0.1:4280/vulnerabilities/brute/ \
    -u admin -w wordlists/sample.txt \
    --cookie "PHPSESSID=abc123; security=high"

# With rockyou.txt + fast jitter
python3 csrf_brute.py \
    -t http://127.0.0.1:4280/vulnerabilities/brute/ \
    -u admin \
    -w /usr/share/wordlists/rockyou.txt \
    -s high --jitter-min 0.1 --jitter-max 0.3

# With Burp Suite proxy + verbose
python3 csrf_brute.py \
    -t http://127.0.0.1:4280/vulnerabilities/brute/ \
    -u admin -w wordlists/sample.txt \
    -s high --proxy http://127.0.0.1:8080 -v

# Custom non-DVWA target
python3 csrf_brute.py \
    -t http://target.local/auth/login \
    -u admin -w rockyou.txt -m POST \
    --token-name csrf_token \
    --failure "Invalid credentials" \
    --success "Dashboard"
```

---

## Installation

```bash
pip install requests
```

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Full target URL | *required* |
| `-u, --username` | Target username | *required* |
| `-w, --wordlist` | Password wordlist | *required* |
| `-s, --security` | DVWA level: `low` `medium` `high` `impossible` | None (auto-detect) |
| `-m, --method` | Override HTTP method: `GET` or `POST` | Auto from `-s` |
| `-c, --cookie` | Inject browser cookies | None (auto-login) |
| `--no-token` | Skip CSRF token extraction | off |
| `--token-name` | CSRF token field name | `user_token` |
| `--failure` | Failure string in response | `Username and/or password incorrect` |
| `--success` | Success string in response | `Welcome to the password protected area` |
| `--jitter-min` | Min delay between requests (sec) | `0.5` |
| `--jitter-max` | Max delay between requests (sec) | `2.0` |
| `--no-ua-rotate` | Disable User-Agent rotation | off |
| `--proxy` | Single HTTP proxy | None |
| `--proxy-list` | Proxy list file for rotation | None |
| `--lockout-after` | Rotate proxy after N attempts | `2` |
| `-o, --output` | File to append cracked credentials | None |
| `-v, --verbose` | Show step-level debug output | off |

---

## Algorithm Architecture

```
┌─────────────────────────────────────────────────────────┐
│  STEP 0: DVWA Auth (auto-login or cookie injection)     │
│  ↓                                                      │
│  STEP 1: Session Init + security cookie override        │
│  ↓                                                      │
│  STEP 2: GET page (fetch HTML)                     ←──┐ │
│  ↓                                                    │ │
│  STEP 3: Extract CSRF token (if level requires it)    │ │
│  ↓                                                    │ │
│  STEP 4: Build payload (creds + token + Login)        │ │
│  ↓                                                    │ │
│  STEP 5: Execute GET/POST + evasion                   │ │
│  ↓                                                    │ │
│  STEP 6: Analyze response (strict string match)       │ │
│  ↓                                                    │ │
│  STEP 7: Reset token → Loop back to Step 2 ──────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## How Token Automation Works

The CSRF token is **100% dynamic and automated**. Every iteration:

1. **GET** → Fresh HTML fetched from server
2. **Regex** → `user_token` nonce extracted from `<input type="hidden">`
3. **Inject** → Token placed into GET/POST payload
4. **Consume** → Server validates and invalidates the token
5. **Discard** → Old token deleted, loop restarts

For Low/Medium: no token exists → skip steps 2-3, go straight to payload.

---

## Bugs Fixed in v3.0

### False Positives (Every attempt showed as "FOUND")
**Root cause**: DVWA's navigation sidebar contains a `Logout` link on **every authenticated page**. The old heuristic matched "logout" in the body → 100% false success rate.
**Fix**: Strict matching — only the verified success string triggers success. No more heuristic fallbacks.

### Cookie Conflict (Security level ignored)
**Root cause**: DVWA sets `security=impossible` as a server cookie on initial page load. Python's `session.cookies.set("security", "low")` created a **duplicate** cookie instead of overwriting. The server's `impossible` value always took precedence.
**Fix**: Clear all existing `security` cookies from the jar before setting the desired level.

### Wrong HTTP Method (Payload silently ignored)
**Root cause**: DVWA's brute force page uses `<form method="GET">` but the script was sending POST. Server ignored the POST body entirely.
**Fix**: Level-aware method selection (Low/Medium/High → GET, Impossible → POST).

---

## Project Structure

```
brute/
├── csrf_brute.py          # Main engine v3.0
├── proxies.txt            # Proxy list template (for lockout bypass)
├── wordlists/
│   └── sample.txt         # Sample wordlist (20 passwords, includes "password")
└── README.md              # This file
```

## Legal Notice

This tool is provided for **educational and authorized security testing purposes only**.
