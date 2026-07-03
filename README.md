# CSRF-Aware Brute Force Engine

> **⚠️ AUTHORIZED PENETRATION TESTING USE ONLY**
> Unauthorized access to computer systems is illegal under laws including
> the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and equivalent
> legislation worldwide. Ensure you have **written authorization** before testing.

## Overview

A Python-based penetration testing tool that bypasses **Anti-CSRF (Cross-Site Request Forgery)** token mechanisms to perform brute-force authentication attacks. Designed for testing **DVWA (Damn Vulnerable Web Application)** and similar CSRF-protected login forms.

### Framework Alignment

| Framework | Mapping |
|-----------|---------|
| **MITRE ATT&CK** | T1110.001 (Brute Force: Password Guessing) |
| **Cyber Kill Chain** | Phase 5 - Exploitation |
| **PTES** | Exploitation Phase |

## Algorithm Architecture

The tool implements a 7-step attack cycle:

```
┌─────────────────────────────────────────────────────────┐
│  STEP 1: Session Initialization (PHPSESSID binding)     │
│  ↓                                                      │
│  STEP 2: GET Request (Fetch login page HTML)       ←──┐ │
│  ↓                                                    │ │
│  STEP 3: DOM Parsing (Extract CSRF token via regex)   │ │
│  ↓                                                    │ │
│  STEP 4: Payload Construction (creds + token + form)  │ │
│  ↓                                                    │ │
│  STEP 5: POST Execution + Evasion (jitter, UA rot.)   │ │
│  ↓                                                    │ │
│  STEP 6: Response Analysis (status code + body scan)  │ │
│  ↓                                                    │ │
│  STEP 7: Reset token → Loop back to Step 2 ──────────┘ │
│  (Token is single-use nonce, must re-fetch each cycle)  │
└─────────────────────────────────────────────────────────┘
```

## Installation

```bash
# Only dependency: requests
pip install requests
```

## Usage

### Basic DVWA Attack

```bash
python3 csrf_brute.py -t http://192.168.1.100 -u admin -w wordlists/sample.txt
```

### With Proxy (Burp Suite)

```bash
python3 csrf_brute.py \
    -t http://192.168.1.100 \
    -u admin \
    -w wordlists/sample.txt \
    --proxy http://127.0.0.1:8080 \
    -v
```

### Maximum Stealth Mode

```bash
python3 csrf_brute.py \
    -t http://192.168.1.100 \
    -u admin \
    -w /usr/share/wordlists/rockyou.txt \
    --jitter-min 3.0 \
    --jitter-max 10.0 \
    -o results.txt
```

### Custom Form Parameters

```bash
python3 csrf_brute.py \
    -t http://target.local \
    -u administrator \
    -w passwords.txt \
    --token-name csrf_token \
    --failure "Invalid credentials" \
    -p /login
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target base URL | *required* |
| `-u, --username` | Target username | *required* |
| `-w, --wordlist` | Password wordlist path | *required* |
| `-p, --path` | Login endpoint path | `/vulnerabilities/brute/` |
| `--token-name` | CSRF token field name | `user_token` |
| `--failure` | Failure indicator string | `Login failed` |
| `--success-path` | Success redirect path | `/dashboard` |
| `--jitter-min` | Min delay between requests (seconds) | `0.5` |
| `--jitter-max` | Max delay between requests (seconds) | `2.0` |
| `--no-ua-rotate` | Disable User-Agent rotation | `false` |
| `--proxy` | HTTP proxy URL | `None` |
| `-o, --output` | Output results file | `None` |
| `-v, --verbose` | Enable debug output | `false` |

## OpSec Features

### User-Agent Rotation (T1036.005)
Randomly selects from 7 legitimate browser User-Agent strings per request to defeat signature-based detection and simple fingerprinting.

### Request Jitter (Rate-Limit Evasion)
Introduces randomized delays between requests using a configurable range. This prevents triggering SOC/SIEM rate-limit alarms and makes traffic appear more organic.

### Referer Header Spoofing
Automatically sets the `Referer` header to the login page URL, mimicking the natural browser navigation flow of a user submitting a form.

### Proxy Support
Routes traffic through an HTTP proxy (e.g., Burp Suite at `127.0.0.1:8080`) for traffic inspection, modification, and replay capabilities.

## Project Structure

```
brute/
├── csrf_brute.py          # Main attack engine (7-step algorithm)
├── wordlists/
│   └── sample.txt         # Sample wordlist for DVWA testing
└── README.md              # This file
```

## Why CSRF Tokens Require Per-Request Refresh

CSRF tokens in secure implementations are **single-use cryptographic nonces**:

1. Server generates a unique token and binds it to the current session
2. Token is embedded in the HTML form as a hidden input field
3. When the form is submitted, the server validates and **consumes** the token
4. The consumed token is **invalidated** — it cannot be reused

This is why the tool must perform a **full GET → Extract → POST cycle** for every
password attempt, rather than simply reusing a single token for all requests.

## Legal Notice

This tool is provided for **educational and authorized security testing purposes only**.
The authors are not responsible for misuse or damage caused by this tool.
Always obtain proper authorization before conducting any penetration testing activities.
