# idorf

<p align="center">
  <img src="https://img.shields.io/badge/version-0.8.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/github/license/Z4D3S/idorf?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/go-%3E%3D1.21-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" alt="PRs">
</p>

**idorf** — IDOR Runner. A CLI tool for detecting Insecure Direct Object Reference and access control vulnerabilities.

```bash
# Proxy mode: browse the target, idorf detects access issues automatically
idorf --proxy-mode --users "admin:Bearer tok1,user:Bearer tok2,anon:"

# Auto-detect: point at any endpoint, idorf finds IDs and fuzzes them
idorf -c 'curl "http://target.com/api/users/123/profile"' --auto

# HAR import: capture traffic with Burp, replay with N sessions offline
idorf --har traffic.har --users "admin:x,user:y"
```

## How it works

idorf detects access control vulnerabilities using two complementary approaches:

### 1. Multi-session comparison (proxy mode)

Captures each request and replays it with N different user sessions. Compares responses to find:

- **Role-based access issues**: admin sees data, user gets 403 — detected by comparing user A vs user B
- **Missing ownership checks**: any user can access any user's data — detected via automatic ID fuzzing (v0.8+)

### 2. ID fuzzing (auto-detect mode)

Scans requests for object references (integers, UUIDs, prefixed IDs), generates mutations, and tests if different values return data for different users.

## Features

| Feature | Description | Since |
|---------|-------------|-------|
| **Proxy mode** | Intercept HTTP/HTTPS traffic, replay with N users | v0.4 |
| **Multi-session** | Compare admin vs user vs anonymous side by side | v0.3 |
| **Auto-ID detection** | Finds IDs in URL, query, body (int, UUID, base64, hash, prefixed) | v0.5 |
| **ID fuzzing** | Sequential mutations, random UUIDs, base64 decode/re-encode | v0.5 |
| **Proxy auto-ID** | After comparison, fuzzes detected IDs to find universal IDORs | v0.8 |
| **Semantic diff** | JSON structural comparison (not just size/status code) | v0.3 |
| **HTTPS MITM** | Self-signed CA cert at `~/.config/idorf/ca.crt` | v0.6 |
| **CSRF filtering** | Ignores volatile fields (timestamps, nonces, tokens) in diffs | v0.6 |
| **HAR import** | Import Burp/DevTools traffic, replay offline | v0.7 |
| **HTML report** | Self-contained dark-mode report for sharing | v0.7 |
| **Custom patterns** | Regex-based sensitive data detection (email, phone, SSN, etc.) | v0.2 |
| **Known-IDs baseline** | Mark your own IDs as safe | v0.2 |
| **Session management** | Auto-updates cookies from Set-Cookie headers | v0.1 |
| **Concurrent engine** | Parallel requests with rate limiting | v0.1 |

## Install

```bash
go install github.com/Z4D3S/idorf/cmd/idorf@latest
```

Or build from source:

```bash
git clone https://github.com/Z4D3S/idorf
cd idorf
make build
```

## Usage

### Proxy mode (recommended for auditing)

Browse the target normally. idorf replays each request with N user sessions and detects access control differences.

```bash
idorf --proxy-mode --proxy-listen 127.0.0.1:8081 \
  --users "admin:Bearer admin-token,user:Bearer user-token,anon:"
```

Then configure your browser to use `127.0.0.1:8081` as HTTP proxy. Browser → idorf → target.

idorf will show two types of findings:

```
🔴 [HIGH] GET http://api.target.com/orders/ORD-001
 admin:200/150 user:403/49
   admin got 200 but user got 403
```
↑ **Role-based**: admin can access, user can't (expected, marks as HIGH)

```
🟢 [SAFE] GET http://api.target.com/users/1/profile
 admin:200/118 user:200/118
   🚨 IDOR via ID mutation: 3 → diff score: 100
```
↑ **Universal IDOR**: both users see the same data, BUT fuzzing found that different IDs return different users' data

### Auto-detect mode

Scans the request for IDs and generates mutations automatically:

```bash
idorf -c 'curl "http://target.com/api/users/123/profile"' --auto
```

Output:
```
[+] Auto-detect: found 1 IDs
    integer: 123 (url) at url.path[5]
[+] Auto-detect: generated 8 mutations
🚨 [CRITICAL] 1 → HTTP 200 (different user data)
🚨 [CRITICAL] 2 → HTTP 200 (different user data)
```

Use with `--known-ids` to mark your own IDs as safe:

```bash
idorf -c 'curl "http://target.com/api/users/123/profile"' --auto --known-ids 123
```

### HAR import

Capture traffic with Burp Suite or browser DevTools, export as HAR, then replay with idorf:

```bash
idorf --har capture.har --users "admin:Bearer x,user:Bearer y"
```

This replays each request in the HAR file with each user session and reports access control differences.

### Classic fuzzing

```bash
idorf -c 'curl "http://target.com/api/users/FUZZ/profile"' -w ids.txt
```

### Multi-session comparison (without proxy)

```bash
idorf -c 'curl "http://target.com/api/orders/ORD-001"' \
  --users "admin:Bearer x,user:Bearer y"
```

### HTML report

```bash
idorf -c 'curl "http://target.com/api/users/FUZZ"' -w ids.txt -o report.html
```

### Session file

```json
{
  "cookies": [
    {"name": "JSESSIONID", "value": "ABC123", "domain": ".target.com"}
  ],
  "headers": [
    {"name": "Authorization", "value": "Bearer ey..."}
  ]
}
```

### Users file (for multi-session)

```json
{
  "users": [
    {"name": "admin", "headers": [{"name": "Authorization", "value": "Bearer admin-token"}]},
    {"name": "user", "cookies": [{"name": "session", "value": "abc123"}],
     "headers": [{"name": "Authorization", "value": "Bearer user-token"}]},
    {"name": "anon", "headers": []}
  ]
}
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | `""` | cURL command |
| `-r` | `""` | Raw HTTP request file |
| `-w` | `""` | Wordlist (one per line) |
| `-m` | `"FUZZ"` | Marker to replace |
| `--proxy-mode` | `false` | Start proxy for live capture |
| `--proxy-listen` | `127.0.0.1:8081` | Proxy listen address |
| `--har` | `""` | HAR file to import |
| `--include-static` | `false` | Include static assets in HAR |
| `--auto` | `false` | Auto-detect IDs and generate mutations |
| `--users` | `""` | Multi-session: `name:token,name:token` |
| `--users-file` | `""` | JSON file with user sessions |
| `-s` | `""` | Session file (cookies/tokens) |
| `-o` | `""` | Output file (JSON or HTML) |
| `--diff-pattern` | `""` | Custom regex for sensitive data |
| `--known-ids` | `""` | Comma-separated known-safe IDs |
| `-t` | `5` | Concurrent threads |
| `--rate-limit` | `10` | Requests per second |
| `--timeout` | `10` | Request timeout in seconds |
| `--proxy` | `""` | Outbound proxy (for Burp) |
| `--verbose` | `false` | Verbose output |
| `-v` | `false` | Show version |

## ID detection

| Type | Example | Detection |
|------|---------|-----------|
| Integer | `/users/12345` | 3+ digits |
| Short integer | `/users/3` | 1-2 digits after ID-like path segment |
| UUID | `/orders/550e8400-e29b-41d4-a716-446655440000` | 8-4-4-4-12 hex |
| Base64 | `?user=MTIzNDU=` | Base64 encoded (decoded as integer) |
| Prefixed | `ORD-001`, `INV-2024-002` | Prefix + digits, year + digits |
| Hash | `?ref=a1b2c3d4e5f6` | Hex string 8+ chars |

## Mutation strategies

| Type | Mutations |
|------|-----------|
| Integer | +1, -1, +2, -2, +5, -5, +10, -10, +100, -100, +1000, -1000 |
| UUID | 3 random UUID v4 values |
| Base64 | Decode, increment, re-encode |
| Prefixed | Keep prefix, change number (ORD-001 → ORD-002) |
| Prefixed (year) | Keep prefix and year (INV-2024-002 → INV-2024-003) |
| Hash | 3 random hex strings of same length |

## Response analysis

| Status | Icon | Description |
|--------|------|-------------|
| CRITICAL | 🚨 | Sensitive data mismatch (email, phone, SSN exposed) |
| HIGH | 🔴 | Different access level between users (admin vs user) |
| WARN | 🟡 | Same response (likely blocked or identical) |
| SAFE | 🟢 | HTTP 401/403 or matches known-safe baseline |
| ERROR | ⚠️ | Request failed |

## Limitations

- **UUID-based IDORs** require a wordlist of valid UUIDs (random guessing won't work)
- **Universal lack of access control** (no auth at all) can't be detected by comparison alone
- **HTTPS MITM** requires installing the idorf CA certificate in your browser
- **Not a Burp replacement** — it's a CLI tool for automating access control testing

## Architecture

```
idorf/
├── cmd/idorf/main.go         ← CLI entrypoint
├── internal/
│   ├── parser/               ← cURL + raw HTTP parsing
│   ├── fuzzer/               ← concurrent request engine
│   ├── session/              ← cookie/token management
│   ├── analyzer/             ← response comparison
│   ├── diff/                 ← semantic JSON diff (ignores CSRF/timestamps)
│   ├── detector/             ← auto-ID detection (int, UUID, base64, prefixed)
│   ├── mutator/              ← ID mutation strategies
│   ├── multisession/         ← multi-user session manager
│   ├── proxy/                ← MITM proxy with auto-ID fuzzing
│   ├── har/                  ← HAR file import
│   └── reporter/             ← terminal, JSON, HTML output
├── Makefile
├── README.md
└── LICENSE
```

## License

MIT