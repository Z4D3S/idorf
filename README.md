# idorf

<p align="center">
  <img src="https://img.shields.io/badge/version-0.5.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/github/license/Z4D3S/idorf?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/go-%3E%3D1.21-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" alt="PRs">
</p>

**idorf** — IDOR Runner. A CLI tool for detecting Insecure Direct Object Reference and access control vulnerabilities.

```bash
# Proxy mode: browse the target normally, idorf detects access control issues
idorf --proxy-mode --users "admin:Bearer tok1,user:Bearer tok2,anon:"

# Auto-detect: point at any endpoint, idorf finds IDs and fuzzes them
idorf -c 'curl "http://target.com/api/users/123/profile"' --auto

# Multi-session: compare responses across N users
idorf -c 'curl "http://target.com/api/admin/users"' \
  --users "admin:Bearer tok1,user:Bearer tok2,anon:"
```

## Features

| Feature | Description |
|---------|-------------|
| **Proxy mode** | Intercept HTTP traffic and replay each request with N user sessions |
| **Auto-detect** | Automatically finds IDs (int, UUID, base64, hash) in URLs, query params, and body |
| **ID mutations** | Generates smart mutations: sequential (+/-1..1000), random UUID, base64 decode/re-encode |
| **Multi-session** | Compare responses across multiple users side by side |
| **Semantic diff** | JSON structural comparison (key added/removed/changed, array size, nested objects) |
| **Session management** | Auto-updates cookies from Set-Cookie headers |
| **Custom patterns** | Regex-based sensitive data detection (email, phone, credit card, etc.) |
| **Known-IDs baseline** | Mark your own IDs as safe to reduce false positives |
| **Concurrent engine** | Parallel requests with configurable rate limiting |
| **Flexible input** | cURL commands, raw HTTP, HAR (planned) |
| **JSON export** | Machine-readable output for CI/CD pipelines |

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

### Proxy mode (recommended)

Browse the target normally. idorf replays each request with N user sessions and detects access control differences.

```bash
idorf --proxy-mode --proxy-listen 127.0.0.1:8081 \
  --users "admin:Bearer admin-token,user:Bearer user-token,anon:"
```

Configure your browser to use `127.0.0.1:8081` as HTTP proxy. Browse the target. idorf shows:
```
🔴 [HIGH] GET http://api.target.com/users/123/profile
 alice:200/512 charlie:403/22 anon:401/25
   alice got 200 but charlie got 403alice got 200 but charlie got 403
```

Press Ctrl+C to see the full summary.

### Auto-detect mode

idorf scans the request for IDs and generates mutations automatically:

```bash
idorf -c 'curl "http://target.com/api/users/123/profile"' --auto

```

Output:
```
[+] Auto-detect: found 1 IDs
    integer: 123 (url) at url.path[5]
[+] Auto-detect: generated 12 mutations
```

This replaces the ID with FUZZ, generates mutations as wordlist, and starts fuzzing.

### Fuzzing mode (classic)

```bash
idorf -c 'curl "http://target.com/api/users/FUZZ/profile"' -w ids.txt
```

### Multi-session comparison

```bash
idorf -c 'curl -H "Authorization: Bearer FUZZ" "http://target.com/api/orders/123"' \
  --users "admin:Bearer admin-token,user:Bearer user-token,anon:"
```

### Known-IDs baseline

```bash
idorf -c 'curl "http://target.com/api/users/FUZZ"' -w ids.txt --known-ids 1,2,3
```

### Custom sensitive data patterns

```bash
idorf -c 'curl "http://target.com/api/users/FUZZ"' -w ids.txt \
  --diff-pattern 'credit_card|ssn|api_key'
```

### Session persistence

```bash
echo '{"cookies":[{"name":"JSESSIONID","value":"ABC123","domain":".target.com"}],
       "headers":[{"name":"Authorization","value":"Bearer ey..."}]}' > session.json

idorf -c 'curl "http://target.com/api/users/FUZZ"' -w ids.txt -s session.json
```

### Proxy debugging

```bash
idorf -c 'curl "http://target.com/api/users/FUZZ"' -w ids.txt --proxy http://127.0.0.1:8080
```

### JSON export

```bash
idorf -c 'curl "http://target.com/api/users/FUZZ"' -w ids.txt -o results.json
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | `""` | cURL command to use as request template |
| `-r` | `""` | File containing raw HTTP request |
| `-w` | `""` | Wordlist with values to fuzz (one per line) |
| `-m` | `"FUZZ"` | Marker to replace in request |
| `-s` | `""` | Session file (cookies/tokens) |
| `--proxy-mode` | `false` | Start proxy mode for live traffic capture and replay |
| `--proxy-listen` | `127.0.0.1:8081` | Proxy listen address |
| `-o` | `""` | Output file for JSON results |
| `-t` | `5` | Concurrent threads |
| `--rate-limit` | `10` | Requests per second |
| `--timeout` | `10` | Request timeout in seconds |
| `--proxy` | `""` | Outbound proxy URL |
| `--diff-pattern` | `""` | Custom regex for sensitive data |
| `--known-ids` | `""` | Comma-separated known-safe IDs |
| `--users` | `""` | Multi-session: `name:token,name:token` |
| `--users-file` | `""` | JSON file with user sessions |
| `--auto` | `false` | Auto-detect IDs and generate mutations |
| `--verbose` | `false` | Verbose output |
| `-v` | `false` | Show version |

## Users file format

```json
{
  "users": [
    {
      "name": "admin",
      "headers": [{"name": "Authorization", "value": "Bearer admin-token"}]
    },
    {
      "name": "user",
      "cookies": [{"name": "session", "value": "abc123", "domain": ".target.com"}],
      "headers": [{"name": "X-CSRF", "value": "xyz"}]
    },
    {
      "name": "anon",
      "headers": []
    }
  ]
}
```

## ID detection patterns

| Type | Example | Pattern |
|------|---------|---------|
| Integer | `/users/12345` | 3+ digits |
| Short integer | `/users/3` | 1-2 digits after ID-like path segment |
| UUID | `/orders/550e8400-e29b-41d4-a716-446655440000` | 8-4-4-4-12 hex |
| Base64 | `?user=MTIzNDU=` | Decoded as integer, mutated |
| Prefixed | `ORD-001`, `CUST-2024-001` | Alpha prefix + digits |
| Hash | `?ref=a1b2c3d4e5f6` | Hex string 8+ chars |

## ID mutation strategies

| Type | Mutations |
|------|-----------|
| Integer | +1, -1, +2, -2, +5, -5, +10, -10, +100, -100, +1000, -1000 |
| UUID | 3 random UUID v4 values |
| Base64 | Decode integer, mutate, re-encode |
| Prefixed | Keep prefix (ORD-), mutate digits (001 -> 002, 003, etc.) |
| Hash | 3 random hex strings of same length |

## Response analysis

| Status | Icon | Description |
|--------|------|-------------|
| CRITICAL | 🚨 | Sensitive data mismatch detected (email, phone, etc.) |
| HIGH | 🔴 | Different status code or access level between users |
| WARN | 🟡 | Same response — likely blocked or identical |
| SAFE | 🟢 | HTTP 401/403 or matches known-safe baseline |
| ERROR | ⚠️ | Request failed (timeout, connection error) |

## Architecture

```
idorf/
├── cmd/idorf/main.go         ← CLI entrypoint
├── internal/
│   ├── parser/               ← Parse cURL and raw HTTP
│   ├── fuzzer/               ← Concurrent request engine
│   ├── session/              ← Cookie/token management
│   ├── analyzer/             ← Response comparison
│   ├── diff/                 ← Semantic JSON diff
│   ├── detector/             ← Auto-ID detection
│   ├── mutator/              ← ID mutation strategies
│   ├── multisession/         ← Multi-user manager
│   ├── proxy/                ← MITM proxy
│   └── reporter/             ← Terminal + JSON output
├── Makefile
├── README.md
└── LICENSE
```

## Roadmap

- [x] cURL and raw HTTP parsing
- [x] Concurrent request engine
- [x] Session management (cookies, auto-update)
- [x] Semantic JSON diff
- [x] Multi-session comparison
- [x] Known-IDs baseline
- [x] Custom diff patterns
- [x] Proxy mode (MITM with N users)
- [x] Auto-ID detection (int, UUID, base64, hash, prefixed)
- [x] ID mutation strategies
- [x] Proxy HTTPS MITM support
- [ ] CSRF/nonce filtering (ignore dynamic fields)
- [ ] OpenAPI/Swagger spec import
- [ ] HTML report
- [ ] CI/CD pipeline integration

## License

MIT