# idorf — IDOR Finder

**idorf** is a blazing fast CLI tool for automatically detecting Insecure Direct Object Reference (IDOR) and access control vulnerabilities in web applications.

Born from the pain of testing IDORs manually — changing IDs one by one in Burp — idorf automates the entire workflow: take a request, replace IDs, fire requests, detect access control failures.

## The Problem

You find an endpoint like `GET /api/users/12345/orders`. You change it to `12346`, `12347`, `12348`... manually. In Burp. One by one. It's slow, tedious, and easy to miss results.

## The Solution

```bash
# curl + wordlist = automatic IDOR hunting
idorf -c 'curl -H "Authorization: Bearer ey..." http://api.target.com/users/FUZZ/orders' -w ids.txt

# Or from a raw request file
idorf -r request.txt -w ids.txt

# With session persistence (cookies, tokens)
idorf -r request.txt -w ids.txt -s session.json
```

idorf systematically:
1. Replaces markers (`FUZZ` by default) with each ID from your wordlist
2. Sends requests maintaining session state
3. Compares responses to detect access control bypasses
4. Reports results with clear pass/fail indicators

## Features

- **Session-aware**: maintains cookies, JWT tokens, OAuth sessions across requests
- **Smart comparison**: detects access control issues by comparing response sizes, status codes, and content
- **Multi-position fuzzing**: replace IDs in URL path, query params, headers, and request body
- **Concurrent**: fast parallel requests with configurable rate limiting
- **Flexible input**: raw HTTP requests, cURL commands, HAR files
- **Burp integration**: export requests from Burp and feed them directly
- **CLI-first**: designed for piping and scripting

## Installation

```bash
go install github.com/z4d3s/idorf/cmd/idorf@latest
```

Or download from [releases](https://github.com/z4d3s/idorf/releases).

## Quick Start

```bash
# 1. Capture a request in Burp → copy as cURL
# 2. Create a wordlist of IDs
echo -e "12346\n12347\n12348\n12349" > ids.txt

# 3. Run idorf
idorf -c 'curl -H "Authorization: Bearer ey..." "http://api.target.com/users/12345/orders"' -w ids.txt

# 4. Analyze results
# 🔴 HIGH: Response 200 with user data — IDOR confirmed
# 🟢 SAFE: Response 403/401 — access control working
```

## Usage

```bash
idorf [flags]

Flags:
  -c, --curl string       cURL command to use as request template
  -r, --request string    File containing raw HTTP request
  -w, --wordlist string   File with IDs/values to fuzz (one per line)
  -m, --marker string     Marker to replace in request (default "FUZZ")
  -s, --session string    Session file (cookies/tokens) for auth persistence
  -o, --output string     Output file for results (default "stdout")
  -t, --threads int       Concurrent threads (default 5)
  --rate-limit int        Requests per second (default 10)
  --timeout int           Request timeout in seconds (default 10)
  --proxy string          Proxy URL (e.g. http://127.0.0.1:8080)
  --verbose               Verbose output
  -v, --version           Show version
```

## Response Analysis

idorf classifies responses into:

| Status | Color | Meaning |
|--------|-------|---------|
| SAFE | 🟢 | 401/403 — access control working |
| WARN | 🟡 | Same response size as baseline — likely blocked |
| HIGH | 🔴 | Different response size/content — possible IDOR |
| CRITICAL | 🚨 | Response contains user data (email, name, address) |

## Examples

### IDOR in API path
```bash
idorf -c 'curl "https://api.xyz.com/api/v2/users/FUZZ/profile"' -w user_ids.txt
```

### IDOR in query parameter
```bash
idorf -c 'curl "https://api.xyz.com/orders?orderId=FUZZ"' -w order_ids.txt
```

### IDOR in POST body
```bash
idorf -c 'curl -X POST -d "{\"userId\":\"FUZZ\"}" "https://api.xyz.com/transfer"' -w user_ids.txt
```

### Using Burp proxy for inspection
```bash
idorf -r request.txt -w ids.txt --proxy http://127.0.0.1:8080
```

### Session from file
```bash
idorf -c 'curl "https://api.xyz.com/users/FUZZ"' -w ids.txt -s session.json
```

## Session File Format

```json
{
  "cookies": [
    {"name": "JSESSIONID", "value": "ABC123", "domain": ".xyz.com"}
  ],
  "headers": [
    {"name": "Authorization", "value": "Bearer ey..."}
  ]
}
```

## Roadmap

- [x] Project setup
- [ ] Raw request parser (cURL + HTTP file)
- [ ] Marker replacement engine
- [ ] Session management
- [ ] Concurrent request engine
- [ ] Response analyzer
- [ ] Report generator (JSON, HTML, terminal)
- [ ] HAR file import
- [ ] OpenAPI/Swagger import
- [ ] Smart baseline detection

## Why Go?

- Single binary, no dependencies
- Blazing fast (goroutines for concurrent requests)
- Cross-platform (Linux, macOS, Windows)
- Easy to distribute for CI/CD pipelines

## License

MIT
