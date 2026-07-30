# idorf

**IDOR Runner** — A CLI tool for detecting Insecure Direct Object Reference and access control vulnerabilities.

`idorf` automates the most tedious part of access control testing: sending requests with different user sessions and comparing responses. It does not replace human analysis — it makes it faster.

## Features

- **Multi-session mode**: send the same request with N different user tokens and compare responses side-by-side
- **Semantic JSON diff**: detects structural changes in JSON responses (key added/removed/changed), not just size or status code
- **Concurrent engine**: parallel requests with configurable rate limiting
- **Session management**: auto-updates cookies from `Set-Cookie` headers
- **Custom patterns**: regex-based sensitive data detection
- **Known-IDs baseline**: mark your own IDs as safe to reduce false positives
- **Flexible input**: cURL commands, raw HTTP, Burp exports, HAR files (planned)
- **JSON export**: machine-readable output for CI/CD pipelines

## Installation

```bash
go install github.com/z4d3s/idorf/cmd/idorf@latest
```

Or build from source:

```bash
git clone https://github.com/z4d3s/idorf
cd idorf
make build
```

## Usage

### Single-session mode (fuzzing one auth context)

```bash
idorf -c 'curl "http://target.com/api/users/FUZZ/profile"' -w ids.txt
```

### Multi-session mode (the killer feature)

Test the same endpoint with multiple users to find access control issues:

```bash
idorf -c 'curl "http://target.com/api/admin/users"' \
  --users "admin:Bearer token123,user:Bearer token456,anon:"
```

This sends the request with each user's token and compares the responses:

```
── ACCESS CONTROL DIFFERENCES ──────────────────
🔴 [HIGH] ID: admin vs user
   admin:    HTTP 200, 512 bytes  ← sees data
   user:     HTTP 403, 22 bytes   ← blocked  
   anon:     HTTP 401, 25 bytes   ← unauthenticated
   Diff: new fields exposed (access gain), 3 other changes
```

### Known-IDs baseline

Mark your own account IDs as safe to reduce false positives:

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
# Create session file
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
| `--users` | `""` | Multi-session mode: `name:token,name:token` |
| `--users-file` | `""` | JSON file with user sessions |
| `-o` | `""` | Output file for JSON results |
| `-t` | `5` | Concurrent threads |
| `--rate-limit` | `10` | Requests per second |
| `--timeout` | `10` | Request timeout in seconds |
| `--proxy` | `""` | Proxy URL |
| `--diff-pattern` | `""` | Custom regex for sensitive data |
| `--known-ids` | `""` | Comma-separated known-safe IDs |
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

## Response analysis

| Status | Icon | Description |
|--------|------|-------------|
| CRITICAL | 🚨 | Semantic diff found sensitive data mismatch |
| HIGH | 🔴 | Different status code or access level |
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
│   ├── diff/                 ← Semantic JSON diff engine
│   ├── multisession/         ← Multi-user session manager
│   └── reporter/             ← Terminal + JSON output
├── Makefile
├── README.md
└── LICENSE
```

## Roadmap

- [x] cURL and raw HTTP parsing
- [x] Concurrent request engine
- [x] Session management (cookies, auto-update)
- [x] Semantic JSON diff engine
- [x] Multi-session comparison mode
- [x] Known-IDs baseline
- [x] Custom diff patterns
- [ ] Auto-ID detection (int, UUID, base64, JWT)
- [ ] Proxy mode for live traffic replay
- [ ] ID mutation strategies
- [ ] HAR file import
- [ ] OpenAPI/Swagger spec import
- [ ] HTML report
- [ ] CI/CD pipeline integration

## License

MIT — see [LICENSE](LICENSE)