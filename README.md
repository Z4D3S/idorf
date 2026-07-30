# idorf

A fast CLI tool for running IDOR (Insecure Direct Object Reference) and access control tests at scale.

`idorf` is not a magic scanner that finds bugs for you. It is a **concurrent IDOR runner** that automates the most tedious part of access control testing: replacing markers in requests, firing hundreds of authenticated requests in parallel, maintaining session state, and highlighting responses that differ from the baseline.

## Why

Testing IDORs manually looks like this:

1. Capture a request in Burp: `GET /api/users/12345/orders`
2. Change `12345` to `12346`
3. Send it
4. Compare the response with the original
5. Repeat for `12347`, `12348`, `12349`, `12350`...

This is slow. `idorf` does it in one command:

```bash
idorf -c 'curl -H "Authorization: Bearer ey..." "http://api.target.com/users/FUZZ/orders"' -w ids.txt
```

## What it does

- Parses cURL commands and raw HTTP requests (Burp export)
- Replaces a marker (`FUZZ` by default) in URL, headers, and body
- Fires requests concurrently with rate limiting
- Maintains session state (cookies, auth headers) across requests
- Updates cookies from `Set-Cookie` headers automatically
- Compares responses against a baseline to flag differences
- Detects sensitive data patterns (email, phone, address, etc.)
- Outputs results in terminal or JSON

## What it does NOT do

- It will not log in for you (yet)
- It will not bypass WAFs or rate limits
- It will not magically know which response is a real IDOR vs a generic 200 error
- It does not replace human analysis — it makes it faster

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

```bash
idorf [flags]

Flags:
  -c, --curl string        cURL command to use as request template
  -r, --request string     File containing raw HTTP request
  -w, --wordlist string    File with IDs/values to fuzz (one per line)
  -m, --marker string      Marker to replace (default "FUZZ")
  -s, --session string     Session file (cookies/tokens) for auth persistence
  -o, --output string      Output file for JSON results (default stdout)
  -t, --threads int        Concurrent threads (default 5)
      --rate-limit int    Requests per second (default 10)
      --timeout int       Request timeout in seconds (default 10)
      --proxy string       Proxy URL (e.g. http://127.0.0.1:8080)
      --diff-pattern string  Custom regex to detect sensitive data (default: email|phone|address|password|token|ssn)
  --known-ids string      Comma-separated IDs that are safe (used as baseline)
      --verbose            Verbose output
  -v, --version           Show version
```

## Examples

### Basic IDOR test
```bash
# Wordlist of user IDs
echo -e "12346\n12347\n12348" > ids.txt

# Run idorf
idorf -c 'curl -H "Authorization: Bearer ey..." "http://api.target.com/users/FUZZ/profile"' -w ids.txt
```

### Use Burp proxy to inspect traffic
```bash
idorf -c 'curl "http://api.target.com/users/FUZZ"' -w ids.txt --proxy http://127.0.0.1:8080
```

### Session persistence (cookies auto-updated)
```bash
# Create session file
echo '{"cookies":[{"name":"JSESSIONID","value":"ABC123","domain":".target.com"}],
       "headers":[{"name":"Authorization","value":"Bearer ey..."}]}' > session.json

# Run with session
idorf -c 'curl "http://api.target.com/users/FUZZ/orders"' -w ids.txt -s session.json

# Session is updated and saved back (new cookies from responses)
```

### Custom sensitive data patterns
```bash
# Add your own patterns to detect in responses
idorf -c 'curl "http://api.target.com/users/FUZZ"' -w ids.txt \
  --diff-pattern 'credit_card|ssn|api_key|private_key'
```

### Specify known IDs as baseline
```bash
# IDs 1 and 2 are known to be safe (your own accounts)
idorf -c 'curl "http://api.target.com/users/FUZZ"' -w ids.txt --known-ids 1,2
```

### POST body IDOR
```bash
idorf -c 'curl -X POST -d "{\"userId\":\"FUZZ\"}" "http://api.target.com/transfer"' -w ids.txt
```

### Export results to JSON
```bash
idorf -c 'curl "http://api.target.com/users/FUZZ"' -w ids.txt -o results.json
```

## Session File Format

```json
{
  "cookies": [
    {"name": "JSESSIONID", "value": "ABC123", "domain": ".target.com"},
    {"name": "session", "value": "XYZ789", "domain": ".target.com"}
  ],
  "headers": [
    {"name": "Authorization", "value": "Bearer ey..."},
    {"name": "X-CSRF-Token", "value": "abc123"}
  ]
}
```

## Response Analysis

idorf compares each response against a baseline (first response by default) and flags:

| Status | Icon | Description |
|--------|------|-------------|
| CRITICAL | 🚨 | Response contains sensitive data patterns (email, phone, etc.) |
| HIGH | 🔴 | Different status code or response size from baseline |
| WARN | 🟡 | Same size and status as baseline (likely blocked, needs manual check) |
| SAFE | 🟢 | HTTP 401/403 (access control working) |
| ERROR | ⚠️ | Request failed (timeout, connection error) |

## Roadmap

- [x] cURL and raw HTTP parsing
- [x] Concurrent request engine with rate limiting
- [x] Session management (cookies, headers, auto-update)
- [x] Baseline comparison analyzer
- [x] JSON and terminal output
- [x] Custom diff patterns
- [x] Known IDs baseline specification
- [ ] Login subcommand for auth flows
- [ ] Pipeline mode (multi-step: login -> create resource -> fuzz)
- [ ] HAR file import
- [ ] OpenAPI/Swagger spec import
- [ ] Smart false-positive filtering
- [ ] HTML report

## License

MIT