// Package parser parses raw HTTP requests and cURL commands into structured requests.
package parser

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Request represents a parsed HTTP request ready for fuzzing.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// NewRequest creates a new Request with default values.
func NewRequest() *Request {
	return &Request{
		Method:  "GET",
		Headers: make(map[string]string),
	}
}

// ParseCurl parses a cURL command string into a Request.
// Supports: -X, -H, -d/--data/--data-raw, URL, -k, --compressed (ignored).
// Handles both single and double quoted strings.
func ParseCurl(cmd string) (*Request, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil, fmt.Errorf("empty cURL command")
	}

	if !strings.HasPrefix(cmd, "curl") {
		return nil, fmt.Errorf("not a cURL command (must start with 'curl')")
	}

	cmd = strings.TrimPrefix(cmd, "curl")

	tokens, err := tokenizeCurl(cmd)
	if err != nil {
		return nil, fmt.Errorf("tokenizing cURL: %w", err)
	}

	req := NewRequest()
	headers := make(map[string]string)
	var dataFlag string

	i := 0
	for i < len(tokens) {
		tok := tokens[i]

		switch {
		case tok == "-X":
			if i+1 < len(tokens) {
				req.Method = strings.ToUpper(tokens[i+1])
				i += 2
			} else {
				return nil, fmt.Errorf("-X requires a value")
			}

		case tok == "-H" || tok == "--header":
			if i+1 < len(tokens) {
				parseHeader(headers, tokens[i+1])
				i += 2
			} else {
				return nil, fmt.Errorf("-H requires a value")
			}

		case tok == "-d" || tok == "--data" || tok == "--data-raw" || tok == "--data-binary":
			if i+1 < len(tokens) {
				if dataFlag == "" {
					dataFlag = tokens[i+1]
					if headers["Content-Type"] == "" {
						headers["Content-Type"] = "application/x-www-form-urlencoded"
					}
					if req.Method == "GET" || req.Method == "HEAD" {
						req.Method = "POST"
					}
				}
				i += 2
			} else {
				return nil, fmt.Errorf("%s requires a value", tok)
			}

		case tok == "-k" || tok == "--insecure":
			i++

		case tok == "--compressed":
			i++

		case tok == "-s" || tok == "-S" || tok == "--silent" || tok == "--show-error":
			i++

		case tok == "-o" || tok == "--output":
			i += 2

		case tok == "-A" || tok == "--user-agent":
			if i+1 < len(tokens) {
				headers["User-Agent"] = tokens[i+1]
				i += 2
			} else {
				return nil, fmt.Errorf("-A requires a value")
			}

		case tok == "--path-as-is":
			i++

		case strings.HasPrefix(tok, "-"):
			i++

		default:
			t := strings.Trim(tok, "'\"")
			if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
				if req.URL == "" {
					req.URL = t
				}
			}
			i++
		}
	}

	if req.URL == "" {
		return nil, fmt.Errorf("no URL found in cURL command")
	}

	req.Headers = headers
	if dataFlag != "" {
		req.Body = dataFlag
	}

	return req, nil
}

// tokenizeCurl splits a cURL command into tokens, respecting quotes.
// Handles single quotes, double quotes, and escaped characters.
func tokenizeCurl(cmd string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	var insideSingle, insideDouble, escaped bool

	for _, ch := range cmd {
		switch {
		case escaped:
			current.WriteRune(ch)
			escaped = false

		case ch == '\\' && !insideSingle:
			escaped = true

		case ch == '\'' && !insideDouble:
			insideSingle = !insideSingle

		case ch == '"' && !insideSingle:
			insideDouble = !insideDouble

		case (ch == ' ' || ch == '\t') && !insideSingle && !insideDouble:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}

		default:
			current.WriteRune(ch)
		}
	}

	if insideSingle || insideDouble {
		return nil, fmt.Errorf("unclosed quote in cURL command")
	}

	if escaped {
		return nil, fmt.Errorf("dangling escape in cURL command")
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}

// parseHeader parses a single HTTP header value like "Content-Type: application/json".
func parseHeader(headers map[string]string, h string) {
	parts := strings.SplitN(h, ":", 2)
	if len(parts) == 2 {
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(strings.Trim(parts[1], "'\""))
		if key != "" {
			headers[key] = val
		}
	}
}

// ParseRaw parses a raw HTTP request string into a Request.
// Expected format:
//
//	POST /api/v1/orders HTTP/1.1
//	Host: api.example.com
//	Content-Type: application/json
//
//	{"userId": "12345"}
func ParseRaw(raw string) (*Request, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty request")
	}

	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("no lines in request")
	}

	req := NewRequest()

	// Parse request line: METHOD PATH HTTP/1.1
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", lines[0])
	}
	req.Method = parts[0]

	// Parse headers
	headerEnd := len(lines)
	bodyStart := len(lines)
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			bodyStart = i + 1
			break
		}
		parseHeader(req.Headers, lines[i])
	}
	_ = headerEnd

	// Extract host and build full URL
	host := req.Headers["Host"]
	if host == "" {
		host = "localhost"
	}
	path := parts[1]

	scheme := "https"
	if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
		scheme = "http"
	}

	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		req.URL = path
	} else {
		req.URL = fmt.Sprintf("%s://%s%s", scheme, host, path)
	}

	// Extract body if present
	if bodyStart < len(lines) {
		body := strings.Join(lines[bodyStart:], "\n")
		body = strings.TrimSpace(body)
		if body != "" {
			req.Body = body
		}
	}

	return req, nil
}

// ReplaceMarker replaces all occurrences of marker in the request.
func (r *Request) ReplaceMarker(marker, replacement string) *Request {
	r.URL = strings.ReplaceAll(r.URL, marker, replacement)
	r.Body = strings.ReplaceAll(r.Body, marker, replacement)
	for k, v := range r.Headers {
		r.Headers[k] = strings.ReplaceAll(v, marker, replacement)
	}
	return r
}

// ContainsMarker checks if the request contains the marker.
func (r *Request) ContainsMarker(marker string) bool {
	if strings.Contains(r.URL, marker) {
		return true
	}
	if strings.Contains(r.Body, marker) {
		return true
	}
	for _, v := range r.Headers {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

// ToURL returns the parsed URL.
func (r *Request) ToURL() (*url.URL, error) {
	return url.Parse(r.URL)
}

// String returns a human-readable representation of the request.
func (r *Request) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s\n", r.Method, r.URL))
	for k, v := range r.Headers {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	if r.Body != "" {
		sb.WriteString(fmt.Sprintf("\n%s\n", r.Body))
	}
	return sb.String()
}

// Clone returns a deep copy of the request.
func (r *Request) Clone() *Request {
	clone := &Request{
		Method:  r.Method,
		URL:     r.URL,
		Body:    r.Body,
		Headers: make(map[string]string),
	}
	for k, v := range r.Headers {
		clone.Headers[k] = v
	}
	return clone
}

// HasMarkerInURL checks if the marker is in the URL only.
func (r *Request) HasMarkerInURL(marker string) bool {
	return strings.Contains(r.URL, marker)
}

// MarkerPositions returns the locations where the marker appears.
type MarkerPositions struct {
	InURL     bool
	InBody    bool
	InHeaders []string
}

// GetMarkerPositions returns where the marker appears in the request.
func (r *Request) GetMarkerPositions(marker string) MarkerPositions {
	pos := MarkerPositions{
		InURL:  strings.Contains(r.URL, marker),
		InBody: strings.Contains(r.Body, marker),
	}
	for k, v := range r.Headers {
		if strings.Contains(v, marker) {
			pos.InHeaders = append(pos.InHeaders, k)
		}
	}
	return pos
}

// StripDataPrefix removes the leading $ prefix from shell-expanded data strings.
var shellVarRegex = regexp.MustCompile(`^\$'`)
