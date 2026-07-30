// Package har parses HTTP Archive (HAR) files for offline replay.
//
// HAR files are exported by browser DevTools, Burp Suite, and other tools.
// idorf imports HAR entries and replays each request across N user sessions,
// allowing you to capture traffic once and analyze it offline with different
// authentication contexts.
package har

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/z4d3s/idorf/internal/parser"
)

// HAR represents the top-level HAR structure.
type HAR struct {
	Log Log `json:"log"`
}

// Log contains the list of entries.
type Log struct {
	Entries []Entry `json:"entries"`
}

// Entry represents a single HTTP request/response pair.
type Entry struct {
	Request  RequestObject  `json:"request"`
	Response ResponseObject `json:"response"`
	Time     float64        `json:"time"`
}

// RequestObject represents an HTTP request in HAR format.
type RequestObject struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	Headers     []HeaderObject `json:"headers"`
	PostData    *PostData      `json:"postData,omitempty"`
	QueryString []QueryParam   `json:"queryString"`
}

// ResponseObject represents an HTTP response in HAR format.
type ResponseObject struct {
	Status  int            `json:"status"`
	Headers []HeaderObject `json:"headers"`
	Content ContentObject  `json:"content"`
}

// HeaderObject represents an HTTP header.
type HeaderObject struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// PostData represents the request body.
type PostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// QueryParam represents a query string parameter.
type QueryParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ContentObject represents the response body.
type ContentObject struct {
	Text     string `json:"text"`
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
}

// Import reads a HAR file and returns a list of parsed requests.
// Filters out non-API requests (images, CSS, JS, fonts, etc.).
func Import(path string, includeStatic bool) ([]*parser.Request, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading HAR file: %w", err)
	}

	var har HAR
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("parsing HAR file: %w", err)
	}

	if len(har.Log.Entries) == 0 {
		return nil, fmt.Errorf("no entries found in HAR file")
	}

	var requests []*parser.Request
	for i, entry := range har.Log.Entries {
		if !includeStatic && isStaticRequest(entry.Request.URL) {
			continue
		}
		if entry.Request.Method == "OPTIONS" || entry.Request.Method == "HEAD" {
			continue
		}

		req := &parser.Request{
			Method:  entry.Request.Method,
			URL:     entry.Request.URL,
			Headers: make(map[string]string),
		}

		// Copy headers
		for _, h := range entry.Request.Headers {
			if strings.ToLower(h.Name) == "cookie" {
				continue // cookies are managed by session
			}
			if strings.ToLower(h.Name) == "authorization" {
				continue // auth is managed by session
			}
			if strings.HasPrefix(strings.ToLower(h.Name), "sec-") {
				continue
			}
			req.Headers[h.Name] = h.Value
		}

		// Copy body
		if entry.Request.PostData != nil && entry.Request.PostData.Text != "" {
			req.Body = entry.Request.PostData.Text
		}

		// Set content type from HAR if present
		for _, h := range entry.Request.Headers {
			if strings.ToLower(h.Name) == "content-type" {
				req.Headers["Content-Type"] = h.Value
				break
			}
		}

		req.Headers["X-idorf-Entry"] = fmt.Sprintf("%d", i)
		requests = append(requests, req)
	}

	if len(requests) == 0 {
		return nil, fmt.Errorf("no API requests found in HAR file (try --include-static)")
	}

	return requests, nil
}

// ImportRequests reads a HAR file and returns structured request data for replay.
func ImportRequests(path string, includeStatic bool) ([]*parser.Request, error) {
	return Import(path, includeStatic)
}

// isStaticRequest checks if a URL is likely a static resource.
func isStaticRequest(url string) bool {
	lower := strings.ToLower(url)
	staticExtensions := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".webp", ".mp4", ".webm",
		".pdf", ".zip", ".gz", ".tar",
	}
	for _, ext := range staticExtensions {
		if strings.Contains(lower, ext) {
			return true
		}
	}

	staticKeywords := []string{
		"google-analytics", "googletagmanager", "facebook.net", "doubleclick",
		"hotjar", "cdn.", "/static/", "/assets/", "/fonts/", "/images/",
	}
	for _, kw := range staticKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}

	return false
}

// Count returns the number of entries in a HAR file.
func Count(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var har HAR
	if err := json.Unmarshal(data, &har); err != nil {
		return 0, err
	}
	return len(har.Log.Entries), nil
}
