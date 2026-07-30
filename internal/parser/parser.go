// Package parser parses raw HTTP requests and cURL commands into structured requests.
package parser

import (
	"fmt"
	"net/url"
	"strings"
)

// Request represents a parsed HTTP request ready for fuzzing.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// ParseCurl parses a cURL command string into a Request.
func ParseCurl(cmd string) (*Request, error) {
	// TODO: implement cURL parsing
	return nil, fmt.Errorf("not implemented")
}

// ParseRaw parses a raw HTTP request string into a Request.
func ParseRaw(raw string) (*Request, error) {
	// TODO: implement raw HTTP parsing
	return nil, fmt.Errorf("not implemented")
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

// ToURL returns the parsed URL.
func (r *Request) ToURL() (*url.URL, error) {
	return url.Parse(r.URL)
}
