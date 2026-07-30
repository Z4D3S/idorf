// Package session manages authentication state across requests.
package session

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Session holds authentication data for stateful fuzzing.
type Session struct {
	Cookies []Cookie `json:"cookies"`
	Headers []Header `json:"headers"`
	mu      sync.Mutex
}

// Cookie represents an HTTP cookie.
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
}

// Header represents an HTTP header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// New creates a new session from a JSON file.
// If path is empty, returns an empty session.
func New(path string) (*Session, error) {
	if path == "" {
		return &Session{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading session file: %w", err)
	}

	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing session file: %w", err)
	}

	return &s, nil
}

// FromString creates a session from a string of cookies (name=value; name2=value2).
func FromString(cookieStr string) *Session {
	s := &Session{}
	for _, part := range strings.Split(cookieStr, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			s.Cookies = append(s.Cookies, Cookie{
				Name:  strings.TrimSpace(kv[0]),
				Value: strings.TrimSpace(kv[1]),
			})
		}
	}
	return s
}

// ApplyHeaders sets session headers on a headers map.
func (s *Session) ApplyHeaders(headers map[string]string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.Headers {
		headers[h.Name] = h.Value
	}
}

// ToCookieHeader returns Cookie header string from session cookies.
func (s *Session) ToCookieHeader() string {
	if s == nil || len(s.Cookies) == 0 {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var parts []string
	for _, c := range s.Cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// UpdateFromResponse updates session cookies from an HTTP response Set-Cookie headers.
func (s *Session) UpdateFromResponse(resp *http.Response) {
	if s == nil || resp == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, cookie := range resp.Cookies() {
		found := false
		for i, c := range s.Cookies {
			if c.Name == cookie.Name {
				if cookie.Value == "" {
					s.Cookies = append(s.Cookies[:i], s.Cookies[i+1:]...)
				} else {
					s.Cookies[i].Value = cookie.Value
				}
				found = true
				break
			}
		}
		if !found && cookie.Value != "" {
			s.Cookies = append(s.Cookies, Cookie{
				Name:   cookie.Name,
				Value:  cookie.Value,
				Domain: cookie.Domain,
			})
		}
	}
}

// AddHeader adds or replaces a session header.
func (s *Session) AddHeader(name, value string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, h := range s.Headers {
		if h.Name == name {
			s.Headers[i].Value = value
			return
		}
	}
	s.Headers = append(s.Headers, Header{Name: name, Value: value})
}

// AddCookie adds or replaces a session cookie.
func (s *Session) AddCookie(name, value, domain string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, c := range s.Cookies {
		if c.Name == name {
			s.Cookies[i].Value = value
			return
		}
	}
	s.Cookies = append(s.Cookies, Cookie{Name: name, Value: value, Domain: domain})
}

// Save persists the session to a JSON file.
func (s *Session) Save(path string) error {
	if s == nil {
		return fmt.Errorf("nil session")
	}
	if path == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling session: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing session file: %w", err)
	}

	return nil
}

// Clone returns a deep copy of the session.
func (s *Session) Clone() *Session {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	clone := &Session{
		Cookies: make([]Cookie, len(s.Cookies)),
		Headers: make([]Header, len(s.Headers)),
	}
	copy(clone.Cookies, s.Cookies)
	copy(clone.Headers, s.Headers)
	return clone
}

// IsEmpty returns true if the session has no cookies or headers.
func (s *Session) IsEmpty() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Cookies) == 0 && len(s.Headers) == 0
}
