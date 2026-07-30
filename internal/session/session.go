// Package session manages authentication state across requests.
package session

import (
	"encoding/json"
	"fmt"
	"os"
)

// Session holds authentication data for stateful fuzzing.
type Session struct {
	Cookies []Cookie `json:"cookies"`
	Headers []Header `json:"headers"`
	storage Storage
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

// Storage handles session persistence.
type Storage interface {
	Save(*Session) error
	Load() (*Session, error)
}

type fileStorage struct {
	path string
}

// New creates a new session from a file.
func New(path string) (*Session, error) {
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

// ApplyHeaders sets session headers on a headers map.
func (s *Session) ApplyHeaders(headers map[string]string) {
	for _, h := range s.Headers {
		headers[h.Name] = h.Value
	}
}

// ToCookieHeader returns Cookie header string.
func (s *Session) ToCookieHeader() string {
	var result string
	for i, c := range s.Cookies {
		if i > 0 {
			result += "; "
		}
		result += c.Name + "=" + c.Value
	}
	return result
}
