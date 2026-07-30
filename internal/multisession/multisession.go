// Package multisession manages multiple user sessions for comparative IDOR testing.
//
// The core idea: send the SAME request with N different auth tokens,
// then compare the responses. If user A sees user B's data, that's an IDOR.
package multisession

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/z4d3s/idorf/internal/diff"
	"github.com/z4d3s/idorf/internal/session"
)

// UserSession represents a named user with their auth session.
type UserSession struct {
	Name    string `json:"name"`
	Session *session.Session
}

// ComparisonResult holds the result of comparing one user's response against another.
type ComparisonResult struct {
	UserA        string      `json:"user_a"`
	UserB        string      `json:"user_b"`
	Value        string      `json:"value"` // The fuzzed ID value
	DiffResult   diff.Result `json:"diff"`
	StatusA      int         `json:"status_a"`
	StatusB      int         `json:"status_b"`
	IsVulnerable bool        `json:"is_vulnerable"`
	Confidence   string      `json:"confidence"`
	Reason       string      `json:"reason"`
}

// MultiResult holds results for a single fuzzed value across all users.
type MultiResult struct {
	Value        string             `json:"value"`
	Responses    map[string]int     `json:"responses"`  // user -> HTTP status
	BodySizes    map[string]int     `json:"body_sizes"` // user -> body size
	Bodies       map[string]string  `json:"bodies"`     // user -> response body
	Comparisons  []ComparisonResult `json:"comparisons"`
	IsVulnerable bool               `json:"is_vulnerable"`
	Confidence   string             `json:"confidence"`
	Reason       string             `json:"reason"`
}

// Manager handles multiple user sessions.
type Manager struct {
	Users      []UserSession
	diffEngine *diff.Engine
	mu         sync.Mutex
}

// NewManager creates a new multi-session manager.
func NewManager() *Manager {
	return &Manager{
		diffEngine: diff.NewEngine(),
	}
}

// AddUser adds a named user session to the manager.
func (m *Manager) AddUser(name string, sess *session.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Users = append(m.Users, UserSession{Name: name, Session: sess})
}

// LoadUsersFromFile loads user sessions from a JSON file.
//
// File format:
//
//	{
//	  "users": [
//	    {"name": "admin", "cookies": [...], "headers": [{"name": "Authorization", "value": "Bearer admin-token"}]},
//	    {"name": "user1", "headers": [{"name": "Authorization", "value": "Bearer user1-token"}]},
//	    {"name": "anon", "headers": []}
//	  ]
//	}
func LoadUsersFromFile(path string) (*Manager, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading users file: %w", err)
	}

	var config struct {
		Users []struct {
			Name    string           `json:"name"`
			Cookies []session.Cookie `json:"cookies"`
			Headers []session.Header `json:"headers"`
		} `json:"users"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing users file: %w", err)
	}

	mgr := NewManager()
	for _, u := range config.Users {
		sess := &session.Session{
			Cookies: u.Cookies,
			Headers: u.Headers,
		}
		mgr.AddUser(u.Name, sess)
	}

	return mgr, nil
}

// ParseUsersFlag parses a --users flag value like:
//
//	"admin:Bearer admin-token,user1:Bearer user1-token,anon:"
//
// Each entry is name:header-value. The header name is "Authorization" by default.
func ParseUsersFlag(flag string) (*Manager, error) {
	if flag == "" {
		return nil, fmt.Errorf("empty users flag")
	}

	mgr := NewManager()
	entries := strings.Split(flag, ",")
	for _, entry := range entries {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid user entry: %s (expected name:value)", entry)
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		sess := &session.Session{}
		if value != "" {
			sess.AddHeader("Authorization", value)
		}
		mgr.AddUser(name, sess)
	}

	return mgr, nil
}

// CompareResponses compares two users' responses for the same fuzzed value.
func (m *Manager) CompareResponses(userA, userB string, value string, statusA, statusB int, bodyA, bodyB string) ComparisonResult {
	result := ComparisonResult{
		UserA:      userA,
		UserB:      userB,
		Value:      value,
		StatusA:    statusA,
		StatusB:    statusB,
		DiffResult: m.diffEngine.Diff(bodyA, bodyB),
	}

	// Determine vulnerability
	switch {
	case statusA == 200 && statusB == 403:
		result.IsVulnerable = true
		result.Confidence = "high"
		result.Reason = fmt.Sprintf("%s got 200 but %s got 403", userA, userB)

	case statusA == 200 && statusB == 401:
		result.IsVulnerable = true
		result.Confidence = "high"
		result.Reason = fmt.Sprintf("%s got 200 but %s got 401", userA, userB)

	case statusA == 403 && statusB == 200:
		result.IsVulnerable = true
		result.Confidence = "high"
		result.Reason = fmt.Sprintf("%s got 403 but %s got 200", userA, userB)

	case statusA == 200 && statusB == 200:
		if result.DiffResult.HasDataLeak {
			result.IsVulnerable = true
			result.Confidence = "critical"
			result.Reason = fmt.Sprintf("both 200 but different sensitive data: %s", result.DiffResult.Summary)
		} else if result.DiffResult.HasAccessGain {
			result.IsVulnerable = true
			result.Confidence = "high"
			result.Reason = fmt.Sprintf("both 200 but %s has extra fields: %s", userB, result.DiffResult.Summary)
		} else if statusA == statusB && bodyA != bodyB {
			result.IsVulnerable = true
			result.Confidence = "warn"
			result.Reason = "both 200, different content"
		}

	case statusA == 403 && statusB == 403:
		result.IsVulnerable = false
		result.Confidence = "safe"
		result.Reason = "both blocked"
	}

	return result
}

// BuildMultiResult creates a MultiResult from per-user responses.
func (m *Manager) BuildMultiResult(value string, responses map[string]int, bodies map[string]string) MultiResult {
	result := MultiResult{
		Value:       value,
		Responses:   responses,
		BodySizes:   make(map[string]int),
		Bodies:      bodies,
		Comparisons: []ComparisonResult{},
	}

	// Record body sizes
	for user, body := range bodies {
		result.BodySizes[user] = len(body)
	}

	// Compare all pairs of users
	userNames := make([]string, 0, len(responses))
	for name := range responses {
		userNames = append(userNames, name)
	}

	for i := 0; i < len(userNames); i++ {
		for j := i + 1; j < len(userNames); j++ {
			a, b := userNames[i], userNames[j]
			comp := m.CompareResponses(a, b, value, responses[a], responses[b], bodies[a], bodies[b])
			result.Comparisons = append(result.Comparisons, comp)
			if comp.IsVulnerable {
				result.IsVulnerable = true
				if comp.Confidence == "critical" {
					result.Confidence = "critical"
				} else if result.Confidence == "" {
					result.Confidence = comp.Confidence
				}
				if result.Reason == "" {
					result.Reason = comp.Reason
				}
			}
		}
	}

	if !result.IsVulnerable {
		result.Confidence = "safe"
		result.Reason = "no access control differences detected"
	}

	return result
}

// GetUserCount returns the number of configured users.
func (m *Manager) GetUserCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Users)
}

// GetUserSession returns the session for a named user.
func (m *Manager) GetUserSession(name string) *session.Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.Users {
		if u.Name == name {
			return u.Session
		}
	}
	return nil
}

// GetUserNames returns the names of all configured users.
func (m *Manager) GetUserNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, len(m.Users))
	for i, u := range m.Users {
		names[i] = u.Name
	}
	return names
}
