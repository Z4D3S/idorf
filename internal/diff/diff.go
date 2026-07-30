// Package diff provides semantic JSON comparison for IDOR detection.
//
// Instead of comparing response sizes or status codes (which produce false positives),
// the diff engine parses JSON responses and compares them structurally:
//   - Which keys are present in one response but not the other
//   - Which values differ between responses
//   - Which arrays have different lengths or elements
//
// This is the key innovation: detecting that "email" changed from "alice@x.com"
// to "bob@x.com" is much more meaningful than "size changed by 4 bytes".
package diff

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Change represents a single difference between two JSON values.
type Change struct {
	Path        string `json:"path"`
	Type        string `json:"type"` // "added", "removed", "changed", "array_grew", "array_shrank"
	Expected    string `json:"expected,omitempty"`
	Actual      string `json:"actual,omitempty"`
	Sensitive   bool   `json:"sensitive"` // true if the path matches sensitive patterns
	Description string `json:"description"`
}

// Result holds the complete diff between two responses.
type Result struct {
	Changes       []Change `json:"changes"`
	HasDataLeak   bool     `json:"has_data_leak"`   // true if different user data found
	HasAccessGain bool     `json:"has_access_gain"` // true if access was gained (new keys)
	Summary       string   `json:"summary"`
	Score         int      `json:"score"` // 0-100, higher = more likely IDOR
}

// Engine performs semantic diffs between JSON responses.
type Engine struct {
	SensitiveKeys   []string // keys that suggest personal/sensitive data
	IgnoredPrefixes []string // paths to ignore (e.g. "timestamp", "nonce", "csrf")
}

// NewEngine creates a diff engine with default sensitive key patterns
// and common volatile field prefixes (CSRF tokens, timestamps, etc.).
func NewEngine() *Engine {
	return &Engine{
		SensitiveKeys: []string{
			"email", "mail", "address", "street", "city", "postal", "zip",
			"phone", "mobile", "telephone", "name", "first_name", "last_name",
			"full_name", "username", "user", "customer", "account",
			"credit", "card", "cvv", "cvc", "pan", "ssn", "social",
			"password", "secret", "token", "api_key", "apikey",
			"dob", "date_of_birth", "birthday", "national_id", "passport",
			"balance", "iban", "account_number", "order", "transaction",
			"role", "admin", "permissions", "is_admin", "privileges",
		},
		IgnoredPrefixes: []string{
			// CSRF / tokens
			"csrf", "_csrf", "csrf_token", "csrfmiddlewaretoken",
			"authenticity_token", "__requestverificationtoken",
			"nonce", "challenge",
			// Timestamps
			"timestamp", "_timestamp", "created_at", "updated_at",
			"modified_at", "last_modified", "last_updated",
			"created", "modified", "updated",
			"date_created", "date_modified", "date_updated",
			"expires", "expires_at", "expires_in",
			"iat", "nbf", "exp", "jti",
			// Session / request IDs
			"request_id", "requestid", "trace_id", "traceid",
			"span_id", "spanid", "correlation_id",
			"session_id", "sessionid", "sid",
			// Random / non-deterministic
			"random", "rand", "seed", "uuid",
			"non-deterministic",
			// Pagination
			"page", "per_page", "limit", "offset", "total",
			"total_pages", "total_count", "total_results",
			"current_page", "page_size", "pagecount",
		},
	}
}

// Diff compares two JSON response bodies and returns the structural differences.
// If either body is not valid JSON, falls back to a simple string comparison.
func (e *Engine) Diff(baseline, actual string) Result {
	// Try to parse both as JSON
	var baseJSON, actualJSON interface{}

	baseErr := json.Unmarshal([]byte(baseline), &baseJSON)
	actualErr := json.Unmarshal([]byte(actual), &actualJSON)

	// Fallback: one or both aren't JSON
	if baseErr != nil || actualErr != nil {
		return e.DiffStrings(baseline, actual)
	}

	changes := e.compareValues("", baseJSON, actualJSON)
	result := e.buildResult(changes)
	return result
}

// DiffStrings does a basic string comparison when JSON parsing fails.
func (e *Engine) DiffStrings(baseline, actual string) Result {
	result := Result{}

	if baseline == actual {
		result.Summary = "identical response"
		return result
	}

	if strings.TrimSpace(actual) == "" && strings.TrimSpace(baseline) != "" {
		result.Summary = "empty response (access denied?)"
		return result
	}

	result.Changes = []Change{{
		Path:        "(body)",
		Type:        "changed",
		Description: "non-JSON response differs from baseline",
	}}
	result.HasDataLeak = true
	result.Score = 40
	result.Summary = "non-JSON response differs from baseline"
	return result
}

// compareValues recursively compares two parsed JSON values and collects changes.
func (e *Engine) compareValues(path string, baseline, actual interface{}) []Change {
	// Skip ignored paths (CSRF tokens, timestamps, etc.)
	if e.isIgnoredPath(path) {
		return nil
	}
	var changes []Change

	// Type mismatch
	if reflect.TypeOf(baseline) != reflect.TypeOf(actual) {
		changes = append(changes, Change{
			Path:        path,
			Type:        "changed",
			Expected:    fmt.Sprintf("%v", baseline),
			Actual:      fmt.Sprintf("%v", actual),
			Sensitive:   e.isSensitivePath(path),
			Description: fmt.Sprintf("type changed at %s", path),
		})
		return changes
	}

	switch baseVal := baseline.(type) {
	case map[string]interface{}:
		actualVal := actual.(map[string]interface{})
		changes = append(changes, e.compareMaps(path, baseVal, actualVal)...)

	case []interface{}:
		actualVal := actual.([]interface{})
		changes = append(changes, e.compareArrays(path, baseVal, actualVal)...)

	default:
		if baseline != actual {
			changes = append(changes, Change{
				Path:        path,
				Type:        "changed",
				Expected:    fmt.Sprintf("%v", baseline),
				Actual:      fmt.Sprintf("%v", actual),
				Sensitive:   e.isSensitivePath(path),
				Description: fmt.Sprintf("value changed at %s: %v -> %v", path, baseline, actual),
			})
		}
	}

	return changes
}

// compareMaps compares two JSON objects key by key.
func (e *Engine) compareMaps(path string, baseline, actual map[string]interface{}) []Change {
	var changes []Change

	// Keys present in baseline but not actual (removed)
	for k, baseVal := range baseline {
		childPath := e.joinPath(path, k)
		if _, exists := actual[k]; !exists {
			changes = append(changes, Change{
				Path:        childPath,
				Type:        "removed",
				Expected:    fmt.Sprintf("%v", baseVal),
				Sensitive:   e.isSensitiveKey(k),
				Description: fmt.Sprintf("key removed: %s", childPath),
			})
		}
	}

	// Keys present in actual but not baseline (added = access gain)
	for k, actualVal := range actual {
		childPath := e.joinPath(path, k)
		if _, exists := baseline[k]; !exists {
			changes = append(changes, Change{
				Path:        childPath,
				Type:        "added",
				Actual:      fmt.Sprintf("%v", actualVal),
				Sensitive:   e.isSensitiveKey(k),
				Description: fmt.Sprintf("key added: %s (access gain)", childPath),
			})
		}
	}

	// Keys in both — compare values
	for k, baseVal := range baseline {
		if actualVal, exists := actual[k]; exists {
			childPath := e.joinPath(path, k)
			changes = append(changes, e.compareValues(childPath, baseVal, actualVal)...)
		}
	}

	return changes
}

// compareArrays compares two JSON arrays.
func (e *Engine) compareArrays(path string, baseline, actual []interface{}) []Change {
	var changes []Change

	if len(baseline) != len(actual) {
		changes = append(changes, Change{
			Path:        path,
			Type:        "array_size_changed",
			Expected:    fmt.Sprintf("length=%d", len(baseline)),
			Actual:      fmt.Sprintf("length=%d", len(actual)),
			Sensitive:   e.isSensitivePath(path),
			Description: fmt.Sprintf("array at %s: %d -> %d elements", path, len(baseline), len(actual)),
		})
	}

	// Compare elements up to the shorter array
	minLen := len(baseline)
	if len(actual) < minLen {
		minLen = len(actual)
	}
	for i := 0; i < minLen; i++ {
		childPath := fmt.Sprintf("%s[%d]", path, i)
		changes = append(changes, e.compareValues(childPath, baseline[i], actual[i])...)
	}

	return changes
}

// buildResult creates a Result from a list of changes.
func (e *Engine) buildResult(changes []Change) Result {
	result := Result{Changes: changes}

	for _, c := range changes {
		if c.Type == "added" && c.Sensitive {
			result.HasAccessGain = true
		}
		if c.Type == "changed" && c.Sensitive {
			result.HasDataLeak = true
		}
		if c.Type == "added" {
			result.HasAccessGain = true
		}
	}

	// Calculate score
	result.Score = e.calculateScore(changes)

	// Generate summary
	result.Summary = e.generateSummary(result, changes)

	return result
}

// calculateScore assigns a 0-100 score based on change types.
func (e *Engine) calculateScore(changes []Change) int {
	if len(changes) == 0 {
		return 0
	}

	score := 0
	for _, c := range changes {
		switch c.Type {
		case "changed":
			if c.Sensitive {
				score += 30
			} else {
				score += 5
			}
		case "added":
			if c.Sensitive {
				score += 40
			} else {
				score += 15
			}
		case "removed":
			score += 10
		case "array_size_changed":
			if c.Sensitive {
				score += 20
			} else {
				score += 10
			}
		}
	}

	if score > 100 {
		score = 100
	}
	return score
}

// generateSummary creates a human-readable summary.
func (e *Engine) generateSummary(result Result, changes []Change) string {
	if len(changes) == 0 {
		return "identical to baseline"
	}

	var sensitiveChanges []Change
	var otherChanges int
	for _, c := range changes {
		if c.Sensitive {
			sensitiveChanges = append(sensitiveChanges, c)
		} else {
			otherChanges++
		}
	}

	parts := []string{}
	if result.HasDataLeak {
		parts = append(parts, fmt.Sprintf("sensitive data differs (%d fields)", len(sensitiveChanges)))
	}
	if result.HasAccessGain {
		parts = append(parts, "new fields exposed (access gain)")
	}
	if otherChanges > 0 {
		parts = append(parts, fmt.Sprintf("%d other changes", otherChanges))
	}

	if len(parts) == 0 {
		return fmt.Sprintf("%d changes detected", len(changes))
	}
	return strings.Join(parts, ", ")
}

// isSensitiveKey checks if a key name suggests sensitive data.
func (e *Engine) isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range e.SensitiveKeys {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// isSensitivePath checks if a dot-separated path contains sensitive keys.
func (e *Engine) isSensitivePath(path string) bool {
	if path == "" {
		return false
	}
	parts := strings.Split(path, ".")
	for _, p := range parts {
		p = strings.Split(p, "[")[0]
		if e.isSensitiveKey(p) {
			return true
		}
	}
	return false
}

// isIgnoredPath checks if a path contains volatile fields (CSRF, timestamps, nonces).
func (e *Engine) isIgnoredPath(path string) bool {
	if path == "" || len(e.IgnoredPrefixes) == 0 {
		return false
	}
	parts := strings.Split(path, ".")
	for _, p := range parts {
		p = strings.Split(p, "[")[0]
		lower := strings.ToLower(p)
		for _, ignored := range e.IgnoredPrefixes {
			if lower == ignored || strings.Contains(lower, ignored) {
				return true
			}
		}
	}
	return false
}

// joinPath joins a parent path with a child key.
func (e *Engine) joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

// IsJSONResponse returns true if the body looks like JSON.
func IsJSONResponse(body string) bool {
	body = strings.TrimSpace(body)
	if len(body) == 0 {
		return false
	}
	return body[0] == '{' || body[0] == '['
}
