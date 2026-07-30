// Package analyzer compares responses to detect access control vulnerabilities.
package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// Result represents the analysis outcome for a single response.
type Result struct {
	IsVulnerable bool   `json:"is_vulnerable"`
	Confidence   string `json:"confidence"` // "critical", "high", "warn", "safe", "error"
	Reason       string `json:"reason"`
}

// Config holds analyzer configuration.
type Config struct {
	DiffPattern string          // Custom regex for sensitive data detection
	KnownIDs    map[string]bool // IDs known to be safe (baseline)
}

// defaultSensitivePatterns are patterns that suggest data exposure.
var defaultSensitivePatterns = []string{
	`"email"`, `"e_mail"`, `"mail"`,
	`"address"`, `"street"`, `"city"`, `"postal"`, `"zip"`,
	`"phone"`, `"mobile"`, `"telephone"`,
	`"credit"`, `"card"`, `"cvc"`, `"cvv"`, `"pan"`,
	`"ssn"`, `"social"`,
	`"password"`, `"secret"`, `"token"`, `"api_key"`, `"apikey"`,
	`"private_key"`, `"access_key"`,
	`"date_of_birth"`, `"dob"`, `"birthday"`,
	`"national_id"`, `"passport"`,
	`"balance"`, `"account_number"`, `"iban"`,
}

// CompilePattern compiles a custom diff pattern string into a regex.
// If pattern is empty, returns nil (use default patterns).
func CompilePattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid diff pattern: %w", err)
	}
	return re, nil
}

// Analyze compares a response against a baseline and determines if it's vulnerable.
//
// Parameters:
//   - baselineStatus: HTTP status code of the baseline response
//   - baselineSize: response body size of the baseline response
//   - baselineBody: response body of the baseline (for content comparison)
//   - status: HTTP status code of the current response
//   - size: response body size of the current response
//   - body: response body of the current response
//   - customPattern: optional compiled regex for sensitive data detection
func Analyze(baselineStatus, baselineSize int, baselineBody string, status, size int, body string, customPattern *regexp.Regexp) Result {
	// Access denied = safe
	if status == 401 || status == 403 {
		return Result{
			IsVulnerable: false,
			Confidence:   "safe",
			Reason:       fmt.Sprintf("blocked (HTTP %d)", status),
		}
	}

	// Not found = safe (resource doesn't exist)
	if status == 404 {
		return Result{
			IsVulnerable: false,
			Confidence:   "safe",
			Reason:       fmt.Sprintf("not found (HTTP %d)", status),
		}
	}

	// Server error = error
	if status >= 500 {
		return Result{
			IsVulnerable: false,
			Confidence:   "error",
			Reason:       fmt.Sprintf("server error (HTTP %d)", status),
		}
	}

	// Check for sensitive data patterns
	if status == 200 {
		// Custom pattern first
		if customPattern != nil {
			if match := customPattern.FindString(body); match != "" {
				return Result{
					IsVulnerable: true,
					Confidence:   "critical",
					Reason:       fmt.Sprintf("response matches custom pattern: %s", match),
				}
			}
		}

		// Default patterns
		for _, pattern := range defaultSensitivePatterns {
			if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
				return Result{
					IsVulnerable: true,
					Confidence:   "critical",
					Reason:       fmt.Sprintf("response contains sensitive data: %s", pattern),
				}
			}
		}
	}

	// Different status code from baseline
	if status != baselineStatus {
		if status == 200 && baselineStatus != 200 {
			return Result{
				IsVulnerable: true,
				Confidence:   "high",
				Reason:       fmt.Sprintf("HTTP %d vs baseline %d (access granted)", status, baselineStatus),
			}
		}
		return Result{
			IsVulnerable: false,
			Confidence:   "warn",
			Reason:       fmt.Sprintf("HTTP %d vs baseline %d", status, baselineStatus),
		}
	}

	// Same status code, check size difference
	if status == 200 {
		if size != baselineSize {
			// Significant size difference (>10% or >50 bytes)
			diff := abs(size - baselineSize)
			if diff > 50 || diff > baselineSize/10 {
				return Result{
					IsVulnerable: true,
					Confidence:   "high",
					Reason:       fmt.Sprintf("different response size: %d bytes vs baseline %d (diff: %d)", size, baselineSize, diff),
				}
			}
			return Result{
				IsVulnerable: true,
				Confidence:   "warn",
				Reason:       fmt.Sprintf("minor size difference: %d vs %d", size, baselineSize),
			}
		}

		// Same status, same size — check if content actually differs
		if body != baselineBody {
			return Result{
				IsVulnerable: true,
				Confidence:   "high",
				Reason:       "same size but different content",
			}
		}

		// Same status, same size, same content
		return Result{
			IsVulnerable: false,
			Confidence:   "warn",
			Reason:       "identical to baseline",
		}
	}

	return Result{
		IsVulnerable: false,
		Confidence:   "warn",
		Reason:       fmt.Sprintf("HTTP %d, no clear signal", status),
	}
}

// AnalyzeWithBaselines compares a response against multiple baselines.
// If the response matches any known-safe baseline, it's marked as safe.
func AnalyzeWithBaselines(status, size int, body string, baselines []Baseline, customPattern *regexp.Regexp) Result {
	// Check if this response matches any known-safe baseline
	for _, bl := range baselines {
		if status == bl.Status && size == bl.Size && body == bl.Body {
			return Result{
				IsVulnerable: false,
				Confidence:   "safe",
				Reason:       fmt.Sprintf("matches known-safe baseline (ID: %s)", bl.ID),
			}
		}
	}

	// Fall back to standard analysis using first baseline
	if len(baselines) > 0 {
		bl := baselines[0]
		return Analyze(bl.Status, bl.Size, bl.Body, status, size, body, customPattern)
	}

	// No baselines — use status-only analysis
	return Analyze(0, 0, "", status, size, body, customPattern)
}

// Baseline represents a known-safe response for comparison.
type Baseline struct {
	ID     string
	Status int
	Size   int
	Body   string
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
