// Package analyzer compares responses to detect access control vulnerabilities.
package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/z4d3s/idorf/internal/diff"
)

// Result represents the analysis outcome for a single response.
type Result struct {
	IsVulnerable bool         `json:"is_vulnerable"`
	Confidence   string       `json:"confidence"` // "critical", "high", "warn", "safe", "error"
	Reason       string       `json:"reason"`
	DiffResult   *diff.Result `json:"diff,omitempty"`
}

// Config holds analyzer configuration.
type Config struct {
	DiffPattern string          // Custom regex for sensitive data detection
	KnownIDs    map[string]bool // IDs known to be safe (baseline)
	DiffEngine  *diff.Engine    // Semantic JSON diff engine
}

// CompilePattern compiles a custom diff pattern string into a regex.
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

// Analyze compares a response against a baseline using semantic diffing.
func Analyze(baselineStatus, baselineSize int, baselineBody string, status, size int, body string, customPattern *regexp.Regexp) Result {
	// Access denied = safe
	if status == 401 || status == 403 {
		return Result{
			IsVulnerable: false,
			Confidence:   "safe",
			Reason:       fmt.Sprintf("blocked (HTTP %d)", status),
		}
	}

	// Not found = safe
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

	// Run semantic diff if both responses are JSON
	diffEngine := diff.NewEngine()
	var diffResult diff.Result

	if diff.IsJSONResponse(baselineBody) && diff.IsJSONResponse(body) {
		diffResult = diffEngine.Diff(baselineBody, body)
	} else {
		diffResult = diffEngine.DiffStrings(baselineBody, body)
	}

	// Custom pattern check (regex on body)
	if customPattern != nil && status == 200 {
		if match := customPattern.FindString(body); match != "" {
			return Result{
				IsVulnerable: true,
				Confidence:   "critical",
				Reason:       fmt.Sprintf("response matches custom pattern: %s", match),
				DiffResult:   &diffResult,
			}
		}
	}

	// Different status from baseline
	if status != baselineStatus {
		if status == 200 && baselineStatus != 200 {
			return Result{
				IsVulnerable: true,
				Confidence:   "high",
				Reason:       fmt.Sprintf("HTTP %d vs baseline %d (access granted)", status, baselineStatus),
				DiffResult:   &diffResult,
			}
		}
		return Result{
			IsVulnerable: false,
			Confidence:   "warn",
			Reason:       fmt.Sprintf("HTTP %d vs baseline %d", status, baselineStatus),
		}
	}

	// Same status code — use semantic diff results
	if status == 200 {
		if diffResult.HasDataLeak {
			return Result{
				IsVulnerable: true,
				Confidence:   "critical",
				Reason:       fmt.Sprintf("semantic diff: %s", diffResult.Summary),
				DiffResult:   &diffResult,
			}
		}

		if diffResult.HasAccessGain {
			return Result{
				IsVulnerable: true,
				Confidence:   "high",
				Reason:       fmt.Sprintf("semantic diff: %s", diffResult.Summary),
				DiffResult:   &diffResult,
			}
		}

		// Check raw sensitive patterns (non-JSON or no diff detected)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
				return Result{
					IsVulnerable: true,
					Confidence:   "critical",
					Reason:       fmt.Sprintf("response contains sensitive data: %s", pattern),
					DiffResult:   &diffResult,
				}
			}
		}

		// Size-based fallback if diff didn't catch it
		if size != baselineSize {
			diff := abs(size - baselineSize)
			if diff > 50 || diff > baselineSize/10 {
				return Result{
					IsVulnerable: true,
					Confidence:   "high",
					Reason:       fmt.Sprintf("different response size: %d vs %d (diff: %d)", size, baselineSize, diff),
					DiffResult:   &diffResult,
				}
			}
		}

		if body != baselineBody {
			return Result{
				IsVulnerable: true,
				Confidence:   "high",
				Reason:       "same size but different content",
				DiffResult:   &diffResult,
			}
		}
	}

	return Result{
		IsVulnerable: false,
		Confidence:   "warn",
		Reason:       "identical to baseline",
		DiffResult:   &diffResult,
	}
}

// AnalyzeWithBaselines compares a response against multiple baselineIDs.
func AnalyzeWithBaselines(status, size int, body string, baselines []Baseline, customPattern *regexp.Regexp) Result {
	for _, bl := range baselines {
		if status == bl.Status && size == bl.Size && body == bl.Body {
			return Result{
				IsVulnerable: false,
				Confidence:   "safe",
				Reason:       fmt.Sprintf("matches known-safe baseline (ID: %s)", bl.ID),
			}
		}
	}

	if len(baselines) > 0 {
		bl := baselines[0]
		return Analyze(bl.Status, bl.Size, bl.Body, status, size, body, customPattern)
	}

	return Analyze(0, 0, "", status, size, body, customPattern)
}

// Baseline represents a known-safe response for comparison.
type Baseline struct {
	ID     string
	Status int
	Size   int
	Body   string
}

var sensitivePatterns = []string{
	`"email"`, `"address"`, `"phone"`, `"credit_card"`,
	`"ssn"`, `"password"`, `"secret"`, `"token"`,
	`"user"`, `"customer"`, `"profile"`, `"account"`,
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
