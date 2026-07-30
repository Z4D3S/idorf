// Package analyzer compares responses to detect access control vulnerabilities.
package analyzer

import (
	"fmt"
	"strings"
)

// Result represents the analysis outcome for a single response.
type Result struct {
	IsVulnerable bool
	Confidence   string // "critical", "high", "warn", "safe"
	Reason       string
}

// sensitivePatterns contains patterns that suggest data exposure.
var sensitivePatterns = []string{
	"\"email\"", "\"address\"", "\"phone\"", "\"credit_card\"",
	"\"ssn\"", "\"password\"", "\"secret\"", "\"token\"",
	"user", "customer", "profile", "account",
}

// Config holds analyzer configuration.
type Config struct{}

// Analyze compares a response against a baseline and determines if it's vulnerable.
func Analyze(baselineStatus int, baselineSize int, status int, size int, body string) Result {
	if status == 401 || status == 403 {
		return Result{
			IsVulnerable: false,
			Confidence:   "safe",
			Reason:       fmt.Sprintf("blocked (%d)", status),
		}
	}

	if status == 200 && baselineStatus != 200 {
		return Result{
			IsVulnerable: true,
			Confidence:   "high",
			Reason:       fmt.Sprintf("status %d vs baseline %d", status, baselineStatus),
		}
	}

	if status == 200 && baselineStatus == 200 {
		if size != baselineSize {
			return Result{
				IsVulnerable: true,
				Confidence:   "high",
				Reason:       fmt.Sprintf("size %d vs baseline %d", size, baselineSize),
			}
		}

		for _, pattern := range sensitivePatterns {
			if strings.Contains(body, pattern) {
				return Result{
					IsVulnerable: true,
					Confidence:   "critical",
					Reason:       "response contains potential user data: " + pattern,
				}
			}
		}
	}

	return Result{
		IsVulnerable: false,
		Confidence:   "warn",
		Reason:       "same response as baseline",
	}
}
