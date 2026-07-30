// Package reporter generates output in various formats.
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/z4d3s/idorf/internal/fuzzer"
)

// Config holds reporter configuration.
type Config struct {
	OutputFile string
	Verbose    bool
}

// Report holds the complete fuzzing results.
type Report struct {
	Target     string          `json:"target"`
	Total      int             `json:"total"`
	Vulnerable int             `json:"vulnerable"`
	Safe       int             `json:"safe"`
	Errors     int             `json:"errors"`
	Results    []fuzzer.Result `json:"results"`
}

// Generate creates a JSON report and writes it to the specified file.
func Generate(results []fuzzer.Result, target string, cfg *Config) error {
	stats := fuzzer.ComputeStats(results)

	report := Report{
		Target:     target,
		Total:      len(results),
		Vulnerable: stats.Vulnerable,
		Safe:       stats.Safe,
		Errors:     stats.Errors,
		Results:    results,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling report: %w", err)
	}

	if cfg.OutputFile == "" || cfg.OutputFile == "stdout" {
		fmt.Println(string(data))
		return nil
	}

	if err := os.WriteFile(cfg.OutputFile, data, 0644); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	return nil
}

// PrintTerminal prints a human-readable summary to the terminal with colors.
func PrintTerminal(results []fuzzer.Result) {
	if len(results) == 0 {
		fmt.Println("No results.")
		return
	}

	var vulnResults, safeResults, errorResults []fuzzer.Result

	for _, r := range results {
		switch {
		case r.Error != "":
			errorResults = append(errorResults, r)
		case r.Analysis.IsVulnerable:
			vulnResults = append(vulnResults, r)
		default:
			safeResults = append(safeResults, r)
		}
	}

	// Print vulnerable results first (most important)
	if len(vulnResults) > 0 {
		fmt.Println("── POTENTIAL VULNERABILITIES ──────────────────")
		for _, r := range vulnResults {
			emoji := "🔴"
			if r.Analysis.Confidence == "critical" {
				emoji = "🚨"
			}
			fmt.Printf("%s [%s] %-20s → HTTP %d, %d bytes\n",
				emoji, strings.ToUpper(r.Analysis.Confidence),
				r.Value, r.Status, r.Size)
			fmt.Printf("   Reason: %s\n", r.Analysis.Reason)
			if len(r.Body) < 500 && r.Body != "" {
				fmt.Printf("   Body: %s\n", r.Body)
			}
			fmt.Println()
		}
	}

	// Print errors
	if len(errorResults) > 0 {
		fmt.Println("── ERRORS ─────────────────────────────────────")
		for _, r := range errorResults {
			fmt.Printf("⚠️  %-20s → Error: %s\n", r.Value, r.Error)
		}
		fmt.Println()
	}

	// Print safe results (brief)
	if len(safeResults) > 0 && len(safeResults) <= 20 {
		fmt.Println("── SAFE ───────────────────────────────────────")
		for _, r := range safeResults {
			fmt.Printf("🟢 %-20s → HTTP %d, %d bytes\n", r.Value, r.Status, r.Size)
		}
		fmt.Println()
	}

	// Summary
	fmt.Println("═══════════════════════════════════════════════")
	vulnCount := len(vulnResults)
	safeCount := len(safeResults)
	errCount := len(errorResults)
	total := len(results)

	status := "✅ No vulnerabilities found"
	if vulnCount > 0 {
		status = "🚨 POTENTIAL IDOR DETECTED"
	}

	fmt.Printf("Total: %d | 🚨 Vulnerable: %d | 🟢 Safe: %d | ⚠️  Errors: %d\n",
		total, vulnCount, safeCount, errCount)
	fmt.Printf("Status: %s\n", status)
	fmt.Println("═══════════════════════════════════════════════")
}

// PrintMultiTerminal prints results for multi-session mode.
func PrintMultiTerminal(results []fuzzer.MultiResult) {
	if len(results) == 0 {
		fmt.Println("No results.")
		return
	}

	var vulnResults, safeResults []fuzzer.MultiResult
	for _, r := range results {
		if r.IsVulnerable {
			vulnResults = append(vulnResults, r)
		} else {
			safeResults = append(safeResults, r)
		}
	}

	// Print vulnerable results
	if len(vulnResults) > 0 {
		fmt.Println("── ACCESS CONTROL DIFFERENCES ──────────────────")
		for _, r := range vulnResults {
			emoji := "🔴"
			if r.Confidence == "critical" {
				emoji = "🚨"
			}
			fmt.Printf("%s [%s] ID: %-15s\n", emoji, strings.ToUpper(r.Confidence), r.Value)
			fmt.Printf("   Reason: %s\n", r.Reason)

			// Show per-user status
			for user, status := range r.Responses {
				size := r.BodySizes[user]
				fmt.Printf("   %-10s HTTP %d, %d bytes\n", user+":", status, size)
			}

			// Show diff details for first vulnerable comparison
			for _, comp := range r.Comparisons {
				if comp.IsVulnerable {
					fmt.Printf("   Diff %s vs %s: %s\n", comp.UserA, comp.UserB, comp.DiffResult.Summary)
					break
				}
			}
			fmt.Println()
		}
	}

	// Print safe results (brief)
	if len(safeResults) > 0 && len(safeResults) <= 20 {
		fmt.Println("── NO DIFFERENCES ────────────────────────────────")
		for _, r := range safeResults {
			fmt.Printf("🟢 ID: %-15s — same access for all users\n", r.Value)
		}
		fmt.Println()
	}

	// Summary
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Printf("Total: %d | 🚨 Vulnerable: %d | 🟢 Safe: %d\n",
		len(results), len(vulnResults), len(safeResults))
	if len(vulnResults) > 0 {
		fmt.Println("Status: 🚨 ACCESS CONTROL ISSUES DETECTED")
	} else {
		fmt.Println("Status: ✅ No access control differences found")
	}
	fmt.Println("═══════════════════════════════════════════════")
}

// GenerateMulti creates a JSON report for multi-session results.
func GenerateMulti(results []fuzzer.MultiResult, target string, cfg *Config) error {
	type multiReport struct {
		Target     string               `json:"target"`
		Total      int                  `json:"total"`
		Vulnerable int                  `json:"vulnerable"`
		Safe       int                  `json:"safe"`
		Results    []fuzzer.MultiResult `json:"results"`
	}

	vulnCount := 0
	for _, r := range results {
		if r.IsVulnerable {
			vulnCount++
		}
	}

	report := multiReport{
		Target:     target,
		Total:      len(results),
		Vulnerable: vulnCount,
		Safe:       len(results) - vulnCount,
		Results:    results,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling report: %w", err)
	}

	if cfg.OutputFile == "" || cfg.OutputFile == "stdout" {
		fmt.Println(string(data))
		return nil
	}

	return os.WriteFile(cfg.OutputFile, data, 0644)
}

// GenerateHTML creates a self-contained HTML report for multi-session results.
func GenerateHTML(multiResults []fuzzer.MultiResult, target string, cfg *Config) error {
	var vulnRows, safeRows string
	vulnCount := 0

	for _, r := range multiResults {
		if r.IsVulnerable {
			vulnCount++
			emoji := "🔴"
			statusClass := "warn"
			if r.Confidence == "critical" {
				emoji = "🚨"
				statusClass = "critical"
			}

			var userRows string
			for _, userName := range getSortedKeys(r.Responses) {
				status := r.Responses[userName]
				size := r.BodySizes[userName]
				color := "green"
				if status == 200 {
					color = "red"
				}
				if status == 403 || status == 401 {
					color = "green"
				}
				userRows += fmt.Sprintf("<tr><td>%s</td><td style='color:%s'>%d</td><td>%d</td></tr>", userName, color, status, size)
			}

			vulnRows += fmt.Sprintf(`<tr class="%s">
				<td>%s %s</td>
				<td>%s</td>
				<td><table>%s</table></td>
			</tr>`, statusClass, emoji, r.Value, r.Reason, userRows)
		} else {
			safeRows += fmt.Sprintf(`<tr class="safe"><td>🟢 %s</td><td colspan="2">%s</td></tr>`, r.Value, r.Reason)
		}
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>idorf Report</title>
<style>
body{font-family:-apple-system,sans-serif;margin:20px;background:#0d1117;color:#c9d1d9}
h1{color:#58a6ff}
table{border-collapse:collapse;width:100%%;margin:10px 0}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #30363d}
th{background:#161b22;color:#8b949e}
.critical{background:#3d0e0e}
.high{background:#2d1c0e}
.warn{background:#1d2d0e}
.safe{background:#161b22;color:#8b949e}
.summary{font-size:1.2em;margin:20px 0}
.count{font-weight:bold}
.red{color:#f85149}.green{color:#3fb950}
</style></head>
<body>
<h1>🔍 idorf Access Control Report</h1>
<p>Target: %s</p>
<div class="summary">🚨 Vulnerable: <span class="count">%d</span> | 🟢 Safe: <span class="count">%d</span> | Total: <span class="count">%d</span></div>
<h2>Access Control Issues</h2>
<table><tr><th>ID</th><th>Reason</th><th>Users</th></tr>%s</table>
<h2>Safe</h2>
<table><tr><th>ID</th><th>Reason</th><th></th></tr>%s</table>
</body></html>`, target, vulnCount, len(multiResults)-vulnCount, len(multiResults), vulnRows, safeRows)

	return os.WriteFile(cfg.OutputFile, []byte(html), 0644)
}

func getSortedKeys(m map[string]int) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
