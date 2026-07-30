// Package reporter generates output in various formats.
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
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
