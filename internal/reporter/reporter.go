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
	Results    []fuzzer.Result `json:"results"`
}

// Generate creates a report in the specified format.
func Generate(results []fuzzer.Result, target string, cfg *Config) error {
	report := Report{
		Target:  target,
		Total:   len(results),
		Results: results,
	}

	for _, r := range results {
		if r.Analysis.IsVulnerable {
			report.Vulnerable++
		} else {
			report.Safe++
		}
	}

	output := os.Stdout
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		output = f
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling report: %w", err)
	}

	if _, err := output.Write(data); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	return nil
}

// PrintTerminal prints a human-readable summary to the terminal.
func PrintTerminal(results []fuzzer.Result) {
	var vulnCount, safeCount int
	for _, r := range results {
		if r.Analysis.IsVulnerable {
			vulnCount++
			fmt.Printf("🚨 %s -> Status: %d, Size: %d [%s] %s\n",
				r.Value, r.Status, r.Size, r.Analysis.Confidence, r.Analysis.Reason)
		} else {
			safeCount++
		}
	}

	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("Total: %d | 🚨 Vulnerable: %d | 🟢 Safe: %d\n",
		len(results), vulnCount, safeCount)
}
