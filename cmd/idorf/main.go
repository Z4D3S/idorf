package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/z4d3s/idorf/internal/analyzer"
	"github.com/z4d3s/idorf/internal/fuzzer"
	"github.com/z4d3s/idorf/internal/parser"
	"github.com/z4d3s/idorf/internal/reporter"
	"github.com/z4d3s/idorf/internal/session"
)

var (
	curlCmd      string
	requestFile  string
	wordlistFile string
	marker       string
	sessionFile  string
	outputFile   string
	threads      int
	rateLimit    int
	timeout      int
	proxyURL     string
	diffPattern  string
	knownIDs     string
	verbose      bool
	showVersion  bool
)

const version = "0.2.0"

func main() {
	flag.StringVar(&curlCmd, "c", "", "cURL command to use as request template")
	flag.StringVar(&requestFile, "r", "", "File containing raw HTTP request")
	flag.StringVar(&wordlistFile, "w", "", "File with IDs/values to fuzz (one per line)")
	flag.StringVar(&marker, "m", "FUZZ", "Marker to replace in request")
	flag.StringVar(&sessionFile, "s", "", "Session file (cookies/tokens) for auth persistence")
	flag.StringVar(&outputFile, "o", "", "Output file for JSON results (default stdout)")
	flag.IntVar(&threads, "t", 5, "Concurrent threads")
	flag.IntVar(&rateLimit, "rate-limit", 10, "Requests per second")
	flag.IntVar(&timeout, "timeout", 10, "Request timeout in seconds")
	flag.StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	flag.StringVar(&diffPattern, "diff-pattern", "", "Custom regex for sensitive data detection (e.g. 'credit_card|api_key')")
	flag.StringVar(&knownIDs, "known-ids", "", "Comma-separated IDs that are known-safe (used as baseline)")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
  _ ___ _ ___ ___
 (_) | | '_/ -_) -_)  v%s
  _|_|_|_| \___\___|   IDOR Runner

`[1:], version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  idorf -c 'curl ...' -w ids.txt       (from cURL command)\n")
		fmt.Fprintf(os.Stderr, "  idorf -r request.txt -w ids.txt        (from raw HTTP request)\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  idorf -c 'curl \"http://api.x.com/users/FUZZ\"' -w ids.txt\n")
		fmt.Fprintf(os.Stderr, "  idorf -c 'curl ...' -w ids.txt -s session.json --proxy http://127.0.0.1:8080\n")
		fmt.Fprintf(os.Stderr, "  idorf -c 'curl ...' -w ids.txt --diff-pattern 'credit_card|ssn' --known-ids 1,2\n")
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("idorf v%s\n", version)
		os.Exit(0)
	}

	if curlCmd == "" && requestFile == "" {
		fmt.Fprintln(os.Stderr, "Error: either -c (curl) or -r (request file) is required")
		flag.Usage()
		os.Exit(1)
	}

	if wordlistFile == "" {
		fmt.Fprintln(os.Stderr, "Error: -w (wordlist file) is required")
		flag.Usage()
		os.Exit(1)
	}

	// 1. Parse request
	var req *parser.Request
	var err error

	if curlCmd != "" {
		req, err = parser.ParseCurl(curlCmd)
	} else {
		var rawBytes []byte
		rawBytes, err = os.ReadFile(requestFile)
		if err != nil {
			fatal("reading request file: %v", err)
		}
		req, err = parser.ParseRaw(string(rawBytes))
	}
	if err != nil {
		fatal("parsing request: %v", err)
	}

	fmt.Printf("\n[+] Target: %s %s\n", req.Method, req.URL)
	fmt.Printf("[+] Marker: %s\n", marker)

	// 2. Check marker present
	if !req.ContainsMarker(marker) {
		fmt.Fprintf(os.Stderr, "\n[!] Warning: marker '%s' not found in request\n", marker)
		fmt.Fprintf(os.Stderr, "    Use -m to specify a different marker\n")
		os.Exit(1)
	}

	// 3. Load wordlist
	values, err := loadWordlist(wordlistFile)
	if err != nil {
		fatal("loading wordlist: %v", err)
	}
	fmt.Printf("[+] Wordlist: %d values loaded\n", len(values))

	// 4. Load session
	sess, err := session.New(sessionFile)
	if err != nil {
		fatal("loading session: %v", err)
	}
	if !sess.IsEmpty() {
		fmt.Printf("[+] Session: %d cookies, %d headers\n", len(sess.Cookies), len(sess.Headers))
	}

	// 5. Compile diff pattern
	var customPattern *regexp.Regexp
	if diffPattern != "" {
		customPattern, err = analyzer.CompilePattern(diffPattern)
		if err != nil {
			fatal("compiling diff pattern: %v", err)
		}
		fmt.Printf("[+] Custom diff pattern: %s\n", diffPattern)
	}

	// 6. Parse known IDs
	knownIDSet := make(map[string]bool)
	if knownIDs != "" {
		for _, id := range strings.Split(knownIDs, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				knownIDSet[id] = true
			}
		}
		if len(knownIDSet) > 0 {
			fmt.Printf("[+] Known-safe IDs (baseline): %s\n", knownIDs)
		}
	}

	// 7. Configure fuzzer
	cfg := &fuzzer.Config{
		Threads:   threads,
		RateLimit: rateLimit,
		Timeout:   timeout,
		Proxy:     proxyURL,
		Verbose:   verbose,
	}

	fmt.Printf("[+] Config: %d threads, %d req/s, %ds timeout\n", threads, rateLimit, timeout)
	if proxyURL != "" {
		fmt.Printf("[+] Proxy: %s\n", proxyURL)
	}
	fmt.Println()

	// 8. Run fuzzer
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(values)*timeout+30)*time.Second)
	defer cancel()

	results, err := fuzzer.Run(ctx, req, values, sess, cfg)
	if err != nil {
		fatal("fuzzing failed: %v", err)
	}

	// 9. Build baselines from known IDs
	var baselines []analyzer.Baseline
	if len(knownIDSet) > 0 {
		for _, r := range results {
			if knownIDSet[r.Value] && r.Error == "" {
				baselines = append(baselines, analyzer.Baseline{
					ID:     r.Value,
					Status: r.Status,
					Size:   r.Size,
					Body:   r.Body,
				})
			}
		}
	}

	// 10. Analyze results
	if len(baselines) > 0 {
		for i := range results {
			if results[i].Error == "" && !knownIDSet[results[i].Value] {
				results[i].Analysis = analyzer.AnalyzeWithBaselines(
					results[i].Status, results[i].Size, results[i].Body,
					baselines, customPattern,
				)
			} else if knownIDSet[results[i].Value] {
				results[i].Analysis = analyzer.Result{
					IsVulnerable: false,
					Confidence:   "safe",
					Reason:       "known-safe ID (baseline)",
				}
			}
		}
	} else {
		// Use first result as baseline
		if len(results) > 0 {
			bl := results[0]
			for i := range results {
				if results[i].Error == "" {
					results[i].Analysis = analyzer.Analyze(
						bl.Status, bl.Size, bl.Body,
						results[i].Status, results[i].Size, results[i].Body,
						customPattern,
					)
				}
			}
		}
	}

	// 11. Report
	reporter.PrintTerminal(results)

	// 12. Save JSON if requested
	if outputFile != "" {
		if err := reporter.Generate(results, req.URL, &reporter.Config{
			OutputFile: outputFile,
			Verbose:    verbose,
		}); err != nil {
			fatal("saving report: %v", err)
		}
		fmt.Printf("\n[+] Report saved to %s\n", outputFile)
	}

	// 13. Save session if it changed
	if sessionFile != "" {
		if err := sess.Save(sessionFile); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Warning: could not save session: %v\n", err)
		}
	}

	// Exit code: 1 if vulnerabilities found
	stats := fuzzer.ComputeStats(results)
	if stats.Vulnerable > 0 {
		os.Exit(1)
	}
}

func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var values []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			values = append(values, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return values, nil
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[!] Error: "+format+"\n", args...)
	os.Exit(2)
}
