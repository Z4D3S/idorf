package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/z4d3s/idorf/internal/analyzer"
	"github.com/z4d3s/idorf/internal/fuzzer"
	"github.com/z4d3s/idorf/internal/parser"
	"github.com/z4d3s/idorf/internal/reporter"
	"github.com/z4d3s/idorf/internal/session"
)

var (
	curlCmd     string
	requestFile string
	wordlistFile string
	marker      string
	sessionFile string
	outputFile string
	threads     int
	rateLimit   int
	timeout     int
	proxyURL    string
	verbose     bool
	showVersion bool
	baseline    bool
)

const version = "0.1.0"

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
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&baseline, "baseline", false, "Send first value as baseline (for comparison)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
  _ ___ _ ___ ___
 (_) | | '_/ -_) -_)  v%s
  _|_|_|_| \___\___|   IDOR Finder

`[1:], version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  idorf -c 'curl ...' -w ids.txt       (from cURL command)\n")
		fmt.Fprintf(os.Stderr, "  idorf -r request.txt -w ids.txt        (from raw HTTP request)\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
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

	// 5. Configure fuzzer
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

	// 6. Run fuzzer
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(values)*timeout+30)*time.Second)
	defer cancel()

	results, err := fuzzer.Run(ctx, req, values, sess, cfg)
	if err != nil {
		fatal("fuzzing failed: %v", err)
	}

	// 7. Calculate baseline if needed
	baselineStatus := 0
	baselineSize := 0
	if len(results) > 0 {
		baselineStatus = results[0].Status
		baselineSize = results[0].Size
	}

	// Re-analyze with baseline
	for i := range results {
		if results[i].Error == "" {
			results[i].Analysis = analyzer.Analyze(
				baselineStatus, baselineSize,
				results[i].Status, results[i].Size,
				results[i].Body,
			)
		}
	}

	// 8. Report
	reporter.PrintTerminal(results)

	// 9. Save JSON if requested
	if outputFile != "" {
		if err := reporter.Generate(results, req.URL, &reporter.Config{
			OutputFile: outputFile,
			Verbose:    verbose,
		}); err != nil {
			fatal("saving report: %v", err)
		}
		fmt.Printf("\n[+] Report saved to %s\n", outputFile)
	}

	// 10. Save session if it changed
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