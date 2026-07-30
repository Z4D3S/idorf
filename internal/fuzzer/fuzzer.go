// Package fuzzer orchestrates the IDOR fuzzing campaign.
package fuzzer

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/z4d3s/idorf/internal/analyzer"
	"github.com/z4d3s/idorf/internal/parser"
	"github.com/z4d3s/idorf/internal/session"
)

// Result holds the outcome of a single fuzzed request.
type Result struct {
	Value    string          `json:"value"`
	Status   int             `json:"status"`
	Size     int             `json:"size"`
	Body     string          `json:"body,omitempty"`
	Headers  http.Header     `json:"headers,omitempty"`
	Analysis analyzer.Result `json:"analysis"`
	Error    string          `json:"error,omitempty"`
	Duration time.Duration   `json:"duration_ms,omitempty"`
}

// Config holds fuzzer configuration.
type Config struct {
	Threads   int
	RateLimit int
	Timeout   int
	Proxy     string
	Verbose   bool
	Insecure  bool
}

// Stats holds fuzzer statistics.
type Stats struct {
	Total      int
	Vulnerable int
	Safe       int
	Errors     int
}

// Run executes the fuzzing campaign.
// It takes a base request template, a list of values to fuzz,
// a session for authentication, and configuration.
// Returns a slice of results for all tested values.
func Run(ctx context.Context, baseReq *parser.Request, values []string, sess *session.Session, cfg *Config) ([]Result, error) {
	if baseReq == nil {
		return nil, fmt.Errorf("nil base request")
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("no values to fuzz")
	}
	if cfg.Threads < 1 {
		cfg.Threads = 1
	}

	client := buildHTTPClient(cfg)

	jobs := make(chan string, len(values))
	results := make(chan Result, len(values))
	var wg sync.WaitGroup

	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go worker(ctx, i, jobs, results, baseReq, sess, cfg, client, &wg)
	}

	for _, v := range values {
		jobs <- v
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []Result
	for r := range results {
		allResults = append(allResults, r)
	}

	return allResults, nil
}

// worker processes fuzzing jobs from the channel.
func worker(ctx context.Context, id int, jobs <-chan string, results chan<- Result, baseReq *parser.Request, sess *session.Session, cfg *Config, client *http.Client, wg *sync.WaitGroup) {
	defer wg.Done()

	var rateLimiter *time.Ticker
	if cfg.RateLimit > 0 {
		interval := time.Second / time.Duration(cfg.RateLimit)
		rateLimiter = time.NewTicker(interval)
		defer rateLimiter.Stop()
	}

	for value := range jobs {
		if ctx.Err() != nil {
			return
		}

		if rateLimiter != nil {
			<-rateLimiter.C
		}

		result := sendFuzzedRequest(ctx, baseReq, value, sess, cfg, client)
		results <- result
	}
}

// sendFuzzedRequest sends a single request with the marker replaced by value.
func sendFuzzedRequest(ctx context.Context, baseReq *parser.Request, value string, sess *session.Session, cfg *Config, client *http.Client) Result {
	start := time.Now()

	fuzzed := baseReq.Clone()
	fuzzed.ReplaceMarker("FUZZ", value)

	if sess != nil {
		sess.ApplyHeaders(fuzzed.Headers)
		cookieHeader := sess.ToCookieHeader()
		if cookieHeader != "" {
			existing := fuzzed.Headers["Cookie"]
			if existing != "" {
				fuzzed.Headers["Cookie"] = existing + "; " + cookieHeader
			} else {
				fuzzed.Headers["Cookie"] = cookieHeader
			}
		}
	}

	bodyReader := strings.NewReader(fuzzed.Body)
	req, err := http.NewRequestWithContext(ctx, fuzzed.Method, fuzzed.URL, bodyReader)
	if err != nil {
		return Result{
			Value: value,
			Error: fmt.Sprintf("creating request: %v", err),
		}
	}

	for k, v := range fuzzed.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{
			Value: value,
			Error: fmt.Sprintf("sending request: %v", err),
		}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{
			Value: value,
			Error: fmt.Sprintf("reading response: %v", err),
		}
	}

	bodyStr := string(bodyBytes)
	duration := time.Since(start)

	// Initial analysis without baseline (will be refined later)
	analysis := analyzer.Analyze(0, 0, "", resp.StatusCode, len(bodyBytes), bodyStr, nil)

	if sess != nil {
		sess.UpdateFromResponse(resp)
	}

	return Result{
		Value:    value,
		Status:   resp.StatusCode,
		Size:     len(bodyBytes),
		Body:     bodyStr,
		Headers:  resp.Header.Clone(),
		Analysis: analysis,
		Duration: duration,
	}
}

// buildHTTPClient creates an HTTP client with the given configuration.
func buildHTTPClient(cfg *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure || true,
		},
		MaxIdleConnsPerHost: cfg.Threads,
		MaxIdleConns:        cfg.Threads * 2,
		IdleConnTimeout:     30 * time.Second,
	}

	if cfg.Proxy != "" {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			return url.Parse(cfg.Proxy)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// ComputeStats calculates statistics from results.
func ComputeStats(results []Result) Stats {
	stats := Stats{Total: len(results)}
	for _, r := range results {
		if r.Error != "" {
			stats.Errors++
		} else if r.Analysis.IsVulnerable {
			stats.Vulnerable++
		} else {
			stats.Safe++
		}
	}
	return stats
}
