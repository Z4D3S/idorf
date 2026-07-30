// Package proxy implements a reverse proxy that replays captured requests
// across multiple user sessions to detect access control vulnerabilities.
//
// How it works:
//  1. You configure N user sessions (admin, user1, anon)
//  2. Point your browser to use idorf as HTTP proxy (127.0.0.1:PORT)
//  3. Browse the target application normally
//  4. idorf forwards each request to the real server
//  5. For each captured request, idorf replays it with each user's session
//  6. Responses are compared to detect access control differences
//  7. Results are displayed in real-time
package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/z4d3s/idorf/internal/fuzzer"
	"github.com/z4d3s/idorf/internal/multisession"
)

// Capture holds a single HTTP request captured from the proxy.
type Capture struct {
	ID        int
	Method    string
	URL       string
	Headers   map[string]string
	Body      string
	Timestamp time.Time
	UserAgent string
}

// Result holds the proxy analysis result for one captured request.
type Result struct {
	Capture      Capture
	MultiResult  fuzzer.MultiResult `json:"multi_result"`
	IsVulnerable bool
	Confidence   string
	Reason       string
}

// Config holds the proxy configuration.
type Config struct {
	ListenAddr  string // e.g. "127.0.0.1:8081"
	Upstream    string // e.g. "https://target.com" (optional, inferred from requests)
	Manager     *multisession.Manager
	DiffPattern string
	Verbose     bool
}

// Proxy is an HTTP proxy that captures and replays requests.
type Proxy struct {
	cfg       Config
	captures  []Capture
	results   []Result
	mu        sync.Mutex
	captureID int
	server    *http.Server
	done      chan struct{}
}

// New creates a new proxy with the given configuration.
func New(cfg Config) *Proxy {
	return &Proxy{
		cfg:  cfg,
		done: make(chan struct{}),
	}
}

// Start begins the proxy server. Blocks until the server stops.
func (p *Proxy) Start(ctx context.Context) error {
	p.server = &http.Server{
		Addr:    p.cfg.ListenAddr,
		Handler: http.HandlerFunc(p.handleRequest),
	}

	fmt.Printf("\n  idorf proxy running on http://%s\n", p.cfg.ListenAddr)
	fmt.Printf("  Users: %d (%s)\n", p.cfg.Manager.GetUserCount(), strings.Join(p.cfg.Manager.GetUserNames(), ", "))
	fmt.Printf("  Browse your target application normally.\n")
	fmt.Printf("  Press Ctrl+C to stop and see results.\n\n")

	err := p.server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("proxy server error: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the proxy.
func (p *Proxy) Stop(ctx context.Context) error {
	if p.server != nil {
		return p.server.Shutdown(ctx)
	}
	return nil
}

// GetCaptures returns all captured requests.
func (p *Proxy) GetCaptures() []Capture {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]Capture, len(p.captures))
	copy(result, p.captures)
	return result
}

// GetResults returns all analysis results.
func (p *Proxy) GetResults() []Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]Result, len(p.results))
	copy(result, p.results)
	return result
}

// handleRequest processes an incoming HTTP request through the proxy.
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Forward the request to the real server
	targetURL := r.URL.String()
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + r.Host + r.URL.RequestURI()
	}

	// Parse target URL
	target, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	// Create reverse proxy
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = func(resp *http.Response) error {
		// Read the response body
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Capture the request for replay
		p.captureRequest(r, resp.StatusCode, string(bodyBytes))

		return nil
	}

	// Strip proxy headers
	r.RequestURI = ""
	r.URL.Scheme = target.Scheme
	r.URL.Host = target.Host
	r.Header.Del("Proxy-Connection")

	rp.ServeHTTP(w, r)
}

// captureRequest stores a captured request and triggers multi-session replay.
func (p *Proxy) captureRequest(r *http.Request, statusCode int, body string) {
	p.mu.Lock()
	p.captureID++
	id := p.captureID
	p.mu.Unlock()

	// Build capture record
	capturedHeaders := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			capturedHeaders[k] = v[0]
		}
	}

	captured := Capture{
		ID:        id,
		Method:    r.Method,
		URL:       r.URL.String(),
		Headers:   capturedHeaders,
		Body:      body,
		Timestamp: time.Now(),
		UserAgent: r.UserAgent(),
	}

	p.mu.Lock()
	p.captures = append(p.captures, captured)
	p.mu.Unlock()

	// Replay with each user's session in background
	go p.replayCapture(captured)
}

// replayCapture replays a captured request with each user session.
func (p *Proxy) replayCapture(captured Capture) {
	userNames := p.cfg.Manager.GetUserNames()
	client := &http.Client{Timeout: 10 * time.Second}

	responses := make(map[string]int)
	bodySizes := make(map[string]int)
	bodies := make(map[string]string)

	for _, userName := range userNames {
		userSess := p.cfg.Manager.GetUserSession(userName)
		if userSess == nil {
			continue
		}

		// Build request from capture
		var bodyReader io.Reader
		if captured.Body != "" {
			bodyReader = strings.NewReader(captured.Body)
		}

		req, err := http.NewRequest(captured.Method, captured.URL, bodyReader)
		if err != nil {
			continue
		}

		// Set headers from capture
		for k, v := range captured.Headers {
			// Skip hop-by-hop headers
			if strings.ToLower(k) == "proxy-connection" || strings.ToLower(k) == "connection" {
				continue
			}
			req.Header.Set(k, v)
		}

		// Apply user session (replaces Authorization, Cookie)
		delete(req.Header, "Authorization")
		delete(req.Header, "Cookie")

		// Convert http.Header to map[string]string for session ApplyHeaders
		headerMap := make(map[string]string)
		for k, v := range req.Header {
			if len(v) > 0 {
				headerMap[k] = v[0]
			}
		}
		userSess.ApplyHeaders(headerMap)
		for k, v := range headerMap {
			req.Header.Set(k, v)
		}

		cookieHeader := userSess.ToCookieHeader()
		if cookieHeader != "" {
			req.Header.Set("Cookie", cookieHeader)
		}

		resp, err := client.Do(req)
		if err != nil {
			responses[userName] = 0
			bodies[userName] = ""
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		responses[userName] = resp.StatusCode
		bodies[userName] = string(respBody)
		bodySizes[userName] = len(respBody)
	}

	// Build multi-result
	msResult := p.cfg.Manager.BuildMultiResult(fmt.Sprintf("req-%d", captured.ID), responses, bodies)

	// Convert to fuzzer.MultiResult
	multiResult := fuzzer.MultiResult{
		Value:        msResult.Value,
		Responses:    msResult.Responses,
		BodySizes:    msResult.BodySizes,
		Bodies:       msResult.Bodies,
		Comparisons:  msResult.Comparisons,
		IsVulnerable: msResult.IsVulnerable,
		Confidence:   msResult.Confidence,
		Reason:       msResult.Reason,
	}

	// Determine vulnerability
	isVuln := multiResult.IsVulnerable
	confidence := multiResult.Confidence
	reason := multiResult.Reason

	// Print to terminal immediately
	emoji := "🟢"
	if isVuln {
		emoji = "🔴"
		if confidence == "critical" {
			emoji = "🚨"
		}
	}

	// Show what the auth user got vs others
	var statusLine string
	for _, userName := range userNames {
		status := responses[userName]
		size := bodySizes[userName]
		statusLine += fmt.Sprintf(" %s:%d/%d", userName, status, size)
	}

	fmt.Printf("%s [%s] %s %s\n%s\n",
		emoji, strings.ToUpper(confidence), captured.Method, captured.URL, statusLine)

	if isVuln {
		fmt.Printf("   %s\n", reason)
	}

	p.mu.Lock()
	p.results = append(p.results, Result{
		Capture:      captured,
		MultiResult:  multiResult,
		IsVulnerable: isVuln,
		Confidence:   confidence,
		Reason:       reason,
	})
	p.mu.Unlock()
}

// PrintSummary prints the final summary of all proxy results.
func PrintSummary(results []Result) {
	fmt.Println("\n═══════════════════════════════════════════════")
	fmt.Println("PROXY ANALYSIS COMPLETE")
	fmt.Println("═══════════════════════════════════════════════")

	var vulnCount, safeCount int
	for _, r := range results {
		if r.IsVulnerable {
			vulnCount++
		} else {
			safeCount++
		}
	}

	total := len(results)
	fmt.Printf("Total requests: %d\n", total)
	fmt.Printf("🚨 Potential access control issues: %d\n", vulnCount)
	fmt.Printf("🟢 Safe: %d\n", safeCount)

	if vulnCount > 0 {
		fmt.Println("\n── VULNERABLE ENDPOINTS ──────────────────")
		for _, r := range results {
			if r.IsVulnerable {
				emoji := "🔴"
				if r.Confidence == "critical" {
					emoji = "🚨"
				}
				fmt.Printf("%s [%s] %s %s\n  %s\n",
					emoji, strings.ToUpper(r.Confidence), r.Capture.Method, r.Capture.URL, r.Reason)
			}
		}
	}
}
