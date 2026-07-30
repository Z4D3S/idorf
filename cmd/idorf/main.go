package main

import (
	"flag"
	"fmt"
	"os"
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
	verbose      bool
	showVersion  bool
)

const version = "0.1.0"

func main() {
	flag.StringVar(&curlCmd, "c", "", "cURL command to use as request template")
	flag.StringVar(&requestFile, "r", "", "File containing raw HTTP request")
	flag.StringVar(&wordlistFile, "w", "", "File with IDs/values to fuzz (one per line)")
	flag.StringVar(&marker, "m", "FUZZ", "Marker to replace in request")
	flag.StringVar(&sessionFile, "s", "", "Session file (cookies/tokens)")
	flag.StringVar(&outputFile, "o", "", "Output file (default stdout)")
	flag.IntVar(&threads, "t", 5, "Concurrent threads")
	flag.IntVar(&rateLimit, "rate-limit", 10, "Requests per second")
	flag.IntVar(&timeout, "timeout", 10, "Request timeout in seconds")
	flag.StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "idorf v%s - IDOR Finder\n", version)
		fmt.Fprintf(os.Stderr, "Usage: idorf -c <curl> -w <wordlist>\n")
		fmt.Fprintf(os.Stderr, "       idorf -r <file> -w <wordlist>\n\n")
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

	fmt.Println("idorf v" + version)
	fmt.Println("Ready to hunt IDORs.")
}
