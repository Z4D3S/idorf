// Package config manages idorf configuration.
package config

import "fmt"

// Config holds all idorf configuration.
type Config struct {
	CurlCmd     string
	RequestFile string
	Wordlist    string
	Marker      string
	SessionFile string
	OutputFile  string
	Threads     int
	RateLimit   int
	Timeout     int
	Proxy       string
	Verbose     bool
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.CurlCmd == "" && c.RequestFile == "" {
		return fmt.Errorf("either curl command (-c) or request file (-r) is required")
	}
	if c.Wordlist == "" {
		return fmt.Errorf("wordlist file (-w) is required")
	}
	if c.Threads < 1 {
		return fmt.Errorf("threads must be at least 1")
	}
	return nil
}
