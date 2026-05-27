package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ─── ANSI Colors ──────────────────────────────────────────────────────────────
const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Purple = "\033[35m"
	Orange = "\033[38;5;208m"
	Bold   = "\033[1m"
	Reset  = "\033[0m"
	Dim    = "\033[2m"
)

// ─── StringSlice flag (repeatable -H) ─────────────────────────────────────────
type StringSlice []string

func (s *StringSlice) String() string     { return strings.Join(*s, ", ") }
func (s *StringSlice) Set(v string) error { *s = append(*s, v); return nil }

// ─── Config ───────────────────────────────────────────────────────────────────
type Config struct {
	// Input
	URLFile   string
	SingleURL string

	// Auth
	Cookie  string
	Token   string
	Headers StringSlice

	// Network
	Proxy     string
	Workers   int
	Timeout   int
	Delay     int
	Retries   int
	MaxBodyKB int

	// OOB
	OOBHost string
	OOBPort string
	SelfOOB bool

	// Modules
	ScanXXE   bool
	ScanGQL   bool
	ScanSSTI  bool
	ScanSSRF  bool
	ScanLog4j bool
	ScanProto bool

	// Output
	Output      string
	MarkdownOut string
	Verbose     bool
	Silent      bool
	ResumeFile  string
	NoResume    bool

	// Evasion
	WAFBypass bool
	RotateUA  bool
	RandomXFF bool

	// Internal
	httpClient *http.Client
}

func (c *Config) initClient() {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	if c.Proxy != "" {
		proxyURL, err := url.Parse(c.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	c.httpClient = &http.Client{
		Timeout:   time.Duration(c.Timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ─── User Agents pool ─────────────────────────────────────────────────────────
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"curl/8.6.0",
	"python-requests/2.31.0",
}

var uaIndex int
var uaMu = struct{ mu interface{} }{}

func nextUA(rotate bool) string {
	if !rotate {
		return userAgents[0]
	}
	ua := userAgents[uaIndex%len(userAgents)]
	uaIndex++
	return ua
}

// ─── Logging ──────────────────────────────────────────────────────────────────
func logInfo(msg string) {
	fmt.Printf("%s[*]%s %s\n", Cyan, Reset, msg)
}

func logWarn(msg string) {
	fmt.Printf("%s[!]%s %s\n", Yellow, Reset, msg)
}

func logDebug(msg string) {
	fmt.Printf("%s[~]%s %s\n", Dim, Reset, msg)
}

func severityColor(sev string) string {
	switch sev {
	case "CRITICAL":
		return Red
	case "HIGH":
		return Orange
	case "MEDIUM":
		return Yellow
	case "LOW":
		return Green
	default:
		return Dim
	}
}

func severityIcon(sev string) string {
	switch sev {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "⚪"
	}
}
