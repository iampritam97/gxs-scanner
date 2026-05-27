package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	banner()

	cfg := &Config{}

	// Input
	flag.StringVar(&cfg.URLFile, "urls", "-", "File of target URLs (use - for stdin)")
	flag.StringVar(&cfg.SingleURL, "u", "", "Single target URL")

	// Auth
	flag.StringVar(&cfg.Cookie, "cookie", "", "Cookie header value")
	flag.StringVar(&cfg.Token, "auth", "", "Authorization header value (e.g. 'Bearer TOKEN')")
	flag.Var(&cfg.Headers, "H", "Custom header (repeatable, e.g. -H 'X-Api-Key: abc')")

	// Network
	flag.StringVar(&cfg.Proxy, "proxy", "", "HTTP proxy (e.g. http://127.0.0.1:8080)")
	flag.IntVar(&cfg.Workers, "workers", 5, "Concurrent workers")
	flag.IntVar(&cfg.Timeout, "timeout", 15, "HTTP timeout (seconds)")
	flag.IntVar(&cfg.Delay, "delay", 0, "Delay between requests per target (ms)")
	flag.IntVar(&cfg.Retries, "retries", 2, "Retries on network error")
	flag.IntVar(&cfg.MaxBodyKB, "max-body", 512, "Max response body size (KB)")

	// OOB
	flag.StringVar(&cfg.OOBHost, "oob", "", "OOB callback host (e.g. your.burpcollaborator.net)")
	flag.StringVar(&cfg.OOBPort, "oob-port", "8888", "Local OOB listener port")
	flag.BoolVar(&cfg.SelfOOB, "self-oob", false, "Start local OOB callback server")

	// Modules
	flag.BoolVar(&cfg.ScanXXE, "xxe", true, "Enable XXE scanner")
	flag.BoolVar(&cfg.ScanGQL, "gql", true, "Enable GraphQL scanner")
	flag.BoolVar(&cfg.ScanSSTI, "ssti", true, "Enable SSTI scanner")
	flag.BoolVar(&cfg.ScanSSRF, "ssrf", true, "Enable SSRF scanner")
	flag.BoolVar(&cfg.ScanLog4j, "log4j", true, "Enable Log4Shell scanner")
	flag.BoolVar(&cfg.ScanProto, "proto", true, "Enable Prototype Pollution scanner")

	// Output
	flag.StringVar(&cfg.Output, "o", "findings.json", "JSON output file")
	flag.StringVar(&cfg.MarkdownOut, "md", "", "Markdown report output file")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose: print all requests")
	flag.BoolVar(&cfg.Silent, "silent", false, "Silent: only print findings")
	flag.StringVar(&cfg.ResumeFile, "resume", ".gxs_resume", "Resume/checkpoint file")
	flag.BoolVar(&cfg.NoResume, "no-resume", false, "Ignore existing resume file")

	// Evasion
	flag.BoolVar(&cfg.WAFBypass, "waf-bypass", false, "Enable WAF evasion encodings")
	flag.BoolVar(&cfg.RotateUA, "rotate-ua", true, "Rotate User-Agent strings")
	flag.BoolVar(&cfg.RandomXFF, "random-xff", false, "Randomize X-Forwarded-For header")

	flag.Parse()

	if cfg.URLFile == "" && cfg.SingleURL == "" {
		fmt.Printf("%s[!] Provide -urls <file> or -u <url>%s\n", Red, Reset)
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Validate
	if cfg.Silent && cfg.Verbose {
		fmt.Printf("%s[!] -silent and -v are mutually exclusive%s\n", Yellow, Reset)
		cfg.Verbose = false
	}

	// Init HTTP client
	cfg.initClient()

	// OOB server
	oobSrv := NewOOBServer()
	if cfg.SelfOOB {
		oobSrv.Start(cfg.OOBPort)
		if cfg.OOBHost == "" {
			cfg.OOBHost = fmt.Sprintf("127.0.0.1:%s", cfg.OOBPort)
		}
	}

	// Load URLs
	urls, err := loadURLs(cfg)
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", Red, err, Reset)
		os.Exit(1)
	}

	// Resume
	progress := NewProgress(cfg.ResumeFile)
	if !cfg.NoResume {
		progress.Load()
	}

	remaining := progress.Filter(urls)
	if len(remaining) < len(urls) && !cfg.Silent {
		logInfo(fmt.Sprintf("Resuming: %d/%d targets remaining (skipping %d done)",
			len(remaining), len(urls), len(urls)-len(remaining)))
	}

	if !cfg.Silent {
		logInfo(fmt.Sprintf("Targets: %d | Workers: %d | Timeout: %ds | Delay: %dms",
			len(remaining), cfg.Workers, cfg.Timeout, cfg.Delay))
		logInfo(fmt.Sprintf("Modules: XXE=%v GQL=%v SSTI=%v SSRF=%v Log4j=%v Proto=%v",
			cfg.ScanXXE, cfg.ScanGQL, cfg.ScanSSTI, cfg.ScanSSRF, cfg.ScanLog4j, cfg.ScanProto))
		if cfg.OOBHost != "" {
			logInfo(fmt.Sprintf("OOB: %s", cfg.OOBHost))
		}
		if cfg.Proxy != "" {
			logInfo(fmt.Sprintf("Proxy: %s", cfg.Proxy))
		}
		if cfg.WAFBypass {
			logInfo("WAF bypass encodings: enabled")
		}
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n%s[!] Interrupted — saving progress...%s\n", Yellow, Reset)
		cancel()
	}()

	// Run scanner
	scanner := NewScanner(cfg, oobSrv, progress)
	scanner.Run(ctx, remaining)

	cancel()

	// Reports
	reporter := NewReporter(scanner.Findings())
	reporter.PrintSummary()
	if cfg.Output != "" {
		reporter.WriteJSON(cfg.Output)
	}
	if cfg.MarkdownOut != "" {
		reporter.WriteMarkdown(cfg.MarkdownOut)
	}
}

func loadURLs(cfg *Config) ([]string, error) {
	var lines []string

	if cfg.SingleURL != "" {
		return []string{cfg.SingleURL}, nil
	}

	var r io.Reader
	if cfg.URLFile == "-" {
		r = os.Stdin
		if !cfg.Silent {
			logInfo("Reading URLs from stdin...")
		}
	} else {
		f, err := os.Open(cfg.URLFile)
		if err != nil {
			return nil, fmt.Errorf("cannot open URL file: %v", err)
		}
		defer f.Close()
		r = f
	}

	sc := bufio.NewScanner(r)
	seen := make(map[string]bool)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !seen[line] {
			seen[line] = true
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("no URLs loaded")
	}
	return lines, nil
}

func banner() {
	fmt.Printf(`%s
 ██████╗ ██╗  ██╗███████╗    ██╗   ██╗██████╗      ██████╗ 
██╔════╝ ╚██╗██╔╝██╔════╝    ██║   ██║╚════██╗    ██╔═████╗
██║  ███╗ ╚███╔╝ ███████╗    ██║   ██║ █████╔╝    ██║██╔██║
██║   ██║ ██╔██╗ ╚════██║    ╚██╗ ██╔╝██╔═══╝     ████╔╝██║
╚██████╔╝██╔╝ ██╗███████║     ╚████╔╝ ███████╗    ╚██████╔╝
 ╚═════╝ ╚═╝  ╚═╝╚══════╝     ╚═══╝  ╚══════╝     ╚═════╝ 
%s  v2.0 — Deep Vulnerability Scanner for Bug Bounty%s
  XXE | GraphQL | SSTI | SSRF | Log4Shell | Prototype Pollution
  In-band | OOB | Blind | Time-based | WAF Bypass | Auth Support
%s`, Cyan, Yellow, Reset, Reset)
	fmt.Printf("%s  %s%s\n\n", Dim, time.Now().Format("2006-01-02 15:04:05"), Reset)
}
