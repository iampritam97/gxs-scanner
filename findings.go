package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FINDINGS
// ═══════════════════════════════════════════════════════════════════════════════

type Finding struct {
	URL       string    `json:"url"`
	Vuln      string    `json:"vulnerability"`
	Type      string    `json:"type"`
	Payload   string    `json:"payload"`
	Evidence  string    `json:"evidence"`
	Severity  string    `json:"severity"`
	CVSS      float64   `json:"cvss_score"`
	Timestamp time.Time `json:"timestamp"`
	Request   string    `json:"request,omitempty"`
	Response  string    `json:"response_snippet,omitempty"`
}

type FindingStore struct {
	mu       sync.Mutex
	findings []Finding
	silent   bool
	verbose  bool
}

func NewFindingStore(silent, verbose bool) *FindingStore {
	return &FindingStore{silent: silent, verbose: verbose}
}

func (fs *FindingStore) Add(f Finding) {
	f.Timestamp = time.Now()
	f.CVSS = cvssScore(f.Vuln, f.Type, f.Severity)
	fs.mu.Lock()
	// Deduplicate: same URL + vuln + type + payload
	key := f.URL + "|" + f.Vuln + "|" + f.Type + "|" + f.Payload
	for _, existing := range fs.findings {
		existingKey := existing.URL + "|" + existing.Vuln + "|" + existing.Type + "|" + existing.Payload
		if existingKey == key {
			fs.mu.Unlock()
			return
		}
	}
	fs.findings = append(fs.findings, f)
	fs.mu.Unlock()

	if !fs.silent {
		fs.print(f)
	}
}

func (fs *FindingStore) print(f Finding) {
	color := severityColor(f.Severity)
	icon := severityIcon(f.Severity)
	fmt.Printf("\n%s%s [%s%s%s%s] %s → %s%s\n",
		color, icon, Bold, f.Vuln, Reset, color, f.Type, f.URL, Reset)
	fmt.Printf("  %sPayload:%s  %s\n", Dim, Reset, truncate(f.Payload, 120))
	fmt.Printf("  %sEvidence:%s %s\n", Dim, Reset, truncate(f.Evidence, 200))
	fmt.Printf("  %sCVSS:%s     %.1f | %sSeverity:%s %s%s%s\n\n",
		Dim, Reset, f.CVSS, Dim, Reset, color, f.Severity, Reset)
}

func (fs *FindingStore) All() []Finding {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make([]Finding, len(fs.findings))
	copy(out, fs.findings)
	return out
}

// cvssScore returns a rough CVSS 3.1 base score
func cvssScore(vuln, typ, severity string) float64 {
	base := map[string]float64{
		"CRITICAL": 9.0,
		"HIGH":     7.5,
		"MEDIUM":   5.5,
		"LOW":      3.0,
	}[severity]

	// Adjust by detection type
	if strings.Contains(typ, "RCE") {
		base = 9.8
	} else if strings.Contains(typ, "OOB") {
		base += 0.5
	} else if strings.Contains(typ, "Blind") || strings.Contains(typ, "Time-based") {
		base -= 0.5
	}

	// Cap at 10.0
	if base > 10.0 {
		base = 10.0
	}
	return base
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ═══════════════════════════════════════════════════════════════════════════════
// OOB SERVER
// ═══════════════════════════════════════════════════════════════════════════════

type OOBServer struct {
	mu   sync.Mutex
	hits map[string]OOBHit
	mux  *http.ServeMux
}

type OOBHit struct {
	RemoteAddr string
	Time       time.Time
	Headers    http.Header
}

func NewOOBServer() *OOBServer {
	s := &OOBServer{
		hits: make(map[string]OOBHit),
		mux:  http.NewServeMux(),
	}
	s.mux.HandleFunc("/oob/", s.handleOOB)
	s.mux.HandleFunc("/dns/", s.handleOOB) // also catch DNS-style paths
	return s
}

func (s *OOBServer) Start(port string) {
	go func() {
		srv := &http.Server{Addr: ":" + port, Handler: s.mux}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logWarn(fmt.Sprintf("OOB server error: %v", err))
		}
	}()
	logInfo(fmt.Sprintf("OOB server listening on :%s/oob/<id>", port))
}

func (s *OOBServer) handleOOB(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/oob/")
	id = strings.TrimPrefix(id, "/dns/")
	id = strings.Trim(id, "/")

	s.mu.Lock()
	s.hits[id] = OOBHit{
		RemoteAddr: r.RemoteAddr,
		Time:       time.Now(),
		Headers:    r.Header.Clone(),
	}
	s.mu.Unlock()
	fmt.Fprintf(w, "OK")
}

func (s *OOBServer) Check(id string, wait time.Duration) (bool, OOBHit) {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if hit, ok := s.hits[id]; ok {
			s.mu.Unlock()
			return true, hit
		}
		s.mu.Unlock()
		time.Sleep(300 * time.Millisecond)
	}
	return false, OOBHit{}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROGRESS / RESUME
// ═══════════════════════════════════════════════════════════════════════════════

type Progress struct {
	file string
	mu   sync.Mutex
	done map[string]bool
}

func NewProgress(file string) *Progress {
	return &Progress{file: file, done: make(map[string]bool)}
}

func (p *Progress) Load() {
	f, err := os.Open(p.file)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			p.done[line] = true
		}
	}
	if len(p.done) > 0 {
		logInfo(fmt.Sprintf("Loaded resume checkpoint: %d completed targets", len(p.done)))
	}
}

func (p *Progress) Mark(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done[url] = true
	f, err := os.OpenFile(p.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, url)
}

func (p *Progress) Filter(urls []string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var remaining []string
	for _, u := range urls {
		if !p.done[u] {
			remaining = append(remaining, u)
		}
	}
	return remaining
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPORTER
// ═══════════════════════════════════════════════════════════════════════════════

type Reporter struct {
	findings []Finding
}

func NewReporter(findings []Finding) *Reporter {
	return &Reporter{findings: findings}
}

func (r *Reporter) PrintSummary() {
	counts := map[string]int{}
	vulnMap := map[string]int{}
	for _, f := range r.findings {
		counts[f.Severity]++
		vulnMap[f.Vuln]++
	}

	fmt.Printf("\n%s%s══════════════════════ SCAN COMPLETE ══════════════════════%s\n", Bold, Cyan, Reset)
	fmt.Printf("  Total findings: %s%d%s\n\n", Bold, len(r.findings), Reset)

	if len(r.findings) == 0 {
		fmt.Printf("  %s✓ No vulnerabilities found.%s\n\n", Green, Reset)
		return
	}

	fmt.Printf("  %s🔴 CRITICAL: %-3d%s  %s🟠 HIGH:   %-3d%s\n",
		Red, counts["CRITICAL"], Reset, Orange, counts["HIGH"], Reset)
	fmt.Printf("  %s🟡 MEDIUM:   %-3d%s  %s🟢 LOW:    %-3d%s\n\n",
		Yellow, counts["MEDIUM"], Reset, Green, counts["LOW"], Reset)

	fmt.Printf("  %sBy vulnerability type:%s\n", Dim, Reset)
	for v, c := range vulnMap {
		fmt.Printf("    %-20s %d finding(s)\n", v, c)
	}

	fmt.Printf("\n  %sFindings:%s\n", Dim, Reset)
	for i, f := range r.findings {
		color := severityColor(f.Severity)
		fmt.Printf("  %s[%02d]%s %s%-8s%s %-12s %sCVSS:%.1f%s  %s\n",
			Dim, i+1, Reset,
			color, f.Severity, Reset,
			f.Vuln,
			Dim, f.CVSS, Reset,
			f.URL,
		)
	}
	fmt.Println()
}

func (r *Reporter) WriteJSON(path string) {
	data, err := json.MarshalIndent(r.findings, "", "  ")
	if err != nil {
		logWarn(fmt.Sprintf("JSON marshal error: %v", err))
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		logWarn(fmt.Sprintf("Cannot write JSON report: %v", err))
		return
	}
	logInfo(fmt.Sprintf("JSON report saved → %s (%d findings)", path, len(r.findings)))
}

func (r *Reporter) WriteMarkdown(path string) {
	var sb strings.Builder

	sb.WriteString("# GXS Scanner v2.0 — Vulnerability Report\n\n")
	sb.WriteString(fmt.Sprintf("**Scan Date:** %s  \n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d\n\n", len(r.findings)))

	counts := map[string]int{}
	for _, f := range r.findings {
		counts[f.Severity]++
	}

	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		sb.WriteString(fmt.Sprintf("| %s | %d |\n", sev, counts[sev]))
	}
	sb.WriteString("\n---\n\n")

	sb.WriteString("## Findings\n\n")
	for i, f := range r.findings {
		sb.WriteString(fmt.Sprintf("### [%02d] %s — %s\n\n", i+1, f.Vuln, f.Type))
		sb.WriteString(fmt.Sprintf("| Field | Value |\n|---|---|\n"))
		sb.WriteString(fmt.Sprintf("| **URL** | `%s` |\n", f.URL))
		sb.WriteString(fmt.Sprintf("| **Severity** | %s |\n", f.Severity))
		sb.WriteString(fmt.Sprintf("| **CVSS** | %.1f |\n", f.CVSS))
		sb.WriteString(fmt.Sprintf("| **Timestamp** | %s |\n", f.Timestamp.Format(time.RFC3339)))
		sb.WriteString("\n**Payload:**\n```\n" + f.Payload + "\n```\n\n")
		sb.WriteString("**Evidence:**\n> " + f.Evidence + "\n\n")
		if f.Request != "" {
			sb.WriteString("**Request:**\n```http\n" + f.Request + "\n```\n\n")
		}
		if f.Response != "" {
			sb.WriteString("**Response Snippet:**\n```\n" + f.Response + "\n```\n\n")
		}
		sb.WriteString("---\n\n")
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		logWarn(fmt.Sprintf("Cannot write Markdown report: %v", err))
		return
	}
	logInfo(fmt.Sprintf("Markdown report saved → %s", path))
}
