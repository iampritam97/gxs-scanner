package main

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ─── Request/Response ─────────────────────────────────────────────────────────
type ReqOpts struct {
	Method      string
	URL         string
	ContentType string
	Body        string
	Headers     map[string]string
	Context     context.Context
}

type RespData struct {
	StatusCode int
	Headers    http.Header
	Body       string
	Elapsed    time.Duration
	Hash       string
}

// ─── Requester ────────────────────────────────────────────────────────────────
type Requester struct {
	cfg       *Config
	baselines map[string]*RespData // url -> baseline
}

func NewRequester(cfg *Config) *Requester {
	return &Requester{
		cfg:       cfg,
		baselines: make(map[string]*RespData),
	}
}

func (r *Requester) Do(opts ReqOpts) (*RespData, error) {
	var lastErr error
	for attempt := 0; attempt <= r.cfg.Retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * 500 * time.Millisecond
			time.Sleep(backoff)
		}
		resp, err := r.doOnce(opts)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (r *Requester) doOnce(opts ReqOpts) (*RespData, error) {
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}

	var bodyReader io.Reader
	if opts.Body != "" {
		bodyReader = strings.NewReader(opts.Body)
	}

	req, err := http.NewRequestWithContext(ctx, opts.Method, opts.URL, bodyReader)
	if err != nil {
		return nil, err
	}

	// UA
	req.Header.Set("User-Agent", nextUA(r.cfg.RotateUA))

	// Auth
	if r.cfg.Cookie != "" {
		req.Header.Set("Cookie", r.cfg.Cookie)
	}
	if r.cfg.Token != "" {
		req.Header.Set("Authorization", r.cfg.Token)
	}

	// Custom headers from config
	for _, h := range r.cfg.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Per-request headers
	if opts.ContentType != "" {
		req.Header.Set("Content-Type", opts.ContentType)
	}
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}

	// Random X-Forwarded-For
	if r.cfg.RandomXFF {
		req.Header.Set("X-Forwarded-For", randomIP())
	}

	// Delay
	if r.cfg.Delay > 0 {
		time.Sleep(time.Duration(r.cfg.Delay) * time.Millisecond)
	}

	start := time.Now()
	resp, err := r.cfg.httpClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	maxBytes := int64(r.cfg.MaxBodyKB) * 1024
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	bodyStr := string(bodyBytes)

	hash := fmt.Sprintf("%x", md5.Sum(bodyBytes))

	if r.cfg.Verbose {
		logDebug(fmt.Sprintf("%s %s → %d (%v) [%db]",
			opts.Method, opts.URL, resp.StatusCode, elapsed.Round(time.Millisecond), len(bodyBytes)))
	}

	return &RespData{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       bodyStr,
		Elapsed:    elapsed,
		Hash:       hash,
	}, nil
}

// Baseline: sends clean request to get normal response fingerprint
func (r *Requester) Baseline(ctx context.Context, targetURL string) *RespData {
	if b, ok := r.baselines[targetURL]; ok {
		return b
	}
	resp, err := r.Do(ReqOpts{Method: "GET", URL: targetURL, Context: ctx})
	if err != nil {
		return nil
	}
	r.baselines[targetURL] = resp
	return resp
}

// IsNewContent checks if payload response has meaningful diff from baseline
func (r *Requester) IsNewContent(baseline *RespData, resp *RespData, pattern *regexp.Regexp) bool {
	if baseline == nil {
		return pattern.MatchString(resp.Body)
	}
	// Pattern must appear in payload response but NOT in baseline
	if pattern.MatchString(baseline.Body) {
		return false // Already in baseline → false positive
	}
	return pattern.MatchString(resp.Body)
}

// ─── WAF Detection ────────────────────────────────────────────────────────────
type WAFType string

const (
	WAFNone       WAFType = "none"
	WAFCloudflare WAFType = "cloudflare"
	WAFAkamai     WAFType = "akamai"
	WAFAWSShield  WAFType = "aws"
	WAFImperva    WAFType = "imperva"
	WAFGeneric    WAFType = "generic"
)

var wafSignatures = map[WAFType][]string{
	WAFCloudflare: {"cf-ray", "cloudflare", "__cfduid", "cf-cache-status"},
	WAFAkamai:     {"akamai", "ak_bmsc", "x-akamai"},
	WAFAWSShield:  {"x-amzn-requestid", "x-amz-cf-id", "awselb"},
	WAFImperva:    {"x-iinfo", "visid_incap", "incap_ses"},
}

func DetectWAF(ctx context.Context, r *Requester, targetURL string) WAFType {
	resp, err := r.Do(ReqOpts{Method: "GET", URL: targetURL, Context: ctx})
	if err != nil {
		return WAFNone
	}

	combined := strings.ToLower(resp.Body)
	for k, v := range resp.Headers {
		combined += strings.ToLower(k) + ":" + strings.ToLower(strings.Join(v, ",")) + "\n"
	}

	for wafType, sigs := range wafSignatures {
		for _, sig := range sigs {
			if strings.Contains(combined, sig) {
				return wafType
			}
		}
	}

	// Generic WAF check: send obvious attack and see if blocked
	probe, _ := r.Do(ReqOpts{
		Method:  "GET",
		URL:     targetURL + "?x=<script>alert(1)</script>",
		Context: ctx,
	})
	if probe != nil && (probe.StatusCode == 403 || probe.StatusCode == 406 || probe.StatusCode == 429) {
		return WAFGeneric
	}

	return WAFNone
}

// ─── WAF Bypass Encodings ─────────────────────────────────────────────────────
func WAFVariants(payload string) []string {
	variants := []string{payload}

	// URL encode
	encoded := strings.NewReplacer(
		"<", "%3C", ">", "%3E",
		"'", "%27", "\"", "%22",
		"{", "%7B", "}", "%7D",
		"$", "%24", "#", "%23",
	).Replace(payload)
	if encoded != payload {
		variants = append(variants, encoded)
	}

	// Double URL encode
	double := strings.NewReplacer(
		"%", "%25",
	).Replace(encoded)
	if double != encoded {
		variants = append(variants, double)
	}

	// Unicode substitution for common chars
	unicode := strings.NewReplacer(
		"<", "\uFE64",
		">", "\uFE65",
		"'", "\u02BC",
		"\"", "\u02BA",
	).Replace(payload)
	if unicode != payload {
		variants = append(variants, unicode)
	}

	// Mixed case (for keyword-based WAFs)
	variants = append(variants, mixCase(payload))

	return variants
}

func mixCase(s string) string {
	var out strings.Builder
	for i, c := range s {
		if i%2 == 0 {
			out.WriteString(strings.ToUpper(string(c)))
		} else {
			out.WriteString(strings.ToLower(string(c)))
		}
	}
	return out.String()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
func randomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(223)+1,
		rand.Intn(255),
		rand.Intn(255),
		rand.Intn(254)+1,
	)
}

func randomID(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), rand.Intn(99999))
}
