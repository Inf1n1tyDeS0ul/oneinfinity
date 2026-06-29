// Package crawler implements a concurrent BFS HTTP crawler with:
//   - configurable worker-pool parallelism
//   - per-host connection limits
//   - global FD budget (max 200 concurrent connections)
//   - HTTP/2 support via golang.org/x/net/http2
//   - extraction of URLs, forms, and JS files
//   - JS endpoint extraction from script bodies
//   - sensitive parameter probing
//   - technology fingerprinting
//   - sensitive file discovery
//   - stable event_id per discovered URL (SHA-256 of scan_id+url)
package crawler

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// rotateUserAgents is a diverse set of real browser/crawler UAs for stealth crawling.
// Selected to include modern Chrome, Firefox, Safari, and common bot-friendly crawlers
// to avoid trivial WAF UA-signature blocks.
var rotateUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"OIScanner/2.0 (+https://github.com/oneinfinity)",
}

func pickUserAgent() string {
	return rotateUserAgents[rand.Intn(len(rotateUserAgents))]
}

const (
	defaultParallelism = 50
	maxParallelism     = 200
	perHostConnLimit   = 10
	globalFDLimit      = 200
	defaultMaxPages    = 500
	requestTimeout     = 15 * time.Second
	maxBodyBytes       = 2 << 20 // 2 MB
)

// Fingerprint holds detected technology stack information for a crawled URL.
type Fingerprint struct {
	Framework string
	Server    string
	CMS       string
	CDN       string
	WAF       string
}

// ParamProbe records a parameter probe that triggered a notable response.
type ParamProbe struct {
	Param      string
	StatusCode int
}

// Result holds everything we learn about a single crawled URL.
type Result struct {
	URL          string
	Method       string
	StatusCode   int
	Forms        []string    // "action|method" pairs
	JsFiles      []string
	JSEndpoints  []string    // endpoints extracted from JS source
	Fingerprint  *Fingerprint
	ParamProbes  []ParamProbe // params that triggered non-baseline responses
	SensitiveHit []string    // sensitive file paths that returned 200/206
	EventID      string      // SHA-256(scanID + "\x00" + url)
}

// Config drives a single crawl run.
type Config struct {
	StartURL         string
	ScanID           string
	MaxPages         int
	Parallelism      int
	ExcludedPatterns []string
}

// sensitiveFiles are probed once per discovered base domain.
var sensitiveFiles = []string{
	"/.git/HEAD",
	"/.env",
	"/config.php",
	"/wp-config.php",
	"/.aws/credentials",
	"/api/swagger.json",
	"/api/openapi.json",
	"/api-docs",
	"/actuator/env",
	"/actuator/heapdump",
	"/debug/pprof",
	"/.well-known/security.txt",
	"/server-status",
	"/phpinfo.php",
	"/.htaccess",
	"/web.config",
	"/crossdomain.xml",
	"/sitemap.xml",
	"/.DS_Store",
	"/backup.sql",
	"/dump.sql",
	"/database.sql",
	"/admin/",
	"/administrator/",
	"/phpmyadmin/",
}

// sensitiveParams are appended to each crawled URL to test for different responses.
var sensitiveParams = []string{
	"debug=true",
	"admin=true",
	"test=1",
	"internal=1",
	"env=dev",
	"verbose=1",
	"trace=1",
	"dev=1",
}

// Run executes the crawl and streams Result values into results until finished
// or done is closed. Returns immediately if start_url resolves to a private IP.
func Run(cfg Config, results chan<- Result, done <-chan struct{}) {
	if cfg.Parallelism <= 0 {
		cfg.Parallelism = defaultParallelism
	}
	if cfg.Parallelism > maxParallelism {
		cfg.Parallelism = maxParallelism
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = defaultMaxPages
	}

	start, err := url.Parse(cfg.StartURL)
	if err != nil {
		return
	}
	if err := validateTarget(cfg.StartURL); err != nil {
		return
	}
	baseHost := start.Host

	client := buildClient()

	// Track domains already probed for sensitive files so we probe once per domain.
	var probedDomains sync.Map

	type job struct{ u string }
	queue := make(chan job, cfg.MaxPages*4+1)
	queue <- job{cfg.StartURL}

	var (
		visited   sync.Map
		pageCount int64
		wg        sync.WaitGroup
	)

	// semaphore enforces global FD/connection budget
	concurrency := cfg.Parallelism
	if concurrency > globalFDLimit {
		concurrency = globalFDLimit
	}
	sem := make(chan struct{}, concurrency)

	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			case j, ok := <-queue:
				if !ok {
					return
				}
				if atomic.LoadInt64(&pageCount) >= int64(cfg.MaxPages) {
					return
				}
				if _, loaded := visited.LoadOrStore(j.u, struct{}{}); loaded {
					continue
				}
				if matchesAny(j.u, cfg.ExcludedPatterns) {
					continue
				}
				if !sameDomain(j.u, baseHost) {
					continue
				}

				sem <- struct{}{}
				result, links := fetch(client, j.u, cfg.ScanID)
				<-sem

				if result == nil {
					continue
				}
				atomic.AddInt64(&pageCount, 1)

				// Probe sensitive files once per base domain (origin).
				parsedU, _ := url.Parse(j.u)
				if parsedU != nil {
					origin := parsedU.Scheme + "://" + parsedU.Host
					if _, alreadyProbed := probedDomains.LoadOrStore(origin, struct{}{}); !alreadyProbed {
						sem <- struct{}{}
						hits := probeSensitiveFiles(client, origin, cfg.ScanID)
						<-sem
						for _, h := range hits {
							select {
							case results <- h:
							case <-done:
								return
							}
						}
					}
				}

				// Probe sensitive parameters on this specific URL.
				sem <- struct{}{}
				probes := probeParams(client, j.u)
				<-sem
				result.ParamProbes = probes

				// Extract JS endpoints from JS file bodies.
				if strings.HasSuffix(strings.Split(j.u, "?")[0], ".js") {
					sem <- struct{}{}
					jsEPs := fetchAndExtractJSEndpoints(client, j.u, parsedU)
					<-sem
					result.JSEndpoints = jsEPs
					// Queue discovered JS endpoints for crawling.
					for _, ep := range jsEPs {
						if abs := resolve(parsedU, ep); abs != "" {
							select {
							case queue <- job{abs}:
							default:
							}
						}
					}
				}

				select {
				case results <- *result:
				case <-done:
					return
				}

				if atomic.LoadInt64(&pageCount) < int64(cfg.MaxPages) {
					for _, l := range links {
						select {
						case queue <- job{l}:
						default:
						}
					}
					// Also queue JS files discovered for endpoint extraction.
					for _, jsFile := range result.JsFiles {
						select {
						case queue <- job{jsFile}:
						default:
						}
					}
				}
			}
		}
	}

	for i := 0; i < cfg.Parallelism; i++ {
		wg.Add(1)
		go worker()
	}

	wg.Wait()
	close(queue)
}

// fetch GETs rawURL, extracts links/forms/JS, fingerprints the response.
func fetch(client *http.Client, rawURL, scanID string) (*Result, []string) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", pickUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	bodyStr := string(body)

	base, _ := url.Parse(rawURL)

	fp := fingerprintResponse(resp, bodyStr)

	result := &Result{
		URL:         rawURL,
		Method:      http.MethodGet,
		StatusCode:  resp.StatusCode,
		EventID:     stableEventID(scanID, rawURL),
		Forms:       extractForms(bodyStr),
		JsFiles:     extractJSFiles(bodyStr, base),
		Fingerprint: fp,
	}

	return result, extractLinks(bodyStr, base)
}

// ─── HTML extraction ──────────────────────────────────────────────────────────

var (
	hrefRe    = regexp.MustCompile(`(?i)href\s*=\s*["']([^"'#\s]+)`)
	srcRe     = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']([^"'\s]+)`)
	actionRe  = regexp.MustCompile(`(?i)\baction\s*=\s*["']([^"'\s]*)`)
	dataURLRe = regexp.MustCompile(`(?i)\bdata-url\s*=\s*["']([^"'\s]+)`)
	fetchRe   = regexp.MustCompile("fetch\\s*\\(\\s*[\"'`]([^\"'`\\s]+)[\"'`]")
	xhrRe     = regexp.MustCompile(`\.open\s*\(\s*["'][^"']+["']\s*,\s*["']([^"'\s]+)["']`)
	formRe    = regexp.MustCompile(`(?is)<form([^>]*)>`)
	jsExtRe   = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']([^"'\s]+\.js(?:\?[^"'\s]*)?)["']`)
	attrValRe = regexp.MustCompile(`(?i)\b(\w[\w-]*)\s*=\s*["']([^"']*)["']`)
)

func extractLinks(body string, base *url.URL) []string {
	seen := make(map[string]bool)
	var out []string
	for _, re := range []*regexp.Regexp{hrefRe, srcRe, actionRe, dataURLRe, fetchRe, xhrRe} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) < 2 {
				continue
			}
			if abs := resolve(base, m[1]); abs != "" && !seen[abs] {
				seen[abs] = true
				out = append(out, abs)
			}
		}
	}
	return out
}

func extractForms(body string) []string {
	var out []string
	for _, m := range formRe.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		attrs := m[1]
		action := attrVal(attrs, "action")
		method := strings.ToUpper(attrVal(attrs, "method"))
		if method == "" {
			method = "GET"
		}
		out = append(out, action+"|"+method)
	}
	return out
}

func extractJSFiles(body string, base *url.URL) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range jsExtRe.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		if abs := resolve(base, m[1]); abs != "" && !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	return out
}

// ─── JS endpoint extraction ───────────────────────────────────────────────────

var (
	// fetch('/api/...') or fetch("/api/...")  or fetch(`/api/...`)
	jsFetchRe = regexp.MustCompile("fetch\\s*\\(\\s*[\"'`]([^\"'`\\s,)]+)[\"'`]")
	// axios.get('/api/...') / axios.post / axios.put / axios.delete etc.
	jsAxiosRe = regexp.MustCompile(`axios\s*\.\s*\w+\s*\(\s*["'` + "`" + `]([^"'` + "`" + `\s,)]+)["'` + "`" + `]`)
	// xhr.open('GET', '/path')
	jsXHRRe = regexp.MustCompile(`\.open\s*\(\s*["'][^"']+["']\s*,\s*["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `]`)
	// apiEndpoints = ['/foo', '/bar']  or  API_ENDPOINTS = [...]
	jsEndpointArrayRe = regexp.MustCompile(`(?i)(?:api[_-]?endpoints?|endpoints?|routes?)\s*=\s*\[([^\]]+)\]`)
	// const API_URL = '...' or const BASE_URL = '...'
	jsAPIURLRe = regexp.MustCompile(`(?i)const\s+\w*(?:api|base|endpoint)\w*\s*=\s*["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `]`)
	// string literal that looks like an API path: '/api/v1/...'
	jsPathLiteralRe = regexp.MustCompile(`["'` + "`" + `](/(?:api|v\d|graphql|rest|internal|admin|user|auth|oauth|service)[^"'` + "`" + `\s]*)["'` + "`" + `]`)
)

// extractJSEndpoints scans JS source text and returns all discovered path/URL strings.
func extractJSEndpoints(jsBody string, base *url.URL) []string {
	seen := make(map[string]bool)
	var out []string

	emit := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			return
		}
		seen[raw] = true
		out = append(out, raw)
	}

	for _, re := range []*regexp.Regexp{jsFetchRe, jsAxiosRe, jsXHRRe, jsAPIURLRe, jsPathLiteralRe} {
		for _, m := range re.FindAllStringSubmatch(jsBody, -1) {
			if len(m) >= 2 {
				emit(m[1])
			}
		}
	}

	// Extract individual strings from endpoint arrays.
	strLitRe := regexp.MustCompile(`["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `]`)
	for _, m := range jsEndpointArrayRe.FindAllStringSubmatch(jsBody, -1) {
		if len(m) < 2 {
			continue
		}
		for _, sm := range strLitRe.FindAllStringSubmatch(m[1], -1) {
			if len(sm) >= 2 {
				emit(sm[1])
			}
		}
	}

	return out
}

// fetchAndExtractJSEndpoints fetches a JS URL and extracts API endpoint strings.
func fetchAndExtractJSEndpoints(client *http.Client, jsURL string, base *url.URL) []string {
	req, err := http.NewRequest(http.MethodGet, jsURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", pickUserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return extractJSEndpoints(string(body), base)
}

// ─── Parameter probing ────────────────────────────────────────────────────────

// probeParams appends each sensitiveParam to rawURL, issues a GET, and records
// any response whose status code differs from the baseline.
func probeParams(client *http.Client, rawURL string) []ParamProbe {
	// Establish baseline.
	baseline := headStatus(client, rawURL)
	if baseline == 0 {
		return nil
	}

	var out []ParamProbe
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	for _, param := range sensitiveParams {
		probeURL := *u // copy
		existing := probeURL.RawQuery
		if existing == "" {
			probeURL.RawQuery = param
		} else {
			probeURL.RawQuery = existing + "&" + param
		}
		code := headStatus(client, probeURL.String())
		if code != 0 && code != baseline {
			out = append(out, ParamProbe{Param: param, StatusCode: code})
		}
	}
	return out
}

// headStatus does a lightweight HEAD (falling back to GET) and returns the status code.
func headStatus(client *http.Client, rawURL string) int {
	req, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", pickUserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	// If HEAD is not supported fall back to GET with no body read.
	if resp.StatusCode == http.StatusMethodNotAllowed {
		req2, err2 := http.NewRequest(http.MethodGet, rawURL, nil)
		if err2 != nil {
			return 0
		}
		req2.Header.Set("User-Agent", pickUserAgent())
		resp2, err2 := client.Do(req2)
		if err2 != nil {
			return 0
		}
		io.Copy(io.Discard, io.LimitReader(resp2.Body, 512))
		resp2.Body.Close()
		return resp2.StatusCode
	}
	return resp.StatusCode
}

// ─── Technology fingerprinting ────────────────────────────────────────────────

var (
	metaGeneratorRe = regexp.MustCompile(`(?i)<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)["']`)
	metaGeneratorRe2 = regexp.MustCompile(`(?i)<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]+name\s*=\s*["']generator["']`)
)

// fingerprintResponse extracts technology signals from response headers and body.
func fingerprintResponse(resp *http.Response, body string) *Fingerprint {
	fp := &Fingerprint{}

	// Server header.
	if sv := resp.Header.Get("Server"); sv != "" {
		fp.Server = sv
	}

	// Framework signals.
	if xpb := resp.Header.Get("X-Powered-By"); xpb != "" {
		fp.Framework = xpb
	}
	if xgen := resp.Header.Get("X-Generator"); xgen != "" {
		fp.Framework = xgen
	}
	// meta generator tag (take first match from either attribute order).
	if fp.Framework == "" {
		for _, re := range []*regexp.Regexp{metaGeneratorRe, metaGeneratorRe2} {
			if m := re.FindStringSubmatch(body); len(m) >= 2 {
				fp.Framework = m[1]
				break
			}
		}
	}

	// CMS detection from body/path indicators.
	switch {
	case strings.Contains(body, "wp-content/") || strings.Contains(body, "wp-includes/"):
		fp.CMS = "WordPress"
	case strings.Contains(body, "/sites/default/") || strings.Contains(body, "Drupal.settings"):
		fp.CMS = "Drupal"
	case strings.Contains(body, "Joomla!") || strings.Contains(body, "/components/com_"):
		fp.CMS = "Joomla"
	case strings.Contains(body, "/skin/frontend/") || strings.Contains(body, "Mage.Cookies"):
		fp.CMS = "Magento"
	case strings.Contains(body, "shopify") || resp.Header.Get("X-ShopId") != "":
		fp.CMS = "Shopify"
	}

	// CDN/proxy detection.
	switch {
	case resp.Header.Get("CF-Ray") != "":
		fp.CDN = "Cloudflare"
	case resp.Header.Get("X-Amz-Cf-Id") != "" || resp.Header.Get("X-Amz-Request-Id") != "":
		fp.CDN = "AWS CloudFront"
	case resp.Header.Get("X-Cache") != "" && strings.Contains(strings.ToLower(resp.Header.Get("Via")), "akamai"):
		fp.CDN = "Akamai"
	case resp.Header.Get("X-Cache") != "" && strings.Contains(strings.ToLower(resp.Header.Get("Via")), "fastly"):
		fp.CDN = "Fastly"
	case resp.Header.Get("X-Served-By") != "" && strings.Contains(resp.Header.Get("X-Served-By"), "cache-"):
		fp.CDN = "Fastly"
	case resp.Header.Get("X-Cache") != "":
		fp.CDN = "CDN (unknown)"
	}

	// WAF detection heuristics.
	if resp.StatusCode == 403 {
		body403 := strings.ToLower(body)
		switch {
		case strings.Contains(body403, "cloudflare") || resp.Header.Get("CF-Ray") != "":
			fp.WAF = "Cloudflare WAF"
		case strings.Contains(body403, "aws waf") || strings.Contains(body403, "awswaf"):
			fp.WAF = "AWS WAF"
		case strings.Contains(body403, "mod_security") || strings.Contains(body403, "modsecurity"):
			fp.WAF = "ModSecurity"
		case strings.Contains(body403, "akamai"):
			fp.WAF = "Akamai Kona"
		case strings.Contains(body403, "sucuri"):
			fp.WAF = "Sucuri"
		case strings.Contains(body403, "incapsula") || resp.Header.Get("X-Iinfo") != "":
			fp.WAF = "Imperva Incapsula"
		case strings.Contains(body403, "access denied") || strings.Contains(body403, "forbidden"):
			fp.WAF = "Unknown WAF (403)"
		}
	}

	return fp
}

// ─── Sensitive file discovery ─────────────────────────────────────────────────

// probeSensitiveFiles probes a list of common sensitive paths against origin.
// Returns a Result for each file that responds with 200 or 206.
func probeSensitiveFiles(client *http.Client, origin, scanID string) []Result {
	var out []Result
	for _, filePath := range sensitiveFiles {
		target := origin + filePath
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", pickUserAgent())
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent {
			out = append(out, Result{
				URL:          target,
				Method:       http.MethodGet,
				StatusCode:   resp.StatusCode,
				SensitiveHit: []string{filePath},
				EventID:      stableEventID(scanID, target),
			})
		}
	}
	return out
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func stableEventID(scanID, u string) string {
	h := sha256.Sum256([]byte(scanID + "\x00" + u))
	return fmt.Sprintf("%x", h)
}

func resolve(base *url.URL, ref string) string {
	if ref == "" ||
		strings.HasPrefix(ref, "javascript:") ||
		strings.HasPrefix(ref, "mailto:") ||
		strings.HasPrefix(ref, "data:") {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(r)
	abs.Fragment = ""
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	return abs.String()
}

func sameDomain(rawURL, baseHost string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Host == baseHost || strings.HasSuffix(u.Host, "."+baseHost)
}

func matchesAny(u string, patterns []string) bool {
	for _, p := range patterns {
		if globMatch(p, u) {
			return true
		}
	}
	return false
}

// globMatch does path.Match-style wildcard matching on the full URL and its path.
func globMatch(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return strings.Contains(s, pattern)
	}
	if matched, err := path.Match(pattern, s); err == nil && matched {
		return true
	}
	if u, err := url.Parse(s); err == nil {
		if matched, _ := path.Match(pattern, u.Path); matched {
			return true
		}
	}
	return false
}

func attrVal(attrs, name string) string {
	for _, m := range attrValRe.FindAllStringSubmatch(attrs, -1) {
		if len(m) >= 3 && strings.EqualFold(m[1], name) {
			return m[2]
		}
	}
	return ""
}

// buildClient creates an http.Client with HTTP/2 and per-host connection limits.
// The custom DialContext enforces the SSRF blocklist on every TCP connection,
// including post-redirect hops, so private/loopback/metadata IPs can never be reached.
func buildClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	t := &http.Transport{
		MaxIdleConnsPerHost: perHostConnLimit,
		MaxConnsPerHost:     perHostConnLimit,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec — scanner intentional
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("ssrf-guard: bad addr %q: %w", addr, err)
			}
			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("ssrf-guard: dns lookup %q: %w", host, err)
			}
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					continue
				}
				if isPrivateIP(ip) {
					return nil, fmt.Errorf("ssrf-guard: %s resolves to private/reserved IP %s", host, ipStr)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
		},
	}
	_ = http2.ConfigureTransport(t) // best-effort HTTP/2; ignore error
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: t,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// ─── SSRF guard ───────────────────────────────────────────────────────────────

// privateRanges lists all IP ranges that must never be fetched.
var privateRanges = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",          // "this" network
		"10.0.0.0/8",         // RFC 1918
		"100.64.0.0/10",      // shared address (carrier-grade NAT)
		"127.0.0.0/8",        // loopback
		"169.254.0.0/16",     // link-local / cloud metadata (169.254.169.254)
		"172.16.0.0/12",      // RFC 1918
		"192.0.0.0/24",       // IETF protocol assignments
		"192.168.0.0/16",     // RFC 1918
		"198.18.0.0/15",      // benchmarking
		"198.51.100.0/24",    // TEST-NET-2 (documentation)
		"203.0.113.0/24",     // TEST-NET-3 (documentation)
		"224.0.0.0/4",        // multicast
		"240.0.0.0/4",        // reserved
		"255.255.255.255/32", // broadcast
		"::1/128",            // IPv6 loopback
		"fc00::/7",           // IPv6 unique local
		"fe80::/10",          // IPv6 link-local
		"ff00::/8",           // IPv6 multicast
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}()

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// validateTarget does a pre-flight DNS resolution of rawURL's host and
// returns an error if any resolved IP is private/reserved.
func validateTarget(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("ssrf-guard: invalid url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("ssrf-guard: empty host in %q", rawURL)
	}
	// If it's already an IP literal, check directly without DNS.
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("ssrf-guard: start_url host %s is a private/reserved IP", host)
		}
		return nil
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("ssrf-guard: dns lookup %q: %w", host, err)
	}
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && isPrivateIP(ip) {
			return fmt.Errorf("ssrf-guard: start_url %q resolves to private IP %s", host, s)
		}
	}
	return nil
}
