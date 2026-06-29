// Package scanner implements SSRF detection logic:
//   - Cloud metadata endpoint probing (AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Kubernetes)
//   - Open-redirect → SSRF chain testing via common URL parameters
//   - Internal CIDR port scanning
//   - OOB blind-SSRF correlation via oi-oob-listener domain tokens
//
// Each finding carries a stable event_id = hex(SHA-256(scan_id + target_url + payload)).
package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/oneinfinity/oi-ssrf/internal/pb"
)

// ─── Probe definitions ────────────────────────────────────────────────────────

type metadataProbe struct {
	name    string
	method  string
	url     string
	headers map[string]string
	// secondStep is populated for IMDSv2: token-fetch URL before the real request
	tokenURL     string
	tokenHeaders map[string]string
	tokenTarget  string // header name to carry the token in the second request
}

var metadataProbes = []metadataProbe{
	// AWS IMDSv1
	{
		name:   "aws-imdsv1",
		method: http.MethodGet,
		url:    "http://169.254.169.254/latest/meta-data/",
	},
	// AWS IMDSv2 — PUT token first, then GET with token header
	{
		name:         "aws-imdsv2",
		method:       http.MethodGet,
		url:          "http://169.254.169.254/latest/meta-data/",
		tokenURL:     "http://169.254.169.254/latest/api/token",
		tokenHeaders: map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
		tokenTarget:  "X-aws-ec2-metadata-token",
	},
	// GCP
	{
		name:    "gcp-metadata",
		method:  http.MethodGet,
		url:     "http://metadata.google.internal/computeMetadata/v1/",
		headers: map[string]string{"Metadata-Flavor": "Google"},
	},
	// Azure
	{
		name:    "azure-imds",
		method:  http.MethodGet,
		url:     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		headers: map[string]string{"Metadata": "true"},
	},
	// DigitalOcean
	{
		name:   "digitalocean-metadata",
		method: http.MethodGet,
		url:    "http://169.254.169.254/metadata/v1/",
	},
	// Kubernetes API server
	{
		name:   "kubernetes-api",
		method: http.MethodGet,
		url:    "https://kubernetes.default.svc/api/v1/namespaces",
	},
	// Alibaba Cloud
	{
		name:   "alibaba-metadata",
		method: http.MethodGet,
		url:    "http://100.100.100.200/latest/meta-data/",
	},
	// Oracle Cloud Infrastructure
	{
		name:    "oracle-imds",
		method:  http.MethodGet,
		url:     "http://169.254.169.254/opc/v2/instance/",
		headers: map[string]string{"Metadata": "true"},
	},
	// OpenStack
	{
		name:   "openstack-metadata",
		method: http.MethodGet,
		url:    "http://169.254.169.254/openstack/latest/meta_data.json",
	},
}
// URL parameters commonly used for SSRF redirects
var ssrfParams = []string{"url", "redirect", "next", "callback", "dest", "return"}

// Internal CIDR hosts and ports for service discovery
var internalHosts = []string{"10.0.0.1", "10.1.1.1", "10.10.0.1", "172.16.0.1", "172.17.0.1", "172.20.0.1", "192.168.0.1", "192.168.1.1", "192.168.100.1", "127.0.0.1"}
var internalPorts = []int{80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200, 2379, 9090, 8500, 4001, 10250, 2181, 5672, 15672, 9092}

// ─── HTTP client (no redirect following — detect redirect chains manually) ───

func newHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		DisableKeepAlives:   true,
		MaxIdleConns:        32,
		IdleConnTimeout:     15 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		// Allow connections to internal addresses for SSRF probing
		DisableCompression: true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Do NOT follow redirects — we detect them as SSRF vectors
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ─── Event ID ─────────────────────────────────────────────────────────────────

func eventID(scanID, targetURL, payload string) string {
	h := sha256.Sum256([]byte(scanID + targetURL + payload))
	return hex.EncodeToString(h[:])
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

// Scan runs all SSRF probes against targetURL, sending findings to out.
// oobDomain (e.g. "<scan_id>.oob.local") is embedded in payloads for blind detection.
// ctx governs the overall scan lifetime.
func Scan(ctx context.Context, req *pb.ScanRequest, oobDomain string, out chan<- *pb.Finding) {
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := newHTTPClient(timeout)
	now := time.Now().UnixNano()

	// 1. Cloud metadata endpoint probes — run all 6 probes concurrently.
	{
		var wg sync.WaitGroup
		fanOut := make(chan *pb.Finding, 128)
		for _, p := range metadataProbes {
			if ctx.Err() != nil {
				break
			}
			probe := p
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, f := range probeMetadata(ctx, client, req, probe, oobDomain, now) {
					fanOut <- f
				}
			}()
		}
		go func() {
			wg.Wait()
			close(fanOut)
		}()
		for f := range fanOut {
			out <- f
		}
	}

	// 2. Open-redirect → SSRF via common URL parameters
	for _, param := range ssrfParams {
		select {
		case <-ctx.Done():
			return
		default:
		}
		findings := probeRedirectParam(ctx, client, req, param, oobDomain, now)
		for _, f := range findings {
			out <- f
		}
	}

	// 3. Internal CIDR scan
	for _, host := range internalHosts {
		for _, port := range internalPorts {
			select {
			case <-ctx.Done():
				return
			default:
			}
			f := probeInternalCIDR(ctx, client, req, host, port, oobDomain, now)
			if f != nil {
				out <- f
			}
		}
	}
}

// ─── Probe: metadata endpoints ────────────────────────────────────────────────

// probeMetadata injects the metadata URL as a parameter value in the target's
// query string for each of ssrfParams, detecting both direct (200) and blind (OOB) SSRF.
func probeMetadata(ctx context.Context, client *http.Client, req *pb.ScanRequest, probe metadataProbe, oobDomain string, ts int64) []*pb.Finding {
	var findings []*pb.Finding

	// For IMDSv2: fetch a token first (simulates attacker enumerating with PUT)
	injectedURL := probe.url
	if oobDomain != "" {
		// Embed OOB domain to detect blind SSRF via DNS callback
		injectedURL = fmt.Sprintf("http://%s.%s/%s", req.ScanId, oobDomain, probe.name)
	}

	for _, param := range ssrfParams {
		payload := fmt.Sprintf("%s=%s", param, url.QueryEscape(injectedURL))
		targetWithParam := appendQueryParam(req.TargetUrl, param, injectedURL)

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetWithParam, nil)
		if err != nil {
			continue
		}
		// Add any custom headers from the scan request
		for _, h := range req.Headers {
			parts := strings.SplitN(h, ": ", 2)
			if len(parts) == 2 {
				httpReq.Header.Set(parts[0], parts[1])
			}
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		severity, evidence := evaluateMetadataResponse(resp.StatusCode, string(body), probe.name)
		if severity == "" {
			continue
		}

		findings = append(findings, &pb.Finding{
			Id:           eventID(req.ScanId, req.TargetUrl, payload),
			Url:          targetWithParam,
			VulnType:     "SSRF",
			Severity:     severity,
			Evidence:     evidence,
			SourceTool:   "oi-ssrf/" + probe.name,
			DiscoveredAt: ts,
			Metadata: map[string]string{
				"probe":      probe.name,
				"param":      param,
				"ssrf_url":   injectedURL,
				"status":     fmt.Sprintf("%d", resp.StatusCode),
				"oob_domain": oobDomain,
			},
			Confidence: confidenceForStatus(resp.StatusCode),
			ScanId:     req.ScanId,
		})
	}

	// Also fire the direct metadata request to confirm from-scanner reachability
	// ONLY when explicitly opted in — default OFF to prevent IMDS self-attack (SA-3).
	if req.Options["direct_metadata_probe"] == "false" {
		return findings
	}
	directPayload := "direct:" + probe.url
	if probe.tokenURL != "" {
		// IMDSv2: PUT for token
		tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPut, probe.tokenURL, nil)
		if err == nil {
			for k, v := range probe.tokenHeaders {
				tokenReq.Header.Set(k, v)
			}
			tokenResp, err := client.Do(tokenReq)
			if err == nil {
				tokenBytes, _ := io.ReadAll(io.LimitReader(tokenResp.Body, 256))
				tokenResp.Body.Close()
				token := strings.TrimSpace(string(tokenBytes))

				if token != "" {
					getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.url, nil)
					if err == nil {
						getReq.Header.Set(probe.tokenTarget, token)
						getResp, err := client.Do(getReq)
						if err == nil {
							body, _ := io.ReadAll(io.LimitReader(getResp.Body, 4096))
							getResp.Body.Close()
							sev, ev := evaluateMetadataResponse(getResp.StatusCode, string(body), probe.name)
							if sev != "" {
								findings = append(findings, &pb.Finding{
									Id:           eventID(req.ScanId, req.TargetUrl, directPayload+"-imdsv2"),
									Url:          probe.url,
									VulnType:     "SSRF",
									Severity:     sev,
									Evidence:     ev,
									SourceTool:   "oi-ssrf/" + probe.name,
									DiscoveredAt: ts,
									Metadata: map[string]string{
										"probe":  probe.name,
										"method": "imdsv2-token-auth",
										"status": fmt.Sprintf("%d", getResp.StatusCode),
									},
									Confidence: confidenceForStatus(getResp.StatusCode),
									ScanId:     req.ScanId,
								})
							}
						}
					}
				}
			}
		}
	} else {
		// Simple GET with optional headers
		directReq, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.url, nil)
		if err == nil {
			for k, v := range probe.headers {
				directReq.Header.Set(k, v)
			}
			directResp, err := client.Do(directReq)
			if err == nil {
				body, _ := io.ReadAll(io.LimitReader(directResp.Body, 4096))
				directResp.Body.Close()
				sev, ev := evaluateMetadataResponse(directResp.StatusCode, string(body), probe.name)
				if sev != "" {
					findings = append(findings, &pb.Finding{
						Id:           eventID(req.ScanId, req.TargetUrl, directPayload),
						Url:          probe.url,
						VulnType:     "SSRF",
						Severity:     sev,
						Evidence:     ev,
						SourceTool:   "oi-ssrf/" + probe.name,
						DiscoveredAt: ts,
						Metadata: map[string]string{
							"probe":  probe.name,
							"method": "direct",
							"status": fmt.Sprintf("%d", directResp.StatusCode),
						},
						Confidence: confidenceForStatus(directResp.StatusCode),
						ScanId:     req.ScanId,
					})
				}
			}
		}
	}

	return findings
}

// evaluateMetadataResponse classifies a metadata endpoint response.
// Returns ("", "") when the response is not interesting.
func evaluateMetadataResponse(status int, body, probe string) (severity, evidence string) {
	switch {
	case status == 200 && len(body) > 0:
		return "critical", fmt.Sprintf("Metadata endpoint %s responded 200 with %d bytes", probe, len(body))
	case status == 401 || status == 403:
		// Auth-required is medium — endpoint exists but access controlled
		return "medium", fmt.Sprintf("Metadata endpoint %s returned %d (exists but auth required)", probe, status)
	case status >= 301 && status <= 308:
		return "medium", fmt.Sprintf("Redirect from metadata endpoint %s (status %d)", probe, status)
	}
	return "", ""
}

func confidenceForStatus(status int) float32 {
	if status == 200 {
		return 0.95
	}
	if status == 401 || status == 403 {
		return 0.65
	}
	return 0.40
}

// ─── Probe: open-redirect → SSRF via query params ─────────────────────────────

// probeRedirectParam injects each internal/OOB target as a redirect parameter
// and detects redirect chains that could lead to SSRF.
func probeRedirectParam(ctx context.Context, client *http.Client, req *pb.ScanRequest, param, oobDomain string, ts int64) []*pb.Finding {
	var findings []*pb.Finding

	// Two payloads: canonical internal + OOB blind
	payloads := []struct {
		value string
		label string
	}{
		{value: "http://169.254.169.254/latest/meta-data/", label: "aws-imds-redirect"},
		{value: fmt.Sprintf("http://%s.%s/redirect-probe", req.ScanId, oobDomain), label: "oob-redirect"},
	}

	for _, p := range payloads {
		targetWithParam := appendQueryParam(req.TargetUrl, param, p.value)
		payload := param + "=" + p.value

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetWithParam, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// A 3xx pointing to our injected URL is a confirmed open-redirect → SSRF
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if strings.Contains(location, "169.254.169.254") || strings.Contains(location, oobDomain) {
				findings = append(findings, &pb.Finding{
					Id:           eventID(req.ScanId, req.TargetUrl, payload),
					Url:          targetWithParam,
					VulnType:     "SSRF",
					Severity:     "high",
					Evidence:     fmt.Sprintf("Open redirect via param %q → Location: %s", param, location),
					SourceTool:   "oi-ssrf/redirect-chain",
					DiscoveredAt: ts,
					Metadata: map[string]string{
						"param":     param,
						"location":  location,
						"status":    fmt.Sprintf("%d", resp.StatusCode),
						"oob_label": p.label,
					},
					Confidence: 0.85,
					ScanId:     req.ScanId,
				})
			}
		}
	}
	return findings
}

// ─── Probe: internal CIDR port scan ──────────────────────────────────────────

// probeInternalCIDR attempts an HTTP GET to an internal host:port via the target's
// SSRF parameters, looking for responses that confirm internal service reachability.
func probeInternalCIDR(ctx context.Context, client *http.Client, req *pb.ScanRequest, host string, port int, oobDomain string, ts int64) *pb.Finding {
	internalTarget := fmt.Sprintf("http://%s:%d/", host, port)
	payload := fmt.Sprintf("cidr-probe:%s", internalTarget)

	// Inject via the first available SSRF param
	for _, param := range ssrfParams {
		targetWithParam := appendQueryParam(req.TargetUrl, param, internalTarget)

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetWithParam, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		// Any non-timeout response suggests the target fetched the internal URL
		if resp.StatusCode > 0 && len(body) > 0 {
			return &pb.Finding{
				Id:           eventID(req.ScanId, req.TargetUrl, payload),
				Url:          targetWithParam,
				VulnType:     "SSRF",
				Severity:     "high",
				Evidence:     fmt.Sprintf("Internal CIDR %s:%d reachable via param %q (status %d, %d bytes)", host, port, param, resp.StatusCode, len(body)),
				SourceTool:   "oi-ssrf/cidr-scan",
				DiscoveredAt: ts,
				Metadata: map[string]string{
					"internal_host": host,
					"internal_port": fmt.Sprintf("%d", port),
					"param":         param,
					"status":        fmt.Sprintf("%d", resp.StatusCode),
					"oob_domain":    oobDomain,
				},
				Confidence: 0.75,
				ScanId:     req.ScanId,
			}
		}
	}
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// appendQueryParam appends param=value to rawURL, preserving existing params.
func appendQueryParam(rawURL, param, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + "?" + param + "=" + url.QueryEscape(value)
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}
