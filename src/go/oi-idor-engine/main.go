// Package main implements the oi-idor-engine gRPC sidecar.
// Provides concurrent IDOR detection with multi-context authorization testing,
// horizontal and vertical privilege escalation detection.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"
)

func init() {
	// Register JSON codec so stream.RecvMsg/SendMsg use JSON over gRPC framing.
	// This overrides the default proto codec; no protoc-generated types needed.
	encoding.RegisterCodec(jsonCodec{})
}

// ---------------------------------------------------------------------------
// Hand-written proto message structs (mirrors oneinfinity.proto v1)
// ---------------------------------------------------------------------------

// Finding mirrors proto Finding.
type Finding struct {
	ID           string            `json:"id"`
	URL          string            `json:"url"`
	VulnType     string            `json:"vuln_type"`
	Severity     string            `json:"severity"`
	Evidence     string            `json:"evidence"`
	SourceTool   string            `json:"source_tool"`
	DiscoveredAt int64             `json:"discovered_at"`
	Metadata     map[string]string `json:"metadata"`
	Confidence   float32           `json:"confidence"`
	ScanID       string            `json:"scan_id"`
}

// IDORRequest mirrors proto IDORRequest.
type IDORRequest struct {
	TargetURL        string            `json:"target_url"`
	ScanID           string            `json:"scan_id"`
	SessionTokens    []string          `json:"session_tokens"`
	EndpointPatterns []string          `json:"endpoint_patterns"`
	Parallelism      int32             `json:"parallelism"`
	Options          map[string]string `json:"options"`
}

// HealthCheckRequest mirrors proto HealthCheckRequest.
type HealthCheckRequest struct {
	Service string `json:"service"`
}

// HealthCheckResponse mirrors proto HealthCheckResponse.
type HealthCheckResponse struct {
	Status int32 `json:"status"` // 0=UNKNOWN 1=SERVING 2=NOT_SERVING
}

// ---------------------------------------------------------------------------
// IDOR evidence payload (serialised into Finding.Evidence as JSON)
// ---------------------------------------------------------------------------

type idorEvidence struct {
	Endpoint        string `json:"endpoint"`
	IDTested        int    `json:"id_tested"`
	TokenUsed       string `json:"token_used"`    // truncated for safety
	TokenIndex      int    `json:"token_index"`   // which session_token slot
	AttackerToken   int    `json:"attacker_token_index"`
	OwnerToken      int    `json:"owner_token_index"`
	Method          string `json:"method"`
	StatusCode      int    `json:"status_code"`
	ExpectedCode    int    `json:"expected_code"`
	ResponseSnippet string `json:"response_snippet"` // first 256 chars
	EscalationType  string `json:"escalation_type"`  // horizontal|vertical
	// Extra fields used by enhancement probes.
	Technique       string `json:"technique,omitempty"`
	InjectedPayload string `json:"injected_payload,omitempty"`
	AltMethod       string `json:"alt_method,omitempty"`
	PathVariant     string `json:"path_variant,omitempty"`
	JWTMutation     string `json:"jwt_mutation,omitempty"`
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// eventID returns SHA256(scanID + endpoint + strconv.Itoa(id) + tokenHash).
// Stable across runs for the same (scan, endpoint, id, token) triple.
func eventID(scanID, endpoint string, id int, token string) string {
	h := sha256.New()
	// Hash token to avoid leaking session material in finding IDs.
	th := sha256.Sum256([]byte(token))
	fmt.Fprintf(h, "%s|%s|%d|%s", scanID, endpoint, id, hex.EncodeToString(th[:8]))
	return hex.EncodeToString(h.Sum(nil))
}

// tokenSnippet returns a safe, non-secret representation of a session token.
func tokenSnippet(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:4] + "..." + token[len(token)-4:]
}

// expandEndpoint substitutes {id} placeholder with the numeric id.
func expandEndpoint(pattern string, id int) string {
	return strings.ReplaceAll(pattern, "{id}", strconv.Itoa(id))
}

// idRangeFromOptions reads "id_min" / "id_max" from options, defaulting to 1–100.
func idRangeFromOptions(opts map[string]string) (int, int) {
	min, max := 1, 100
	if v, ok := opts["id_min"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			min = n
		}
	}
	if v, ok := opts["id_max"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n >= min {
			max = n
		}
	}
	return min, max
}

// methodsFromOptions returns the HTTP methods to test, defaulting to GET/POST.
func methodsFromOptions(opts map[string]string) []string {
	if v, ok := opts["methods"]; ok && v != "" {
		return strings.Split(v, ",")
	}
	return []string{"GET", "POST", "PUT", "DELETE"}
}

// ---------------------------------------------------------------------------
// HTTP probing logic
// ---------------------------------------------------------------------------

const (
	httpTimeout    = 10 * time.Second
	bannerReadSize = 256
)

// newHTTPClient returns an http.Client that does NOT follow redirects
// (redirects can mask 403 → 200 bypass patterns).
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// probeResult holds the outcome of a single HTTP probe.
type probeResult struct {
	StatusCode int
	Body       string // first 256 bytes
}

// probe sends a single HTTP request with the bearer token and returns the result.
func probe(ctx context.Context, client *http.Client, method, url, token string) (*probeResult, error) {
	var body io.Reader
	if method == "POST" || method == "PUT" {
		body = bytes.NewBufferString(`{}`)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Cookie", "session="+token)
	}
	if method == "POST" || method == "PUT" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "oi-idor-engine/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, bannerReadSize))
	return &probeResult{
		StatusCode: resp.StatusCode,
		Body:       string(raw),
	}, nil
}

// ---------------------------------------------------------------------------
// IDOR detection logic
// ---------------------------------------------------------------------------

// isIDOR returns true when the probe response indicates an unauthorised access.
// Strategy:
//  1. Attacker token gets 200 → access granted where we expect denial.
//  2. Cross-token body similarity: response for token[i] contains data
//     that belongs to the resource owned by token[j].
func isIDOR(statusCode, expectedCode int, body, ownerBody string) (bool, float32, string) {
	// Case 1: expected 403/404 but got 200
	if (expectedCode == 403 || expectedCode == 404) && statusCode == 200 {
		return true, 0.9, "status_bypass"
	}
	// Case 2: unexpected 200 for any protected resource
	if statusCode == 200 && expectedCode != 200 {
		return true, 0.8, "unexpected_success"
	}
	// Case 3: body leak — attacker response shares significant content with owner response
	if ownerBody != "" && len(body) > 20 && len(ownerBody) > 20 {
		// Simple overlap heuristic: shared 16-byte substrings
		if bodyOverlap(body, ownerBody, 16) {
			return true, 0.75, "body_leak"
		}
	}
	return false, 0, ""
}

// bodyOverlap returns true if a and b share at least one substring of length n.
func bodyOverlap(a, b string, n int) bool {
	if len(a) < n || len(b) < n {
		return false
	}
	// Only compare first 256 chars to keep O(n) reasonable.
	aS := a
	if len(aS) > 256 {
		aS = aS[:256]
	}
	for i := 0; i+n <= len(aS); i++ {
		sub := aS[i : i+n]
		if strings.Contains(b, sub) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Enhancement 1: Mass assignment probes
// ---------------------------------------------------------------------------

// massAssignPayloads are privilege-escalation field sets injected into POST/PUT bodies.
var massAssignPayloads = []struct {
	label   string
	payload map[string]interface{}
}{
	{"role_admin", map[string]interface{}{"role": "admin"}},
	{"is_admin_true", map[string]interface{}{"is_admin": true}},
	{"admin_verified", map[string]interface{}{"admin": true, "verified": true}},
	{"subscription_enterprise", map[string]interface{}{"subscription": "enterprise"}},
	{"credits_overflow", map[string]interface{}{"credits": 99999}},
	{"user_type_superuser", map[string]interface{}{"user_type": "superuser"}},
}

// probeMassAssignment sends POST and PUT requests with privilege-escalation fields injected.
// It returns findings for any non-4xx responses, indicating the server may have accepted the field.
func probeMassAssignment(ctx context.Context, client *http.Client, baseURL, endpoint, token, scanID string) []*Finding {
	var findings []*Finding
	url := baseURL + endpoint

	for _, entry := range massAssignPayloads {
		for _, method := range []string{"POST", "PUT", "PATCH"} {
			bodyBytes, _ := json.Marshal(entry.payload)
			req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Cookie", "session="+token)
			}
			req.Header.Set("User-Agent", "oi-idor-engine/1.0")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, bannerReadSize))
			resp.Body.Close()

			// 200/201/204 on a privilege-field mutation is suspicious.
			if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 204 {
				ev := idorEvidence{
					Endpoint:        endpoint,
					Method:          method,
					StatusCode:      resp.StatusCode,
					ExpectedCode:    403,
					ResponseSnippet: string(raw),
					Technique:       "mass_assignment",
					InjectedPayload: string(bodyBytes),
				}
				evBytes, _ := json.Marshal(ev)
				h := sha256.New()
				fmt.Fprintf(h, "mass|%s|%s|%s|%s", scanID, endpoint, method, entry.label)
				findings = append(findings, &Finding{
					ID:           hex.EncodeToString(h.Sum(nil)),
					URL:          url,
					VulnType:     "mass_assignment",
					Severity:     "critical",
					Evidence:     string(evBytes),
					SourceTool:   "oi-idor-engine",
					DiscoveredAt: time.Now().UnixNano(),
					Confidence:   0.85,
					ScanID:       scanID,
					Metadata: map[string]string{
						"endpoint": endpoint,
						"method":   method,
						"label":    entry.label,
						"payload":  string(bodyBytes),
					},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Enhancement 2: HTTP verb tampering
// ---------------------------------------------------------------------------

// allVerbs is the full set of methods to try when verb tampering.
var allVerbs = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

// probeVerbTampering tests whether alternative HTTP methods bypass authorization.
// It first determines the baseline GET status, then tries every other verb.
func probeVerbTampering(ctx context.Context, client *http.Client, url, token, scanID, endpoint string) []*Finding {
	var findings []*Finding

	// Baseline: GET without auth to see what the server says.
	baseReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	baseReq.Header.Set("User-Agent", "oi-idor-engine/1.0")
	baseResp, err := client.Do(baseReq)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, baseResp.Body)
	baseResp.Body.Close()
	baseStatus := baseResp.StatusCode

	// Only interesting if baseline blocks us (4xx).
	if baseStatus < 400 || baseStatus > 499 {
		baseStatus = 403 // assume protected
	}

	for _, verb := range allVerbs {
		if verb == "GET" {
			continue // already the baseline
		}
		var body io.Reader
		if verb == "POST" || verb == "PUT" || verb == "PATCH" {
			body = bytes.NewBufferString(`{}`)
		}
		req, err := http.NewRequestWithContext(ctx, verb, url, body)
		if err != nil {
			continue
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Cookie", "session="+token)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		// Classic bypass headers.
		req.Header.Set("X-HTTP-Method-Override", verb)
		req.Header.Set("X-Method-Override", verb)
		req.Header.Set("User-Agent", "oi-idor-engine/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, bannerReadSize))
		resp.Body.Close()

		// Flag: baseline was 4xx but alternative verb returned 2xx or 3xx.
		bypassed := (baseStatus >= 400) && (resp.StatusCode >= 200 && resp.StatusCode < 400)
		// Also flag unauth PUT/PATCH that succeeds — no token check, direct test.
		unauthWrite := (verb == "PUT" || verb == "PATCH") && token == "" && resp.StatusCode < 400
		if !bypassed && !unauthWrite {
			continue
		}

		ev := idorEvidence{
			Endpoint:        endpoint,
			Method:          verb,
			StatusCode:      resp.StatusCode,
			ExpectedCode:    baseStatus,
			ResponseSnippet: string(raw),
			Technique:       "verb_tampering",
			AltMethod:       verb,
		}
		evBytes, _ := json.Marshal(ev)
		h := sha256.New()
		fmt.Fprintf(h, "verb|%s|%s|%s", scanID, endpoint, verb)
		findings = append(findings, &Finding{
			ID:           hex.EncodeToString(h.Sum(nil)),
			URL:          url,
			VulnType:     "verb_tampering",
			Severity:     "high",
			Evidence:     string(evBytes),
			SourceTool:   "oi-idor-engine",
			DiscoveredAt: time.Now().UnixNano(),
			Confidence:   0.88,
			ScanID:       scanID,
			Metadata: map[string]string{
				"endpoint":     endpoint,
				"baseline":     strconv.Itoa(baseStatus),
				"alt_method":   verb,
				"alt_status":   strconv.Itoa(resp.StatusCode),
			},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// Enhancement 3: Path traversal in ID parameters
// ---------------------------------------------------------------------------

// pathTraversalVariants returns the set of traversal strings to substitute for {id}.
func pathTraversalVariants(normalID int) []struct{ label, value string } {
	otherID := normalID + 1
	return []struct{ label, value string }{
		{"dotdot_admin", "../../admin"},
		{"dotdot_user", "../" + strconv.Itoa(otherID)},
		{"url_encoded", "%2e%2e%2f"},
		{"int_overflow", "2147483648"},
		{"negative_one", "-1"},
		{"negative_two", "-2"},
	}
}

// probePathTraversal replaces the numeric id in the URL with traversal variants and
// flags any 200 response.
func probePathTraversal(ctx context.Context, client *http.Client, baseURL, pattern, token, scanID string, normalID int) []*Finding {
	var findings []*Finding

	for _, v := range pathTraversalVariants(normalID) {
		// Replace {id} with the traversal string directly (no strconv, keep raw).
		travEndpoint := strings.ReplaceAll(pattern, "{id}", v.value)
		url := baseURL + travEndpoint

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Cookie", "session="+token)
		}
		req.Header.Set("User-Agent", "oi-idor-engine/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, bannerReadSize))
		resp.Body.Close()

		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			continue
		}

		ev := idorEvidence{
			Endpoint:        pattern,
			IDTested:        normalID,
			Method:          "GET",
			StatusCode:      resp.StatusCode,
			ExpectedCode:    403,
			ResponseSnippet: string(raw),
			Technique:       "path_traversal",
			PathVariant:     v.value,
		}
		evBytes, _ := json.Marshal(ev)
		h := sha256.New()
		fmt.Fprintf(h, "path|%s|%s|%s", scanID, pattern, v.label)
		findings = append(findings, &Finding{
			ID:           hex.EncodeToString(h.Sum(nil)),
			URL:          url,
			VulnType:     "path_traversal",
			Severity:     "high",
			Evidence:     string(evBytes),
			SourceTool:   "oi-idor-engine",
			DiscoveredAt: time.Now().UnixNano(),
			Confidence:   0.82,
			ScanID:       scanID,
			Metadata: map[string]string{
				"endpoint":     pattern,
				"variant":      v.label,
				"path_used":    v.value,
				"status":       strconv.Itoa(resp.StatusCode),
			},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// Enhancement 4: JWT manipulation
// ---------------------------------------------------------------------------

// jwtParts holds the decoded sections of a JWT.
type jwtParts struct {
	headerJSON  []byte
	payloadJSON []byte
	origSig     []byte
}

// decodeJWT decodes a JWT without verifying the signature.
// Returns nil if the token is not a valid three-part JWT.
func decodeJWT(token string) *jwtParts {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	hdr, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pay, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil
	}
	return &jwtParts{headerJSON: hdr, payloadJSON: pay, origSig: sig}
}

// encodeJWT assembles header.payload.signature from raw JSON/bytes.
// For alg:none, pass nil sig. For HMAC, pass the computed sig bytes.
func encodeJWT(header, payload map[string]interface{}, sig []byte) string {
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)
	h64 := base64.RawURLEncoding.EncodeToString(hBytes)
	p64 := base64.RawURLEncoding.EncodeToString(pBytes)
	sigPart := base64.RawURLEncoding.EncodeToString(sig)
	return h64 + "." + p64 + "." + sigPart
}

// jwtMutations returns a set of mutated tokens from a decoded JWT.
func jwtMutations(parts *jwtParts) []struct{ label, token string } {
	var header map[string]interface{}
	var payload map[string]interface{}
	if err := json.Unmarshal(parts.headerJSON, &header); err != nil {
		return nil
	}
	if err := json.Unmarshal(parts.payloadJSON, &payload); err != nil {
		return nil
	}

	var mutations []struct{ label, token string }

	// Mutation 1: alg:none — strip signature entirely.
	{
		h := copyMap(header)
		p := copyMap(payload)
		// Escalate: set role/sub to admin.
		elevatePayload(p)
		h["alg"] = "none"
		mutations = append(mutations, struct{ label, token string }{
			"alg_none", encodeJWT(h, p, []byte{}),
		})
	}

	// Mutation 2: RS256 → HS256 confusion — sign with empty secret.
	if alg, _ := header["alg"].(string); alg == "RS256" {
		h := copyMap(header)
		p := copyMap(payload)
		elevatePayload(p)
		h["alg"] = "HS256"
		hBytes, _ := json.Marshal(h)
		pBytes, _ := json.Marshal(p)
		signingInput := base64.RawURLEncoding.EncodeToString(hBytes) + "." + base64.RawURLEncoding.EncodeToString(pBytes)
		mac := hmac.New(sha256.New, []byte("")) // empty secret
		mac.Write([]byte(signingInput))
		sig := mac.Sum(nil)
		mutations = append(mutations, struct{ label, token string }{
			"rs256_to_hs256", encodeJWT(h, p, sig),
		})
	}

	// Mutation 3: expired token — set exp to a past timestamp.
	{
		h := copyMap(header)
		p := copyMap(payload)
		elevatePayload(p)
		p["exp"] = time.Now().Add(-24 * time.Hour).Unix()
		mutations = append(mutations, struct{ label, token string }{
			"expired_token", encodeJWT(h, p, parts.origSig),
		})
	}

	// Mutation 4: kid path traversal — inject ../../../../dev/null or similar.
	{
		h := copyMap(header)
		p := copyMap(payload)
		elevatePayload(p)
		h["kid"] = "../../dev/null"
		mutations = append(mutations, struct{ label, token string }{
			"kid_traversal", encodeJWT(h, p, []byte("injected")),
		})
	}

	return mutations
}

// elevatePayload mutates a JWT payload map to claim admin/superuser.
func elevatePayload(p map[string]interface{}) {
	p["role"] = "admin"
	p["is_admin"] = true
	if _, ok := p["sub"]; ok {
		p["sub"] = "1" // target user id 1 (often admin)
	}
}

// copyMap returns a shallow copy of a map[string]interface{}.
func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// probeJWTManipulation tests JWT mutations against the given endpoint.
// Only runs if token looks like a JWT (three base64url segments separated by dots).
func probeJWTManipulation(ctx context.Context, client *http.Client, url, token, scanID, endpoint string) []*Finding {
	if token == "" {
		return nil
	}
	parts := decodeJWT(token)
	if parts == nil {
		return nil
	}
	mutations := jwtMutations(parts)
	if len(mutations) == 0 {
		return nil
	}

	var findings []*Finding
	for _, mut := range mutations {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+mut.token)
		req.Header.Set("User-Agent", "oi-idor-engine/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, bannerReadSize))
		resp.Body.Close()

		// Only flag if server returns 200 (accepted manipulated JWT).
		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			continue
		}

		ev := idorEvidence{
			Endpoint:        endpoint,
			Method:          "GET",
			StatusCode:      resp.StatusCode,
			ExpectedCode:    401,
			ResponseSnippet: string(raw),
			Technique:       "jwt_manipulation",
			JWTMutation:     mut.label,
		}
		evBytes, _ := json.Marshal(ev)
		h := sha256.New()
		fmt.Fprintf(h, "jwt|%s|%s|%s", scanID, endpoint, mut.label)
		findings = append(findings, &Finding{
			ID:           hex.EncodeToString(h.Sum(nil)),
			URL:          url,
			VulnType:     "jwt_manipulation",
			Severity:     "critical",
			Evidence:     string(evBytes),
			SourceTool:   "oi-idor-engine",
			DiscoveredAt: time.Now().UnixNano(),
			Confidence:   0.92,
			ScanID:       scanID,
			Metadata: map[string]string{
				"endpoint":     endpoint,
				"mutation":     mut.label,
				"status":       strconv.Itoa(resp.StatusCode),
			},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// Scan worker
// ---------------------------------------------------------------------------

// scanJob is a unit of work: (endpoint pattern, id, attacker token index, owner token index, method).
type scanJob struct {
	pattern      string
	id           int
	attackerIdx  int
	ownerIdx     int
	escalation   string // "horizontal" | "vertical"
	method       string
}

// runScan performs IDOR scanning and sends findings on out.
// Concurrency is controlled by the semaphore.
func runScan(ctx context.Context, req *IDORRequest, out chan<- *Finding) {
	client := newHTTPClient()

	parallelism := int(req.Parallelism)
	if parallelism <= 0 {
		parallelism = 20
	}

	idMin, idMax := idRangeFromOptions(req.Options)
	methods := methodsFromOptions(req.Options)

	tokens := req.SessionTokens
	if len(tokens) == 0 {
		// Nothing to compare against — emit nothing.
		return
	}

	// Semaphore channel for rate-limiting goroutines.
	sem := make(chan struct{}, parallelism)

	var wg sync.WaitGroup

	emit := func(f *Finding) {
		select {
		case out <- f:
		case <-ctx.Done():
		}
	}

	emitAll := func(fs []*Finding) {
		for _, f := range fs {
			emit(f)
		}
	}

	// -----------------------------------------------------------------------
	// Enhancement probes: mass assignment, verb tampering, path traversal, JWT.
	// Run once per (endpoint × first attacker token); these are not id-scoped
	// except for path traversal which takes the first id in range.
	// -----------------------------------------------------------------------
	for _, pattern := range req.EndpointPatterns {
		attackerToken := tokens[0] // use first token as attacker baseline
		firstID := idMin

		// Mass assignment — only meaningful on write endpoints.
		url := req.TargetURL + expandEndpoint(pattern, firstID)
		wg.Add(1)
		go func(u, ep, tok string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			emitAll(probeMassAssignment(ctx, client, req.TargetURL, ep, tok, req.ScanID))
		}(url, expandEndpoint(pattern, firstID), attackerToken)

		// Verb tampering — test on the expanded endpoint.
		wg.Add(1)
		go func(u, ep, tok string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			emitAll(probeVerbTampering(ctx, client, u, tok, req.ScanID, ep))
		}(url, expandEndpoint(pattern, firstID), attackerToken)

		// Path traversal — run for each id in the configured range.
		for id := idMin; id <= idMax; id++ {
			captureID := id
			wg.Add(1)
			go func(ep string, cid int, tok string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				emitAll(probePathTraversal(ctx, client, req.TargetURL, ep, tok, req.ScanID, cid))
			}(pattern, captureID, attackerToken)
		}

		// JWT manipulation — try each token that looks like a JWT.
		for _, tok := range tokens {
			capTok := tok
			capURL := url
			capEP := expandEndpoint(pattern, firstID)
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				emitAll(probeJWTManipulation(ctx, client, capURL, capTok, req.ScanID, capEP))
			}()
		}
	}

	// -----------------------------------------------------------------------
	// Core IDOR scan: (endpoint × id × token-pair × method).
	// -----------------------------------------------------------------------
	for _, pattern := range req.EndpointPatterns {
		for id := idMin; id <= idMax; id++ {
			url := req.TargetURL + expandEndpoint(pattern, id)

			for attackerIdx := 0; attackerIdx < len(tokens); attackerIdx++ {
				for ownerIdx := 0; ownerIdx < len(tokens); ownerIdx++ {
					if attackerIdx == ownerIdx {
						continue
					}

					// Determine escalation type:
					// tokens[0] is assumed low-privilege, tokens[len-1] high-privilege.
					// Vertical: lower index attacking higher-index resource.
					escalation := "horizontal"
					if ownerIdx > attackerIdx {
						escalation = "vertical"
					}

					for _, method := range methods {
						// Capture loop vars for goroutine.
						patt := pattern
						u := url
						aIdx := attackerIdx
						oIdx := ownerIdx
						esc := escalation
						m := method
						theID := id

						select {
						case sem <- struct{}{}:
						case <-ctx.Done():
							return
						}
						wg.Add(1)
						go func() {
							defer wg.Done()
							defer func() { <-sem }()

							if ctx.Err() != nil {
								return
							}

							// Probe with attacker token.
							attackerResult, err := probe(ctx, client, m, u, tokens[aIdx])
							if err != nil {
								return
							}

							// Probe with owner token to get baseline body.
							ownerResult, err := probe(ctx, client, m, u, tokens[oIdx])
							if err != nil {
								ownerResult = &probeResult{}
							}

							// Expected status: owner gets 200, attacker should get 403/404.
							expectedCode := 403
							if ownerResult.StatusCode == 200 {
								expectedCode = 403
							} else if ownerResult.StatusCode == 404 {
								expectedCode = 404
							}

							found, confidence, reason := isIDOR(
								attackerResult.StatusCode, expectedCode,
								attackerResult.Body, ownerResult.Body,
							)
							if !found {
								return
							}

							ev := idorEvidence{
								Endpoint:        patt,
								IDTested:        theID,
								TokenUsed:       tokenSnippet(tokens[aIdx]),
								TokenIndex:      aIdx,
								AttackerToken:   aIdx,
								OwnerToken:      oIdx,
								Method:          m,
								StatusCode:      attackerResult.StatusCode,
								ExpectedCode:    expectedCode,
								ResponseSnippet: attackerResult.Body,
								EscalationType:  esc,
							}
							evBytes, _ := json.Marshal(ev)

							severity := "high"
							if esc == "vertical" {
								severity = "critical" // vertical privesc is more severe
							}

							f := &Finding{
								ID:           eventID(req.ScanID, patt, theID, tokens[aIdx]),
								URL:          u,
								VulnType:     "IDOR",
								Severity:     severity,
								Evidence:     string(evBytes),
								SourceTool:   "oi-idor-engine",
								DiscoveredAt: time.Now().UnixNano(),
								Confidence:   confidence,
								ScanID:       req.ScanID,
								Metadata: map[string]string{
									"endpoint":        patt,
									"id":              strconv.Itoa(theID),
									"escalation_type": esc,
									"method":          m,
									"reason":          reason,
									"attacker_token":  strconv.Itoa(aIdx),
									"owner_token":     strconv.Itoa(oIdx),
								},
							}

							emit(f)
						}()
					}
				}
			}
		}
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// gRPC service implementation
// ---------------------------------------------------------------------------

type idorEngineServer struct{}

// ---------------------------------------------------------------------------
// gRPC streaming handler for IDOREngine.Run
// ---------------------------------------------------------------------------

func idorRunHandler(srv interface{}, stream grpc.ServerStream) error {
	req := &IDORRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	if req.ScanID == "" {
		return status.Errorf(codes.InvalidArgument, "scan_id is required")
	}
	if req.TargetURL == "" {
		return status.Errorf(codes.InvalidArgument, "target_url is required")
	}
	if len(req.EndpointPatterns) == 0 {
		req.EndpointPatterns = []string{"/api/users/{id}", "/api/resources/{id}", "/api/data/{id}"}
	}

	ctx := stream.Context()
	out := make(chan *Finding, 256)

	go func() {
		defer close(out)
		runScan(ctx, req, out)
	}()

	for f := range out {
		if err := stream.SendMsg(f); err != nil {
			return err
		}
	}
	return nil
}

// healthHandler handles the unary Health RPC.
func healthHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := &HealthCheckRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	resp := &HealthCheckResponse{Status: 1}
	if interceptor != nil {
		return interceptor(ctx, req, &grpc.UnaryServerInfo{FullMethod: "/oneinfinity.v1.IDOREngine/Health"},
			func(_ context.Context, _ interface{}) (interface{}, error) {
				return resp, nil
			})
	}
	return resp, nil
}

// idorEngineServiceDesc is the gRPC service descriptor for IDOREngine.
var idorEngineServiceDesc = grpc.ServiceDesc{
	ServiceName: "oneinfinity.v1.IDOREngine",
	HandlerType: (*idorEngineServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Health",
			Handler:    healthHandler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Run",
			Handler:       idorRunHandler,
			ServerStreams: true,
		},
	},
}

// ---------------------------------------------------------------------------
// JSON codec — lets us skip protobuf binary encoding while keeping gRPC framing
// ---------------------------------------------------------------------------

type jsonCodec struct{}

func (jsonCodec) Marshal(v interface{}) ([]byte, error)   { return json.Marshal(v) }
func (jsonCodec) Unmarshal(b []byte, v interface{}) error { return json.Unmarshal(b, v) }
func (jsonCodec) Name() string                            { return "proto" }

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	// Bind to localhost only — never 0.0.0.0.
	const addr = "127.0.0.1:50055"

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("oi-idor-engine: listen %s: %v", addr, err)
	}

	s := grpc.NewServer(
		grpc.UnknownServiceHandler(func(_ interface{}, stream grpc.ServerStream) error {
			return status.Errorf(codes.Unimplemented, "unknown service")
		}),
	)
	s.RegisterService(&idorEngineServiceDesc, &idorEngineServer{})

	log.Printf("oi-idor-engine listening on %s", addr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("oi-idor-engine: serve: %v", err)
	}
}
