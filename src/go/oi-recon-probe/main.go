// Package main implements the oi-recon-probe gRPC sidecar.
// Provides concurrent DNS enumeration with 500-goroutine pool,
// wildcard detection, CNAME chain following, and all 6 DNS record types.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	_ "embed"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// JSON codec registered globally so gRPC uses it for all messages.
// Name() returns "proto" to override the default protobuf codec so standard
// gRPC clients expecting application/grpc+proto still connect cleanly.
// ---------------------------------------------------------------------------

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error)   { return json.Marshal(v) }
func (jsonCodec) Unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
func (jsonCodec) Name() string                    { return "proto" }

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

// ---------------------------------------------------------------------------
// Embedded wordlist (100+ common subdomain labels)
// ---------------------------------------------------------------------------

//go:embed wordlist.txt
var embeddedWordlist string

// ---------------------------------------------------------------------------
// Minimal hand-written proto message structs
// (matches oneinfinity.proto wire fields; JSON tags mirror field names)
// ---------------------------------------------------------------------------

// Finding mirrors proto Finding (fields 1-10).
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

// ScanRequest mirrors proto ScanRequest (fields 1-5).
type ScanRequest struct {
	TargetURL      string            `json:"target_url"`
	ScanID         string            `json:"scan_id"`
	Options        map[string]string `json:"options"`
	Headers        []string          `json:"headers"`
	TimeoutSeconds int32             `json:"timeout_seconds"`
}

// HealthCheckRequest mirrors proto HealthCheckRequest (field 1).
type HealthCheckRequest struct {
	Service string `json:"service"`
}

// HealthCheckResponse mirrors proto HealthCheckResponse (field 1).
// Status values: 0=UNKNOWN, 1=SERVING, 2=NOT_SERVING.
type HealthCheckResponse struct {
	Status int32 `json:"status"`
}

// ---------------------------------------------------------------------------
// DNS resolver pool configuration
// ---------------------------------------------------------------------------

const (
	// concurrency is the goroutine pool size for DNS enumeration.
	concurrency = 500
	// rateLimit is the maximum total DNS queries per second.
	rateLimit = 500
	// cnameMaxDepth is the maximum CNAME chain depth to follow.
	cnameMaxDepth = 10
)

// dnsServers is the upstream resolver rotation list.
var dnsServers = []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}

// resolverFor returns a *net.Resolver that dials the nth server in rotation.
func resolverFor(idx int) *net.Resolver {
	addr := dnsServers[idx%len(dnsServers)]
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// ---------------------------------------------------------------------------
// DNS record types and resolution
// ---------------------------------------------------------------------------

// DNSRecords holds all resolved record types for a single FQDN.
type DNSRecords struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	MX    []string `json:"mx,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	NS    []string `json:"ns,omitempty"`
	CNAME string   `json:"cname,omitempty"`
}

// resolveFQDN queries all 6 DNS record types concurrently for fqdn.
// resolverIdx selects which upstream DNS server to use (mod rotation).
func resolveFQDN(ctx context.Context, fqdn string, resolverIdx int) (*DNSRecords, error) {
	r := resolverFor(resolverIdx)
	rec := &DNSRecords{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Helper: fan out a lookup in a goroutine; errors are best-effort ignored.
	lookup := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = fn()
		}()
	}

	// A + AAAA: LookupHost returns both v4 and v6 addresses.
	lookup(func() error {
		addrs, err := r.LookupHost(ctx, fqdn)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				rec.A = append(rec.A, a)
			} else {
				rec.AAAA = append(rec.AAAA, a)
			}
		}
		return nil
	})

	// MX records
	lookup(func() error {
		mxs, err := r.LookupMX(ctx, fqdn)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		for _, mx := range mxs {
			rec.MX = append(rec.MX, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
		return nil
	})

	// TXT records
	lookup(func() error {
		txts, err := r.LookupTXT(ctx, fqdn)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		rec.TXT = append(rec.TXT, txts...)
		return nil
	})

	// NS records
	lookup(func() error {
		nss, err := r.LookupNS(ctx, fqdn)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		for _, ns := range nss {
			rec.NS = append(rec.NS, ns.Host)
		}
		return nil
	})

	// CNAME chain: follow up to cnameMaxDepth hops.
	lookup(func() error {
		current := fqdn
		for depth := 0; depth < cnameMaxDepth; depth++ {
			cname, err := r.LookupCNAME(ctx, current)
			if err != nil {
				break
			}
			// LookupCNAME always appends a trailing dot; strip it.
			cname = strings.TrimSuffix(cname, ".")
			if cname == current || cname == fqdn {
				// No further alias or points back to origin.
				break
			}
			current = cname
		}
		if current != fqdn {
			mu.Lock()
			rec.CNAME = current
			mu.Unlock()
		}
		return nil
	})

	wg.Wait()
	return rec, nil
}

// hasAnyRecord returns true if at least one DNS record was resolved.
func hasAnyRecord(rec *DNSRecords) bool {
	return len(rec.A) > 0 || len(rec.AAAA) > 0 || len(rec.MX) > 0 ||
		len(rec.TXT) > 0 || len(rec.NS) > 0 || rec.CNAME != ""
}

// ---------------------------------------------------------------------------
// Wildcard detection
// ---------------------------------------------------------------------------

// randomLabel returns a random 16-hex-character string safe as a DNS label.
func randomLabel() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// isWildcard probes a random subdomain of domain with resolver at index idx.
// Returns true if the random subdomain resolves — indicating wildcard DNS.
func isWildcard(ctx context.Context, domain string, idx int) bool {
	probe := randomLabel() + "." + domain
	rec, err := resolveFQDN(ctx, probe, idx)
	if err != nil {
		return false
	}
	return hasAnyRecord(rec)
}

// ---------------------------------------------------------------------------
// Stable event ID
// ---------------------------------------------------------------------------

// findingID returns a stable SHA-256(scanID + fqdn) event ID.
func findingID(scanID, fqdn string) string {
	h := sha256.Sum256([]byte(scanID + fqdn))
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// Wordlist loading
// ---------------------------------------------------------------------------

// loadWordlist returns subdomain labels from disk (if wordlistPath != "") or
// the embedded 200+ word default list.
func loadWordlist(wordlistPath string) ([]string, error) {
	raw := embeddedWordlist
	if wordlistPath != "" {
		data, err := os.ReadFile(wordlistPath)
		if err != nil {
			return nil, fmt.Errorf("reading wordlist %s: %w", wordlistPath, err)
		}
		raw = string(data)
	}
	var words []string
	for _, line := range strings.Split(raw, "\n") {
		w := strings.TrimSpace(line)
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	return words, nil
}

// ---------------------------------------------------------------------------
// Core scan logic
// ---------------------------------------------------------------------------

// extractDomain strips scheme, path and port from target_url.
func extractDomain(targetURL string) string {
	domain := targetURL
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	if i := strings.IndexByte(domain, '/'); i != -1 {
		domain = domain[:i]
	}
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}
	return strings.TrimSuffix(domain, ".")
}

// ---------------------------------------------------------------------------
// Enhancement 1: Zone transfer (AXFR) over TCP port 53
// ---------------------------------------------------------------------------

// axfrQuery builds a minimal raw DNS AXFR request message for the given domain.
// Wire format: 2-byte big-endian length prefix + standard DNS query.
// QTYPE=252 (AXFR), QCLASS=1 (IN).
func axfrQuery(domain string) []byte {
	// Build DNS message: header + question.
	var msg []byte
	// Transaction ID = 0xAAAA (arbitrary)
	msg = append(msg, 0xAA, 0xAA)
	// Flags: standard query, recursion desired
	msg = append(msg, 0x00, 0x00)
	// QDCOUNT=1
	msg = append(msg, 0x00, 0x01)
	// ANCOUNT, NSCOUNT, ARCOUNT = 0
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Encode QNAME as DNS labels.
	d := strings.TrimSuffix(domain, ".")
	for _, label := range strings.Split(d, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	// Root label terminator
	msg = append(msg, 0x00)
	// QTYPE=AXFR(252)
	msg = append(msg, 0x00, 0xFC)
	// QCLASS=IN(1)
	msg = append(msg, 0x00, 0x01)

	// Prepend 2-byte TCP length prefix.
	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(len(msg)))
	return append(prefix, msg...)
}

// parseDNSName reads a DNS wire-format name from buf starting at offset.
// Returns the name string and the offset after the name (handling compression).
func parseDNSName(buf []byte, offset int) (string, int) {
	var labels []string
	visited := make(map[int]bool)
	origOffset := -1
	for offset < len(buf) {
		if visited[offset] {
			break
		}
		visited[offset] = true
		length := int(buf[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			// Pointer compression.
			if offset+1 >= len(buf) {
				break
			}
			ptr := (int(buf[offset]&0x3F) << 8) | int(buf[offset+1])
			if origOffset == -1 {
				origOffset = offset + 2
			}
			offset = ptr
			continue
		}
		offset++
		if offset+length > len(buf) {
			break
		}
		labels = append(labels, string(buf[offset:offset+length]))
		offset += length
	}
	if origOffset != -1 {
		return strings.Join(labels, "."), origOffset
	}
	return strings.Join(labels, "."), offset
}

// axfrRecord holds a single resource record from a zone transfer.
type axfrRecord struct {
	Name  string
	Type  uint16
	RData string
}

// parseAXFRResponse extracts resource records from a raw DNS response buffer.
// We parse Answer section only (ANCOUNT records).
func parseAXFRResponse(buf []byte) []axfrRecord {
	if len(buf) < 12 {
		return nil
	}
	anCount := int(binary.BigEndian.Uint16(buf[6:8]))
	// Skip the header (12 bytes) and question section.
	offset := 12
	// Skip question section: QNAME + QTYPE(2) + QCLASS(2).
	_, offset = parseDNSName(buf, offset)
	offset += 4 // QTYPE + QCLASS

	var records []axfrRecord
	for i := 0; i < anCount && offset < len(buf); i++ {
		name, off := parseDNSName(buf, offset)
		if off+10 > len(buf) {
			break
		}
		rrType := binary.BigEndian.Uint16(buf[off : off+2])
		// class(2) + ttl(4) = 6 bytes
		rdLen := int(binary.BigEndian.Uint16(buf[off+8 : off+10]))
		off += 10
		if off+rdLen > len(buf) {
			break
		}
		rdata := buf[off : off+rdLen]
		offset = off + rdLen

		var rdataStr string
		switch rrType {
		case 1: // A
			if len(rdata) == 4 {
				rdataStr = fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
			}
		case 28: // AAAA
			ip := net.IP(rdata)
			rdataStr = ip.String()
		case 5, 2, 15: // CNAME, NS, MX — name-type rdata
			rdataStr, _ = parseDNSName(buf, off)
		default:
			rdataStr = hex.EncodeToString(rdata)
		}
		records = append(records, axfrRecord{Name: name, Type: rrType, RData: rdataStr})
	}
	return records
}

// attemptZoneTransfer tries an AXFR against each nameserver for domain.
// Returns extracted records on success; nil if all nameservers refuse.
func attemptZoneTransfer(ctx context.Context, domain string) []axfrRecord {
	r := resolverFor(0)
	nss, err := r.LookupNS(ctx, domain)
	if err != nil || len(nss) == 0 {
		return nil
	}

	query := axfrQuery(domain)
	for _, ns := range nss {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		dialer := net.Dialer{Timeout: 10 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", nsHost+":53")
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		_, err = conn.Write(query)
		if err != nil {
			conn.Close()
			continue
		}
		// Read all response data (TCP DNS: 2-byte length prefix per message).
		var fullBuf []byte
		for {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				break
			}
			msgLen := int(binary.BigEndian.Uint16(lenBuf))
			if msgLen == 0 {
				break
			}
			msgBuf := make([]byte, msgLen)
			if _, err := io.ReadFull(conn, msgBuf); err != nil {
				break
			}
			fullBuf = append(fullBuf, msgBuf...)
			// SOA record at start and end signals complete zone transfer.
			// We stop after reading a sizeable chunk to avoid infinite loops.
			if len(fullBuf) > 1<<20 {
				break
			}
		}
		conn.Close()
		if len(fullBuf) > 12 {
			// Check RCODE: bits 0-3 of byte 3 in DNS header.
			rcode := fullBuf[3] & 0x0F
			if rcode == 0 {
				recs := parseAXFRResponse(fullBuf)
				if len(recs) > 0 {
					return recs
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Enhancement 2: Subdomain permutation list
// ---------------------------------------------------------------------------

// permutationLabels is the set of high-value subdomain prefixes to probe.
var permutationLabels = []string{
	"api", "dev", "staging", "prod", "admin", "internal", "vpn",
	"mail", "ftp", "ssh", "jenkins", "gitlab", "jira", "confluence",
	"sonar", "nexus", "artifactory", "kibana", "grafana", "prometheus",
	"vault", "consul", "ldap", "backup", "static", "cdn", "assets",
	"test", "qa", "uat", "preprod", "beta", "alpha", "demo", "sandbox",
	"api2", "api-v2", "api-v1", "dev-api", "internal-api",
	"registry", "docker", "k8s", "kubernetes", "rancher",
	"elastic", "logstash", "fluentd", "splunk", "sentry",
	"db", "database", "mysql", "postgres", "redis", "mongo",
	"s3", "minio", "storage", "files", "uploads",
	"auth", "sso", "oauth", "login", "portal",
	"chat", "slack", "teams", "helpdesk", "ticket",
	"git", "svn", "code", "repo", "ci", "cd",
	"monitoring", "metrics", "health", "status", "uptime",
	"vpn2", "bastion", "jump", "proxy", "gateway", "waf",
	"smtp", "pop3", "imap", "mx1", "mx2", "webmail",
	"dev1", "dev2", "staging1", "staging2", "prod1", "prod2",
	"ns1", "ns2", "dns", "dns1", "dns2",
}

// ---------------------------------------------------------------------------
// Enhancement 3: Reverse DNS sweep
// ---------------------------------------------------------------------------

// reversePTR performs a reverse PTR lookup for the given IP.
func reversePTR(ctx context.Context, ip string) []string {
	r := resolverFor(0)
	hosts, err := r.LookupAddr(ctx, ip)
	if err != nil {
		return nil
	}
	var out []string
	for _, h := range hosts {
		out = append(out, strings.TrimSuffix(h, "."))
	}
	return out
}

// ---------------------------------------------------------------------------
// Enhancement 4: Certificate transparency via crt.sh
// ---------------------------------------------------------------------------

// crtShEntry is a single JSON record from crt.sh.
type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// queryCertTransparency queries crt.sh for known subdomains of domain.
// Returns unique subdomain labels (not FQDNs) discovered from certificate logs.
func queryCertTransparency(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "oi-recon-probe/1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil
	}

	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var subdomains []string
	suffix := "." + domain
	for _, e := range entries {
		// name_value may contain multiple names separated by newline.
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if !strings.HasSuffix(name, suffix) && name != domain {
				continue
			}
			label := strings.TrimSuffix(name, suffix)
			if label == "" || label == domain || seen[label] {
				continue
			}
			seen[label] = true
			subdomains = append(subdomains, label)
		}
	}
	return subdomains
}

// ---------------------------------------------------------------------------
// Enhancement 5: TXT record secrets detection
// ---------------------------------------------------------------------------

// privateIPRe matches RFC-1918 / loopback / link-local IPs in TXT records.
var privateIPRe = regexp.MustCompile(`\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+)\b`)

// tokenRe matches potential secrets/tokens in TXT records.
var tokenRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|apikey|api_key|credential|aws_|key=)[^\s"'<>]{8,}`)

// analyzeTXTRecords inspects TXT, SPF, DMARC, and DKIM records for misconfigurations.
// Returns a slice of Finding entries for each issue detected.
func analyzeTXTRecords(ctx context.Context, domain string, scanID string) []*Finding {
	r := resolverFor(0)
	var findings []*Finding
	now := time.Now().Unix()

	emit := func(fqdn, vulnType, severity, evidence string, meta map[string]string) {
		findings = append(findings, &Finding{
			ID:           findingID(scanID, vulnType+":"+fqdn),
			URL:          fqdn,
			VulnType:     vulnType,
			Severity:     severity,
			Evidence:     evidence,
			SourceTool:   "oi-recon-probe",
			DiscoveredAt: now,
			Metadata:     meta,
			Confidence:   0.85,
			ScanID:       scanID,
		})
	}

	// Check SPF record on the apex domain.
	apexTXTs, _ := r.LookupTXT(ctx, domain)
	hasSPF := false
	for _, txt := range apexTXTs {
		if strings.HasPrefix(txt, "v=spf1") {
			hasSPF = true
			if strings.Contains(txt, "+all") {
				emit(domain, "txt_spf_plusall", "high",
					fmt.Sprintf("SPF +all allows any sender: %s", txt),
					map[string]string{"record": txt, "issue": "spf_plusall"})
			}
			if strings.Contains(txt, "~all") {
				emit(domain, "txt_spf_softfail", "medium",
					fmt.Sprintf("SPF ~all (softfail) permits unauthorized senders: %s", txt),
					map[string]string{"record": txt, "issue": "spf_softfail"})
			}
		}
		// Detect internal IPs in any TXT record.
		if m := privateIPRe.FindString(txt); m != "" {
			emit(domain, "txt_internal_ip", "medium",
				fmt.Sprintf("Internal IP %s exposed in TXT record: %s", m, txt),
				map[string]string{"record": txt, "ip": m, "issue": "internal_ip_in_txt"})
		}
		// Detect potential tokens/secrets.
		if m := tokenRe.FindString(txt); m != "" {
			emit(domain, "txt_secret_token", "high",
				fmt.Sprintf("Potential secret in TXT record: %s", txt),
				map[string]string{"record": txt, "match": m, "issue": "secret_in_txt"})
		}
	}
	if !hasSPF {
		emit(domain, "txt_no_spf", "medium",
			"No SPF record found; domain may be used for phishing",
			map[string]string{"issue": "no_spf"})
	}

	// Check DMARC.
	dmarcFQDN := "_dmarc." + domain
	dmarcTXTs, _ := r.LookupTXT(ctx, dmarcFQDN)
	hasDMARC := false
	for _, txt := range dmarcTXTs {
		if strings.HasPrefix(txt, "v=DMARC1") {
			hasDMARC = true
			if strings.Contains(txt, "p=none") {
				emit(dmarcFQDN, "txt_dmarc_none", "medium",
					fmt.Sprintf("DMARC policy=none (monitoring only): %s", txt),
					map[string]string{"record": txt, "issue": "dmarc_p_none"})
			}
		}
	}
	if !hasDMARC {
		emit(domain, "txt_no_dmarc", "medium",
			"No DMARC record found; domain vulnerable to spoofing",
			map[string]string{"issue": "no_dmarc"})
	}

	// Check DKIM for common selectors.
	dkimSelectors := []string{"default", "google", "mail", "dkim", "selector1", "selector2", "k1"}
	for _, sel := range dkimSelectors {
		dkimFQDN := sel + "._domainkey." + domain
		dkimTXTs, err := r.LookupTXT(ctx, dkimFQDN)
		if err != nil {
			continue
		}
		for _, txt := range dkimTXTs {
			if !strings.Contains(txt, "p=") {
				continue
			}
			// Extract public key (p= field) and estimate length.
			// Base64-encoded RSA-1024 key is ~216 chars; RSA-512 is ~108.
			for _, field := range strings.Split(txt, ";") {
				field = strings.TrimSpace(field)
				if strings.HasPrefix(field, "p=") {
					keyB64 := strings.TrimPrefix(field, "p=")
					// Rough length heuristic: base64 chars * 6 / 8 * 8 = bits.
					estimatedBits := len(keyB64) * 6
					if estimatedBits < 1024 {
						emit(dkimFQDN, "txt_dkim_weak_key", "high",
							fmt.Sprintf("DKIM key estimated <1024 bits (%d est) selector=%s: %s",
								estimatedBits, sel, txt),
							map[string]string{
								"record":   txt,
								"selector": sel,
								"issue":    "dkim_short_key",
							})
					}
				}
			}
		}
	}

	return findings
}

// scan enumerates subdomains of the domain extracted from req.TargetURL.
// Results are sent on resultCh; the channel is NOT closed by this function —
// the caller closes it after the goroutine returns.
func scan(ctx context.Context, req *ScanRequest, resultCh chan<- *Finding) {
	domain := extractDomain(req.TargetURL)

	wordlistPath := ""
	if req.Options != nil {
		wordlistPath = req.Options["wordlist"]
	}
	words, err := loadWordlist(wordlistPath)
	if err != nil {
		log.Printf("wordlist error: %v; falling back to embedded list", err)
		words, _ = loadWordlist("")
	}

	// Wildcard detection: use resolver 0 for the probe.
	wildcard := isWildcard(ctx, domain, 0)
	if wildcard {
		log.Printf("wildcard DNS detected for %s", domain)
	}

	// -----------------------------------------------------------------------
	// Enhancement 1: Zone transfer attempt (AXFR).
	// -----------------------------------------------------------------------
	go func() {
		axfrRecs := attemptZoneTransfer(ctx, domain)
		if len(axfrRecs) == 0 {
			return
		}
		evJSON, _ := json.Marshal(axfrRecs)
		f := &Finding{
			ID:           findingID(req.ScanID, "axfr:"+domain),
			URL:          domain,
			VulnType:     "zone_transfer",
			Severity:     "critical",
			Evidence:     string(evJSON),
			SourceTool:   "oi-recon-probe",
			DiscoveredAt: time.Now().Unix(),
			Metadata: map[string]string{
				"domain":     domain,
				"rec_count":  fmt.Sprintf("%d", len(axfrRecs)),
				"issue":      "axfr_allowed",
			},
			Confidence: 1.0,
			ScanID:     req.ScanID,
		}
		select {
		case resultCh <- f:
		case <-ctx.Done():
		}
		// Emit individual AXFR subdomains as subdomain findings.
		seen := make(map[string]bool)
		for _, rec := range axfrRecs {
			name := strings.ToLower(strings.TrimSuffix(rec.Name, "."))
			if seen[name] || name == domain {
				continue
			}
			seen[name] = true
			sf := &Finding{
				ID:           findingID(req.ScanID, "axfr-sub:"+name),
				URL:          name,
				VulnType:     "subdomain",
				Severity:     "info",
				Evidence:     fmt.Sprintf("axfr rtype=%d rdata=%s", rec.Type, rec.RData),
				SourceTool:   "oi-recon-probe",
				DiscoveredAt: time.Now().Unix(),
				Metadata:     map[string]string{"domain": domain, "source": "axfr"},
				Confidence:   1.0,
				ScanID:       req.ScanID,
			}
			select {
			case resultCh <- sf:
			case <-ctx.Done():
				return
			}
		}
	}()

	// -----------------------------------------------------------------------
	// Enhancement 4: Certificate transparency (crt.sh).
	// -----------------------------------------------------------------------
	go func() {
		ctLabels := queryCertTransparency(ctx, domain)
		for _, label := range ctLabels {
			fqdn := label + "." + domain
			rec, err := resolveFQDN(ctx, fqdn, 0)
			if err != nil || !hasAnyRecord(rec) {
				// Still report the CT finding even if not currently live.
				f := &Finding{
					ID:           findingID(req.ScanID, "ct:"+fqdn),
					URL:          fqdn,
					VulnType:     "subdomain_ct",
					Severity:     "info",
					Evidence:     fmt.Sprintf("certificate transparency record for %s", fqdn),
					SourceTool:   "oi-recon-probe",
					DiscoveredAt: time.Now().Unix(),
					Metadata:     map[string]string{"domain": domain, "source": "crt.sh", "resolves": "false"},
					Confidence:   0.7,
					ScanID:       req.ScanID,
				}
				select {
				case resultCh <- f:
				case <-ctx.Done():
					return
				}
				continue
			}
			evJSON, _ := json.Marshal(rec)
			f := &Finding{
				ID:           findingID(req.ScanID, "ct:"+fqdn),
				URL:          fqdn,
				VulnType:     "subdomain_ct",
				Severity:     "info",
				Evidence:     string(evJSON),
				SourceTool:   "oi-recon-probe",
				DiscoveredAt: time.Now().Unix(),
				Metadata:     map[string]string{"domain": domain, "source": "crt.sh", "resolves": "true"},
				Confidence:   0.95,
				ScanID:       req.ScanID,
			}
			select {
			case resultCh <- f:
			case <-ctx.Done():
				return
			}
		}
	}()

	// -----------------------------------------------------------------------
	// Enhancement 5: TXT record secrets / misconfiguration detection.
	// -----------------------------------------------------------------------
	go func() {
		for _, f := range analyzeTXTRecords(ctx, domain, req.ScanID) {
			select {
			case resultCh <- f:
			case <-ctx.Done():
				return
			}
		}
	}()

	// -----------------------------------------------------------------------
	// Build the full probe list: wordlist + permutation labels (deduped).
	// -----------------------------------------------------------------------
	probeSet := make(map[string]bool)
	for _, w := range words {
		probeSet[w] = true
	}
	// Enhancement 2: add permutation labels.
	for _, p := range permutationLabels {
		probeSet[p] = true
	}
	allWords := make([]string, 0, len(probeSet))
	for w := range probeSet {
		allWords = append(allWords, w)
	}

	// Rate limiter: burst=1, one tick per (1s/rateLimit).
	ticker := time.NewTicker(time.Second / rateLimit)
	defer ticker.Stop()

	// Semaphore-controlled goroutine pool: exactly 500 workers max.
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var resolverCounter atomic.Int64

	for _, word := range allWords {
		// Bail early on context cancellation.
		if ctx.Err() != nil {
			break
		}

		fqdn := word + "." + domain

		// Consume one rate-limit token before acquiring pool slot.
		select {
		case <-ticker.C:
		case <-ctx.Done():
			goto drain
		}

		// Acquire one of the 500 pool slots.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			goto drain
		}

		wg.Add(1)
		idx := int(resolverCounter.Add(1)) - 1

		go func(fqdn string, rIdx int) {
			defer wg.Done()
			defer func() { <-sem }()

			rec, err := resolveFQDN(ctx, fqdn, rIdx)
			if err != nil || !hasAnyRecord(rec) {
				return
			}

			evJSON, _ := json.Marshal(rec)
			f := &Finding{
				ID:           findingID(req.ScanID, fqdn),
				URL:          fqdn,
				VulnType:     "subdomain",
				Severity:     "info",
				Evidence:     string(evJSON),
				SourceTool:   "oi-recon-probe",
				DiscoveredAt: time.Now().Unix(),
				Metadata: map[string]string{
					"domain":   domain,
					"wildcard": fmt.Sprintf("%v", wildcard),
				},
				Confidence: 0.9,
				ScanID:     req.ScanID,
			}

			select {
			case resultCh <- f:
			case <-ctx.Done():
			}

			// Enhancement 3: reverse PTR lookup for each resolved IP.
			allIPs := append(rec.A, rec.AAAA...)
			for _, ip := range allIPs {
				ptrs := reversePTR(ctx, ip)
				if len(ptrs) == 0 {
					continue
				}
				ptrJSON, _ := json.Marshal(ptrs)
				pf := &Finding{
					ID:           findingID(req.ScanID, "ptr:"+ip),
					URL:          fqdn,
					VulnType:     "reverse_dns",
					Severity:     "info",
					Evidence:     string(ptrJSON),
					SourceTool:   "oi-recon-probe",
					DiscoveredAt: time.Now().Unix(),
					Metadata: map[string]string{
						"domain": domain,
						"ip":     ip,
						"source": "ptr",
					},
					Confidence: 0.9,
					ScanID:     req.ScanID,
				}
				select {
				case resultCh <- pf:
				case <-ctx.Done():
					return
				}
			}
		}(fqdn, idx)
	}

drain:
	wg.Wait()
}

// ---------------------------------------------------------------------------
// gRPC service descriptor (no protoc — manual ServiceDesc)
// ---------------------------------------------------------------------------

type reconProbeServer struct{}

// scanHTTPHandler implements the server-streaming ScanHTTP RPC.
func scanHTTPHandler(_ interface{}, stream grpc.ServerStream) error {
	req := &ScanRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}

	ctx := stream.Context()
	resultCh := make(chan *Finding, 256)

	go func() {
		defer close(resultCh)
		scan(ctx, req, resultCh)
	}()

	for f := range resultCh {
		if err := stream.SendMsg(f); err != nil {
			return err
		}
	}
	return nil
}

// healthHandler implements the unary Health RPC.
func healthHandler(_ interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := &HealthCheckRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return &HealthCheckResponse{Status: 1 /* SERVING */}, nil
	}
	if interceptor != nil {
		return interceptor(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: "/oneinfinity.v1.ReconProbe/Health",
		}, handler)
	}
	return handler(ctx, req)
}

// reconProbeServiceDesc is the manual gRPC service descriptor.
var reconProbeServiceDesc = grpc.ServiceDesc{
	ServiceName: "oneinfinity.v1.ReconProbe",
	HandlerType: (*reconProbeServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Health",
			Handler:    healthHandler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ScanHTTP",
			Handler:       scanHTTPHandler,
			ServerStreams: true,
		},
	},
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	const addr = "127.0.0.1:50052"

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}

	s := grpc.NewServer(
		grpc.UnknownServiceHandler(func(_ interface{}, stream grpc.ServerStream) error {
			return status.Errorf(codes.Unimplemented, "unknown service or method")
		}),
	)
	s.RegisterService(&reconProbeServiceDesc, &reconProbeServer{})

	log.Printf("oi-recon-probe listening on %s (pool=%d goroutines, rate=%d qps)",
		addr, concurrency, rateLimit)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
