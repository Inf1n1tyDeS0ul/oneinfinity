// Package listeners implements HTTP, DNS, and SMTP OOB interaction listeners.
// Each listener extracts a correlation token of the form <scan_id>-<probe_id>
// from incoming requests and stores the Interaction for later retrieval.
package listeners

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oneinfinity/oi-oob-listener/internal/pb"
)

// Store is a thread-safe map of scan_id → []Interaction plus a broadcast
// channel that fires whenever a new interaction arrives.
const (
	maxPerScan       = 10_000
	maxGlobalEntries = 500_000
)

type Store struct {
	mu          sync.RWMutex
	data        map[string][]*pb.Interaction
	globalCount int
	notify      chan struct{}
}

func NewStore() *Store {
	return &Store{
		data:   make(map[string][]*pb.Interaction),
		notify: make(chan struct{}, 256),
	}
}

// Add records an interaction and pings all pollers.
// Drops silently if the per-scan cap or global ceiling is reached.
func (s *Store) Add(i *pb.Interaction) {
	s.mu.Lock()
	if s.globalCount >= maxGlobalEntries {
		s.mu.Unlock()
		return
	}
	bucket := s.data[i.ScanId]
	if len(bucket) >= maxPerScan {
		s.mu.Unlock()
		return
	}
	s.data[i.ScanId] = append(bucket, i)
	s.globalCount++
	s.mu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Since returns all interactions for scanID whose ReceivedAt > afterNs.
func (s *Store) Since(scanID string, afterNs int64) []*pb.Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*pb.Interaction
	for _, i := range s.data[scanID] {
		if i.ReceivedAt > afterNs {
			out = append(out, i)
		}
	}
	return out
}

// Notify returns the store's broadcast channel (read-only).
func (s *Store) Notify() <-chan struct{} { return s.notify }

// ─── Token extraction ─────────────────────────────────────────────────────────

// extractToken finds the first token matching <scan_id>-<probe_id> pattern.
// It scans subdomains, URL paths, and arbitrary strings.
func extractToken(s string) string {
	// A token looks like: alphanumeric-alphanumeric (at least 4 chars each part)
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '.' || r == '/' || r == ' ' || r == '\r' || r == '\n'
	})
	for _, p := range parts {
		if idx := strings.Index(p, "-"); idx > 0 {
			left := p[:idx]
			right := p[idx+1:]
			if len(left) >= 4 && len(right) >= 4 && isAlnum(left) && isAlnum(right) {
				return p
			}
		}
	}
	return ""
}

func isAlnum(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return len(s) > 0
}

// scanIDFromToken returns the scan_id portion (left of first '-').
func scanIDFromToken(token string) string {
	if idx := strings.Index(token, "-"); idx > 0 {
		return token[:idx]
	}
	return token
}

// ─── HTTP listener ────────────────────────────────────────────────────────────

func StartHTTP(store *Store) {
	port := os.Getenv("OOB_HTTP_PORT")
	if port == "" {
		port = "8880"
	}
	addr := "127.0.0.1:" + port

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)

		// Try path, query, Host header for embedded token
		token := extractToken(r.URL.Path)
		if token == "" {
			token = extractToken(r.URL.RawQuery)
		}
		if token == "" {
			token = extractToken(r.Host)
		}
		scanID := scanIDFromToken(token)
		if scanID == "" {
			scanID = "unknown"
		}

		payload := fmt.Sprintf("%s %s %s", r.Method, r.URL.String(), r.Header.Get("User-Agent"))
		store.Add(&pb.Interaction{
			Protocol:   "http",
			SourceIp:   sourceIP,
			Payload:    payload,
			ReceivedAt: time.Now().UnixNano(),
			ScanId:     scanID,
		})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:        addr,
		Handler:     mux,
		ReadTimeout: 10 * time.Second,
	}
	log.Printf("[oob-http] listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[oob-http] error: %v", err)
	}
}

// ─── DNS listener ─────────────────────────────────────────────────────────────

func StartDNS(store *Store) {
	port := os.Getenv("OOB_DNS_PORT")
	if port == "" {
		port = "5353"
	}
	addr := "127.0.0.1:" + port

	// Start both UDP and TCP
	go serveDNS(store, "udp", addr)
	go serveDNS(store, "tcp", addr)
}

func serveDNS(store *Store, network, addr string) {
	var pc interface {
		ReadFrom(b []byte) (int, net.Addr, error)
		Close() error
	}

	if network == "udp" {
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			log.Printf("[oob-dns-udp] listen error: %v", err)
			return
		}
		defer conn.Close()
		log.Printf("[oob-dns] UDP listening on %s", addr)
		buf := make([]byte, 512)
		for {
			n, remoteAddr, err := conn.ReadFrom(buf)
			if err != nil {
				log.Printf("[oob-dns-udp] read error: %v", err)
				continue
			}
			processDNSPacket(store, buf[:n], remoteAddr.String())
		}
	} else {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[oob-dns-tcp] listen error: %v", err)
			return
		}
		defer ln.Close()
		log.Printf("[oob-dns] TCP listening on %s", addr)
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("[oob-dns-tcp] accept error: %v", err)
				continue
			}
			go handleDNSTCP(store, conn)
		}
	}
	_ = pc
}

func handleDNSTCP(store *Store, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// DNS over TCP: 2-byte length prefix
	lenBuf := make([]byte, 2)
	if _, err := conn.Read(lenBuf); err != nil {
		return
	}
	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen > 512 {
		msgLen = 512
	}
	buf := make([]byte, msgLen)
	n, _ := conn.Read(buf)
	processDNSPacket(store, buf[:n], conn.RemoteAddr().String())
}

// processDNSPacket extracts the queried domain from a raw DNS packet
// (minimal parser — read QNAME from question section).
func processDNSPacket(store *Store, pkt []byte, remoteAddr string) {
	if len(pkt) < 12 {
		return
	}
	// Skip header (12 bytes), parse QNAME
	pos := 12
	var labels []string
	for pos < len(pkt) {
		length := int(pkt[pos])
		pos++
		if length == 0 {
			break
		}
		if length&0xC0 == 0xC0 {
			break // DNS compression pointer — do not dereference
		}
		if pos+length > len(pkt) {
			break
		}
		labels = append(labels, string(pkt[pos:pos+length]))
		pos += length
	}
	domain := strings.Join(labels, ".")

	token := extractToken(domain)
	scanID := scanIDFromToken(token)
	if scanID == "" {
		scanID = "unknown"
	}

	sourceIP, _, _ := net.SplitHostPort(remoteAddr)
	store.Add(&pb.Interaction{
		Protocol:   "dns",
		SourceIp:   sourceIP,
		Payload:    domain,
		ReceivedAt: time.Now().UnixNano(),
		ScanId:     scanID,
	})
}

// ─── SMTP listener ────────────────────────────────────────────────────────────

func StartSMTP(store *Store) {
	port := os.Getenv("OOB_SMTP_PORT")
	if port == "" {
		port = "2525"
	}
	addr := "127.0.0.1:" + port

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[oob-smtp] listen error: %v", err)
		return
	}
	defer ln.Close()
	log.Printf("[oob-smtp] listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[oob-smtp] accept error: %v", err)
			continue
		}
		go handleSMTP(store, conn)
	}
}

func handleSMTP(store *Store, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	sourceIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	fmt.Fprintln(w, "220 oob.local ESMTP OOBListener")
	_ = w.Flush()

	var heloHost string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO ") || strings.HasPrefix(upper, "HELO "):
			heloHost = strings.TrimSpace(line[5:])
			fmt.Fprintln(w, "250-oob.local")
			fmt.Fprintln(w, "250 OK")
			_ = w.Flush()

			// Extract token from HELO hostname
			token := extractToken(heloHost)
			scanID := scanIDFromToken(token)
			if scanID == "" {
				scanID = "unknown"
			}
			store.Add(&pb.Interaction{
				Protocol:   "smtp",
				SourceIp:   sourceIP,
				Payload:    "HELO " + heloHost,
				ReceivedAt: time.Now().UnixNano(),
				ScanId:     scanID,
			})
		case strings.HasPrefix(upper, "RCPT TO"):
			fmt.Fprintln(w, "250 OK")
			_ = w.Flush()
		case upper == "DATA":
			fmt.Fprintln(w, "354 End data with <CR><LF>.<CR><LF>")
			_ = w.Flush()
			const maxSMTPBody = 64 * 1024
			var bodyBuf strings.Builder
			for bodyBuf.Len() < maxSMTPBody {
				l, e := r.ReadString('\n')
				if e != nil || strings.TrimRight(l, "\r\n") == "." {
					break
				}
				bodyBuf.WriteString(l)
			}
			body := bodyBuf.String()
			// Also try to extract token from email body
			token := extractToken(body)
			scanID := scanIDFromToken(token)
			if scanID == "" {
				scanID = scanIDFromToken(extractToken(heloHost))
			}
			if scanID == "" {
				scanID = "unknown"
			}
			store.Add(&pb.Interaction{
				Protocol:   "smtp",
				SourceIp:   sourceIP,
				Payload:    "DATA: " + body,
				ReceivedAt: time.Now().UnixNano(),
				ScanId:     scanID,
			})
			fmt.Fprintln(w, "250 OK")
			_ = w.Flush()
		case upper == "QUIT":
			fmt.Fprintln(w, "221 Bye")
			_ = w.Flush()
			return
		default:
			fmt.Fprintln(w, "502 Command not implemented")
			_ = w.Flush()
		}
	}
}
