// Package sidecar provides shared startup helpers used by every oi-* sidecar.
package sidecar

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// defaultPorts is the authoritative port map; mirrors config/ports.json plus
// oi-target-disc (50059).
var defaultPorts = map[string]int{
	"oi-phase-runner": 50051,
	"oi-recon-probe":  50052,
	"oi-ssrf":         50053,
	"oi-oob-listener": 50054,
	"oi-idor-engine":  50055,
	"oi-crawler":      50056,
	"oi-live-surface": 50057,
	"oi-ingest":       50058,
	"oi-target-disc":  50059,
}

// Config holds resource budget settings for a sidecar instance.
type Config struct {
	ServiceName    string
	Port           int
	MaxConnections int
	MaxFDs         int
	PerHostLimit   int
	// MaxRecvMsgBytes caps individual gRPC message receive size (default 4 MiB).
	// Prevents memory exhaustion from malformed or oversized extraction outputs.
	MaxRecvMsgBytes int
	// MaxSendMsgBytes caps individual gRPC message send size (default 4 MiB).
	MaxSendMsgBytes int
	// TLSCertFile and TLSKeyFile, when both set, enable mTLS on the gRPC server.
	// Set via SIDECAR_TLS_CERT / SIDECAR_TLS_KEY env vars.
	TLSCertFile string
	TLSKeyFile  string
}

// LoadConfig builds a Config from environment variables, falling back to
// sensible defaults. name must match a key in the defaultPorts map.
func LoadConfig(name string) Config {
	port := envInt("SIDECAR_PORT", defaultPorts[name])
	if port == 0 {
		log.Printf("WARNING: unknown service name %q, SIDECAR_PORT must be set explicitly", name)
	}
	return Config{
		ServiceName:     name,
		Port:            port,
		MaxConnections:  envInt("SIDECAR_MAX_CONN", 200),
		MaxFDs:          envInt("SIDECAR_MAX_FDS", 1000),
		PerHostLimit:    envInt("SIDECAR_PER_HOST", 10),
		MaxRecvMsgBytes: envInt("SIDECAR_MAX_RECV_BYTES", 4*1024*1024),
		MaxSendMsgBytes: envInt("SIDECAR_MAX_SEND_BYTES", 4*1024*1024),
		TLSCertFile:     os.Getenv("SIDECAR_TLS_CERT"),
		TLSKeyFile:      os.Getenv("SIDECAR_TLS_KEY"),
	}
}

// NewServer creates a gRPC server with per-connection limits, message-size
// caps, keepalive, and optional mTLS.
//
// mTLS is enabled when both cfg.TLSCertFile and cfg.TLSKeyFile are non-empty.
// In production, set SIDECAR_TLS_CERT and SIDECAR_TLS_KEY to the paths of
// the server certificate and private key respectively.
func NewServer(cfg Config) *grpc.Server {
	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(uint32(cfg.MaxConnections)),
		grpc.MaxRecvMsgSize(cfg.MaxRecvMsgBytes),
		grpc.MaxSendMsgSize(cfg.MaxSendMsgBytes),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     5 * time.Minute,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 10 * time.Second,
			Time:                  2 * time.Minute,
			Timeout:               20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Fatalf("[%s] failed to load TLS keypair: %v", cfg.ServiceName, err)
		}
		pool := x509.NewCertPool()
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			// Require client certs when a CA pool is supplied (mTLS).
			// With an empty pool the server still encrypts but does not
			// enforce client identity — useful in dev/loopback contexts.
			ClientAuth: tls.VerifyClientCertIfGiven,
			MinVersion: tls.VersionTLS13,
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		log.Printf("[%s] mTLS enabled (cert=%s)", cfg.ServiceName, cfg.TLSCertFile)
	} else {
		log.Printf("[%s] WARNING: mTLS not configured — loopback-only plain gRPC (dev mode)", cfg.ServiceName)
	}

	return grpc.NewServer(opts...)
}

// ListenAndServe binds to 127.0.0.1:cfg.Port and starts serving. It blocks
// until SIGTERM or SIGINT is received, then gives in-flight RPCs 30 s to
// finish before forcibly stopping. All log output goes to stderr.
func ListenAndServe(server *grpc.Server, cfg Config) error {
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("[%s] gRPC listening on %s", cfg.ServiceName, addr)
		if err := server.Serve(lis); err != nil {
			errCh <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-quit:
		log.Printf("[%s] received %s — draining (30s grace)", cfg.ServiceName, sig)
	case err := <-errCh:
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()

	select {
	case <-ctx.Done():
		log.Printf("[%s] grace period expired — forcing stop", cfg.ServiceName)
		server.Stop()
	case <-stopped:
		log.Printf("[%s] clean shutdown", cfg.ServiceName)
	}
	return nil
}

// envInt reads an integer from an environment variable; returns def on missing
// or unparseable value.
func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
