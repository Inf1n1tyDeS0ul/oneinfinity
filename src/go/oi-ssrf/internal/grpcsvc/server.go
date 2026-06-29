// Package grpcsvc implements the SSRFScanner gRPC service.
package grpcsvc

import (
	"context"
	"log"
	"net/url"

	"github.com/oneinfinity/oi-ssrf/internal/pb"
	"github.com/oneinfinity/oi-ssrf/internal/scanner"
)

// SSRFServer implements pb.SSRFScannerServer.
type SSRFServer struct{}

// NewSSRFServer returns a ready SSRFServer.
func NewSSRFServer() *SSRFServer { return &SSRFServer{} }

// Scan streams SSRF findings for the given ScanRequest.
// It contacts oi-oob-listener to obtain an OOB domain for blind-SSRF correlation
// if an oob_listener_addr option is present; otherwise falls back to a static token.
func (s *SSRFServer) Scan(req *pb.ScanRequest, stream pb.SSRFScanner_ScanServer) error {
	ctx := stream.Context()

	// Derive OOB domain: prefer option override, else synthesise from scan_id
	oobDomain := req.Options["oob_domain"]
	if oobDomain == "" {
		oobDomain = req.ScanId + ".oob.local"
	}

	redacted := req.TargetUrl
	if u, err := url.Parse(req.TargetUrl); err == nil {
		redacted = u.Redacted()
	}
	log.Printf("[oi-ssrf] Scan start: target=%s scan_id=%s", redacted, req.ScanId)

	findings := make(chan *pb.Finding, 64)

	// Run scanner in a goroutine; close channel when done
	go func() {
		defer close(findings)
		scanner.Scan(ctx, req, oobDomain, findings)
	}()

	for f := range findings {
		if err := stream.Send(f); err != nil {
			return err
		}
	}
	return nil
}

// Health returns SERVING unconditionally.
func (s *SSRFServer) Health(_ context.Context, _ *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{Status: pb.ServingStatus_SERVING}, nil
}
