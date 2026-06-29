// oi-ssrf: SSRF scanner gRPC sidecar on 127.0.0.1:50053
//
// Implements SSRFScanner service:
//   Scan(ScanRequest) → stream Finding
//   Health(HealthCheckRequest) → HealthCheckResponse
//
// Tests: AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Kubernetes,
//        redirect-chain SSRF, internal CIDR scan (10.x, 172.x, 192.168.x).
// OOB blind-SSRF correlation via oi-oob-listener subdomain tokens.
package main

import (
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/oneinfinity/oi-ssrf/internal/grpcsvc"
	"github.com/oneinfinity/oi-ssrf/internal/pb"
)

func main() {
	grpcPort := os.Getenv("SSRF_GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "50053"
	}
	addr := "127.0.0.1:" + grpcPort

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[oi-ssrf] failed to listen on %s: %v", addr, err)
	}

	// FD/connection budget
	srv := grpc.NewServer(
		grpc.MaxConcurrentStreams(128),
	)

	pb.RegisterSSRFScannerServer(srv, grpcsvc.NewSSRFServer())

	log.Printf("[oi-ssrf] gRPC SSRFScanner listening on %s", addr)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("[oi-ssrf] gRPC serve error: %v", err)
	}
}
