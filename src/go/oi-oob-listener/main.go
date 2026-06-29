// oi-oob-listener: persistent OOB interaction server + gRPC OOBService on 127.0.0.1:50054
//
// Listeners:
//   HTTP  127.0.0.1:8880  (OOB_HTTP_PORT)
//   DNS   127.0.0.1:5353  (OOB_DNS_PORT, UDP+TCP)
//   SMTP  127.0.0.1:2525  (OOB_SMTP_PORT)
//
// gRPC:  127.0.0.1:50054  (OOB_GRPC_PORT)
package main

import (
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/oneinfinity/oi-oob-listener/internal/grpcsvc"
	"github.com/oneinfinity/oi-oob-listener/internal/listeners"
	"github.com/oneinfinity/oi-oob-listener/internal/pb"
)

func main() {
	store := listeners.NewStore()

	// Start OOB protocol listeners (each runs in its own goroutine internally)
	go listeners.StartHTTP(store)
	go listeners.StartDNS(store)
	go listeners.StartSMTP(store)

	grpcPort := os.Getenv("OOB_GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "50054"
	}
	addr := "127.0.0.1:" + grpcPort

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[oi-oob-listener] failed to listen on %s: %v", addr, err)
	}

	// FD/connection budget: cap concurrent streams
	srv := grpc.NewServer(
		grpc.MaxConcurrentStreams(256),
	)

	pb.RegisterOOBServiceServer(srv, grpcsvc.NewOOBServer(store))

	log.Printf("[oi-oob-listener] gRPC OOBService listening on %s", addr)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("[oi-oob-listener] gRPC serve error: %v", err)
	}
}
