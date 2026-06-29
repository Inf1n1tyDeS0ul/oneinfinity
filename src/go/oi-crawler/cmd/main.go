// cmd/main.go — entry point for the oi-crawler gRPC sidecar.
// Binds ONLY to 127.0.0.1 (never 0.0.0.0).
// Port: env SIDECAR_PORT, default 50056.
package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	// side-effect: registers JSON codec overriding the default "proto" codec
	_ "github.com/oneinfinity/oi-crawler/pb"
	"github.com/oneinfinity/oi-crawler/server"
)

func main() {
	port := os.Getenv("SIDECAR_PORT")
	if port == "" {
		port = "50056"
	}

	addr := fmt.Sprintf("127.0.0.1:%s", port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("oi-crawler: listen %s: %v", addr, err)
	}

	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 60e9, // 60 s in nanoseconds
		}),
	)

	grpcServer.RegisterService(&server.CrawlerServiceDesc, &server.CrawlerServer{})

	log.Printf("oi-crawler: listening on %s", addr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("oi-crawler: serve: %v", err)
	}
}
