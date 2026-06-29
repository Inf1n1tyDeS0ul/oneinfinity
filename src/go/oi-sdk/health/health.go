// Package health implements a gRPC health handler that always returns SERVING.
// Register it on every sidecar server with:
//
//	pb.RegisterHealthServer(grpcServer, health.NewHandler())
package health

import (
	"context"

	"github.com/oneinfinity/oi-sdk/pb"
)

// Handler satisfies pb.HealthServer.
type Handler struct{}

// NewHandler returns a Handler that unconditionally reports SERVING.
func NewHandler() *Handler { return &Handler{} }

// Check returns SERVING for any service name, including the empty string.
func (h *Handler) Check(_ context.Context, _ *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{Status: pb.HealthCheckResponse_SERVING}, nil
}
