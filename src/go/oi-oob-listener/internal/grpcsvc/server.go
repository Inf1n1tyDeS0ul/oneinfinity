// Package grpcsvc implements the OOBService gRPC server.
package grpcsvc

import (
	"context"
	"fmt"
	"time"

	"github.com/oneinfinity/oi-oob-listener/internal/listeners"
	"github.com/oneinfinity/oi-oob-listener/internal/pb"
)

// OOBServer implements pb.OOBServiceServer.
type OOBServer struct {
	store *listeners.Store
}

// NewOOBServer creates an OOBServer backed by the given interaction store.
func NewOOBServer(store *listeners.Store) *OOBServer {
	return &OOBServer{store: store}
}

// Start allocates a unique OOB subdomain for the given scan_id.
// Domain format: <scan_id>.oob.local
func (s *OOBServer) Start(_ context.Context, req *pb.OOBStartRequest) (*pb.OOBDomain, error) {
	if req.ScanId == "" {
		return nil, fmt.Errorf("scan_id is required")
	}
	domain := fmt.Sprintf("%s.oob.local", req.ScanId)
	return &pb.OOBDomain{
		Domain: domain,
		ScanId: req.ScanId,
	}, nil
}

// Poll streams all Interaction records for the given scan_id that arrive
// within timeout_seconds. It first flushes already-stored interactions,
// then waits for new ones until the deadline expires.
func (s *OOBServer) Poll(req *pb.PollRequest, stream pb.OOBService_PollServer) error {
	if req.ScanId == "" {
		return fmt.Errorf("scan_id is required")
	}

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)

	cursor := int64(0)
	for {
		batch := s.store.Since(req.ScanId, cursor)
		for _, i := range batch {
			if err := stream.Send(i); err != nil {
				return err
			}
			if i.ReceivedAt > cursor {
				cursor = i.ReceivedAt
			}
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}

		waitTimer := time.NewTimer(remaining)
		select {
		case <-s.store.Notify():
			waitTimer.Stop()
		case <-waitTimer.C:
			return nil
		case <-stream.Context().Done():
			waitTimer.Stop()
			return stream.Context().Err()
		}
	}
}

// Health returns SERVING unconditionally.
func (s *OOBServer) Health(_ context.Context, _ *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{Status: pb.ServingStatus_SERVING}, nil
}
