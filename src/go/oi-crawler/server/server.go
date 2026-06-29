// Package server wires the crawler engine to a gRPC CrawlerService.
// We use grpc.ServiceDesc directly to avoid needing protoc-generated code.
// Wire format is JSON (registered in pb/codec.go by overriding the "proto" codec).
package server

import (
	"context"
	"log"
	"net/url"

	"google.golang.org/grpc"

	"github.com/oneinfinity/oi-crawler/crawler"
	"github.com/oneinfinity/oi-crawler/pb"
)

// CrawlerServer implements the CrawlerService gRPC service.
type CrawlerServer struct{}

// Crawl streams URL results for the given CrawlRequest.
func (s *CrawlerServer) Crawl(req *pb.CrawlRequest, stream grpc.ServerStream) error {
	done := make(chan struct{})
	results := make(chan crawler.Result, 64)

	go func() {
		defer close(results)
		crawler.Run(crawler.Config{
			StartURL:         req.StartUrl,
			ScanID:           req.ScanId,
			MaxPages:         int(req.MaxPages),
			Parallelism:      int(req.Parallelism),
			ExcludedPatterns: req.ExcludedPatterns,
		}, results, done)
	}()

	for {
		select {
		case <-stream.Context().Done():
			close(done)
			return stream.Context().Err()
		case r, ok := <-results:
			if !ok {
				return nil
			}
			msg := &pb.URL{
				Url:        r.URL,
				Method:     r.Method,
				StatusCode: int32(r.StatusCode),
				Forms:      r.Forms,
				JsFiles:    r.JsFiles,
				EventId:    r.EventID,
			}
			if err := stream.SendMsg(msg); err != nil {
				close(done)
				return err
			}
		}
	}
}

// Health returns SERVING unconditionally.
func (s *CrawlerServer) Health(_ context.Context, _ *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{Status: pb.HealthCheckResponse_SERVING}, nil
}

// ─── gRPC service descriptor ──────────────────────────────────────────────────

// CrawlerServiceDesc is the grpc.ServiceDesc for CrawlerService.
// Method signatures must match the proto contract exactly:
//   - Crawl(CrawlRequest) returns (stream URL)
//   - Health(HealthCheckRequest) returns (HealthCheckResponse)
var CrawlerServiceDesc = grpc.ServiceDesc{
	ServiceName: "oneinfinity.v1.CrawlerService",
	HandlerType: (*CrawlerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Health",
			Handler:    healthHandler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Crawl",
			Handler:       crawlHandler,
			ServerStreams: true,
		},
	},
}

func healthHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(pb.HealthCheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*CrawlerServer).Health(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/oneinfinity.v1.CrawlerService/Health"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(*CrawlerServer).Health(ctx, req.(*pb.HealthCheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func crawlHandler(srv interface{}, stream grpc.ServerStream) error {
	msg := new(pb.CrawlRequest)
	if err := stream.RecvMsg(msg); err != nil {
		return err
	}
	redactedURL := msg.StartUrl
	if u, err := url.Parse(msg.StartUrl); err == nil {
		redactedURL = u.Redacted()
	}
	log.Printf("[crawler] Crawl scan_id=%s start_url=%s max_pages=%d parallelism=%d",
		msg.ScanId, redactedURL, msg.MaxPages, msg.Parallelism)
	return srv.(*CrawlerServer).Crawl(msg, stream)
}
