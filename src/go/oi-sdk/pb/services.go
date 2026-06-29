// Package pb — service interfaces and gRPC registration helpers.
//
// Every service's Server interface and Register* function is defined here.
// Other agents must implement the Server interface for their service, then
// call the matching Register* function.
//
// Wire format: JSON over gRPC framing (see codec in pb.go). The JSON codec
// is named "proto" so gRPC picks it up as the default without any extra dial
// options.
//
// Quick-start for a new sidecar (copy this block):
//
//	type myImpl struct{ pb.UnimplementedXxxServer }
//	func (m *myImpl) Xxx(req *pb.XxxRequest, stream pb.XxxService_XxxServer) error { ... }
//	func (m *myImpl) Health(ctx context.Context, r *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
//	    return &pb.HealthCheckResponse{Status: pb.HealthCheckResponse_SERVING}, nil
//	}
//	// In main():
//	srv := sidecar.NewServer(cfg)
//	pb.RegisterXxxServiceServer(srv, &myImpl{})
//	sidecar.ListenAndServe(srv, cfg)

package pb

import (
	"context"

	"google.golang.org/grpc"
)

// ---------------------------------------------------------------------------
// Streaming-server helper interfaces — one per stream RPC direction.
// ---------------------------------------------------------------------------

// grpcServerStream wraps grpc.ServerStream for typed Send/Recv helpers used
// by the generated service servers below.
type grpcServerStream[T any] interface {
	grpc.ServerStream
	Send(*T) error
}

// ---------------------------------------------------------------------------
// HealthServer — shared by ALL services.
// ---------------------------------------------------------------------------

// HealthServer is implemented by every sidecar service.
type HealthServer interface {
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

// RegisterHealthServer binds a HealthServer to s under the standard Health
// service descriptor. Each sidecar calls this once alongside its own service.
func RegisterHealthServer(s *grpc.Server, srv HealthServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.Health",
		HandlerType: (*HealthServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Check",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(HealthServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{},
	}, srv)
}

// ---------------------------------------------------------------------------
// CrawlerService
// ---------------------------------------------------------------------------

// CrawlerService_CrawlServer is the server-side stream for Crawl.
type CrawlerService_CrawlServer interface {
	Send(*URL) error
	grpc.ServerStream
}

type crawlServerStream struct{ grpc.ServerStream }

func (s *crawlServerStream) Send(m *URL) error { return s.ServerStream.SendMsg(m) }

// CrawlerServiceServer must be implemented by the oi-crawler sidecar.
type CrawlerServiceServer interface {
	Crawl(*CrawlRequest, CrawlerService_CrawlServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

// UnimplementedCrawlerServiceServer provides safe defaults so new sidecars
// only override the methods they need.
type UnimplementedCrawlerServiceServer struct{}

func (UnimplementedCrawlerServiceServer) Crawl(_ *CrawlRequest, _ CrawlerService_CrawlServer) error {
	return nil
}
func (UnimplementedCrawlerServiceServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterCrawlerServiceServer binds srv to s.
func RegisterCrawlerServiceServer(s *grpc.Server, srv CrawlerServiceServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.CrawlerService",
		HandlerType: (*CrawlerServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(CrawlerServiceServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Crawl",
				Handler:       crawlHandler,
				ServerStreams: true,
			},
		},
	}, srv)
}

func crawlHandler(srv any, stream grpc.ServerStream) error {
	req := &CrawlRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	return srv.(CrawlerServiceServer).Crawl(req, &crawlServerStream{stream})
}

// ---------------------------------------------------------------------------
// ReconProbe
// ---------------------------------------------------------------------------

// ReconProbe_ScanHTTPServer is the server-side stream for ScanHTTP.
type ReconProbe_ScanHTTPServer interface {
	Send(*Finding) error
	grpc.ServerStream
}

type reconScanHTTPStream struct{ grpc.ServerStream }

func (s *reconScanHTTPStream) Send(m *Finding) error { return s.ServerStream.SendMsg(m) }

// ReconProbeServer must be implemented by the oi-recon-probe sidecar.
type ReconProbeServer interface {
	ScanHTTP(*ScanRequest, ReconProbe_ScanHTTPServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

type UnimplementedReconProbeServer struct{}

func (UnimplementedReconProbeServer) ScanHTTP(_ *ScanRequest, _ ReconProbe_ScanHTTPServer) error {
	return nil
}
func (UnimplementedReconProbeServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterReconProbeServer binds srv to s.
func RegisterReconProbeServer(s *grpc.Server, srv ReconProbeServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.ReconProbe",
		HandlerType: (*ReconProbeServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(ReconProbeServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "ScanHTTP",
				Handler:       reconScanHTTPHandler,
				ServerStreams: true,
			},
		},
	}, srv)
}

func reconScanHTTPHandler(srv any, stream grpc.ServerStream) error {
	req := &ScanRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	return srv.(ReconProbeServer).ScanHTTP(req, &reconScanHTTPStream{stream})
}

// ---------------------------------------------------------------------------
// SSRFScanner
// ---------------------------------------------------------------------------

// SSRFScanner_ScanServer is the server-side stream for Scan.
type SSRFScanner_ScanServer interface {
	Send(*Finding) error
	grpc.ServerStream
}

type ssrfScanStream struct{ grpc.ServerStream }

func (s *ssrfScanStream) Send(m *Finding) error { return s.ServerStream.SendMsg(m) }

// SSRFScannerServer must be implemented by the oi-ssrf sidecar.
type SSRFScannerServer interface {
	Scan(*ScanRequest, SSRFScanner_ScanServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

type UnimplementedSSRFScannerServer struct{}

func (UnimplementedSSRFScannerServer) Scan(_ *ScanRequest, _ SSRFScanner_ScanServer) error {
	return nil
}
func (UnimplementedSSRFScannerServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterSSRFScannerServer binds srv to s.
func RegisterSSRFScannerServer(s *grpc.Server, srv SSRFScannerServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.SSRFScanner",
		HandlerType: (*SSRFScannerServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(SSRFScannerServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Scan",
				Handler:       ssrfScanHandler,
				ServerStreams: true,
			},
		},
	}, srv)
}

func ssrfScanHandler(srv any, stream grpc.ServerStream) error {
	req := &ScanRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	return srv.(SSRFScannerServer).Scan(req, &ssrfScanStream{stream})
}

// ---------------------------------------------------------------------------
// OOBService
// ---------------------------------------------------------------------------

// OOBService_PollServer is the server-side stream for Poll.
type OOBService_PollServer interface {
	Send(*Interaction) error
	grpc.ServerStream
}

type oobPollStream struct{ grpc.ServerStream }

func (s *oobPollStream) Send(m *Interaction) error { return s.ServerStream.SendMsg(m) }

// OOBServiceServer must be implemented by the oi-oob-listener sidecar.
type OOBServiceServer interface {
	Start(context.Context, *OOBStartRequest) (*OOBDomain, error)
	Poll(*PollRequest, OOBService_PollServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

type UnimplementedOOBServiceServer struct{}

func (UnimplementedOOBServiceServer) Start(_ context.Context, _ *OOBStartRequest) (*OOBDomain, error) {
	return &OOBDomain{}, nil
}
func (UnimplementedOOBServiceServer) Poll(_ *PollRequest, _ OOBService_PollServer) error {
	return nil
}
func (UnimplementedOOBServiceServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterOOBServiceServer binds srv to s.
func RegisterOOBServiceServer(s *grpc.Server, srv OOBServiceServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.OOBService",
		HandlerType: (*OOBServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Start",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &OOBStartRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(OOBServiceServer).Start(ctx, in)
				},
			},
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(OOBServiceServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Poll",
				Handler:       oobPollHandler,
				ServerStreams: true,
			},
		},
	}, srv)
}

func oobPollHandler(srv any, stream grpc.ServerStream) error {
	req := &PollRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	return srv.(OOBServiceServer).Poll(req, &oobPollStream{stream})
}

// ---------------------------------------------------------------------------
// IDOREngine
// ---------------------------------------------------------------------------

// IDOREngine_RunServer is the server-side stream for Run.
type IDOREngine_RunServer interface {
	Send(*Finding) error
	grpc.ServerStream
}

type idorRunStream struct{ grpc.ServerStream }

func (s *idorRunStream) Send(m *Finding) error { return s.ServerStream.SendMsg(m) }

// IDOREngineServer must be implemented by the oi-idor-engine sidecar.
type IDOREngineServer interface {
	Run(*IDORRequest, IDOREngine_RunServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

type UnimplementedIDOREngineServer struct{}

func (UnimplementedIDOREngineServer) Run(_ *IDORRequest, _ IDOREngine_RunServer) error {
	return nil
}
func (UnimplementedIDOREngineServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterIDOREngineServer binds srv to s.
func RegisterIDOREngineServer(s *grpc.Server, srv IDOREngineServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.IDOREngine",
		HandlerType: (*IDOREngineServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(IDOREngineServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Run",
				Handler:       idorRunHandler,
				ServerStreams: true,
			},
		},
	}, srv)
}

func idorRunHandler(srv any, stream grpc.ServerStream) error {
	req := &IDORRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	return srv.(IDOREngineServer).Run(req, &idorRunStream{stream})
}

// ---------------------------------------------------------------------------
// TargetDisc  (new service, port 50059)
// ---------------------------------------------------------------------------

// TargetDisc_DiscoverServer is the server-side stream for Discover.
type TargetDisc_DiscoverServer interface {
	Send(*Asset) error
	grpc.ServerStream
}

type targetDiscStream struct{ grpc.ServerStream }

func (s *targetDiscStream) Send(m *Asset) error { return s.ServerStream.SendMsg(m) }

// TargetDiscServer must be implemented by the oi-target-disc sidecar.
type TargetDiscServer interface {
	Discover(*DiscoverRequest, TargetDisc_DiscoverServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

type UnimplementedTargetDiscServer struct{}

func (UnimplementedTargetDiscServer) Discover(_ *DiscoverRequest, _ TargetDisc_DiscoverServer) error {
	return nil
}
func (UnimplementedTargetDiscServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterTargetDiscServer binds srv to s.
func RegisterTargetDiscServer(s *grpc.Server, srv TargetDiscServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.TargetDisc",
		HandlerType: (*TargetDiscServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(TargetDiscServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Discover",
				Handler:       targetDiscHandler,
				ServerStreams: true,
			},
		},
	}, srv)
}

func targetDiscHandler(srv any, stream grpc.ServerStream) error {
	req := &DiscoverRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	return srv.(TargetDiscServer).Discover(req, &targetDiscStream{stream})
}

// ---------------------------------------------------------------------------
// LiveSurface
// ---------------------------------------------------------------------------

// LiveSurface_DiscoverServer is the server-side stream for Discover.
type LiveSurface_DiscoverServer interface {
	Send(*Asset) error
	grpc.ServerStream
}

type liveSurfaceStream struct{ grpc.ServerStream }

func (s *liveSurfaceStream) Send(m *Asset) error { return s.ServerStream.SendMsg(m) }

// LiveSurfaceServer must be implemented by the oi-live-surface sidecar.
type LiveSurfaceServer interface {
	Discover(*DiscoverRequest, LiveSurface_DiscoverServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

type UnimplementedLiveSurfaceServer struct{}

func (UnimplementedLiveSurfaceServer) Discover(_ *DiscoverRequest, _ LiveSurface_DiscoverServer) error {
	return nil
}
func (UnimplementedLiveSurfaceServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterLiveSurfaceServer binds srv to s.
func RegisterLiveSurfaceServer(s *grpc.Server, srv LiveSurfaceServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.LiveSurface",
		HandlerType: (*LiveSurfaceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(LiveSurfaceServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Discover",
				Handler:       liveSurfaceHandler,
				ServerStreams: true,
			},
		},
	}, srv)
}

func liveSurfaceHandler(srv any, stream grpc.ServerStream) error {
	req := &DiscoverRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	return srv.(LiveSurfaceServer).Discover(req, &liveSurfaceStream{stream})
}

// ---------------------------------------------------------------------------
// PhaseRunner
// ---------------------------------------------------------------------------

// PhaseRunner_RunPhaseServer is the server-side stream for RunPhase.
type PhaseRunner_RunPhaseServer interface {
	Send(*PhaseEvent) error
	grpc.ServerStream
}

type phaseRunStream struct{ grpc.ServerStream }

func (s *phaseRunStream) Send(m *PhaseEvent) error { return s.ServerStream.SendMsg(m) }

// PhaseRunnerServer must be implemented by the oi-phase-runner sidecar.
type PhaseRunnerServer interface {
	RunPhase(*PhaseRequest, PhaseRunner_RunPhaseServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

type UnimplementedPhaseRunnerServer struct{}

func (UnimplementedPhaseRunnerServer) RunPhase(_ *PhaseRequest, _ PhaseRunner_RunPhaseServer) error {
	return nil
}
func (UnimplementedPhaseRunnerServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterPhaseRunnerServer binds srv to s.
func RegisterPhaseRunnerServer(s *grpc.Server, srv PhaseRunnerServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.PhaseRunner",
		HandlerType: (*PhaseRunnerServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(PhaseRunnerServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "RunPhase",
				Handler:       phaseRunHandler,
				ServerStreams: true,
			},
		},
	}, srv)
}

func phaseRunHandler(srv any, stream grpc.ServerStream) error {
	req := &PhaseRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	return srv.(PhaseRunnerServer).RunPhase(req, &phaseRunStream{stream})
}

// ---------------------------------------------------------------------------
// CacheScanner (same Scan signature as SSRFScanner)
// ---------------------------------------------------------------------------

// CacheScanner_ScanServer is the server-side stream for Scan.
type CacheScanner_ScanServer interface {
	Send(*Finding) error
	grpc.ServerStream
}

type cacheScanStream struct{ grpc.ServerStream }

func (s *cacheScanStream) Send(m *Finding) error { return s.ServerStream.SendMsg(m) }

// CacheScannerServer must be implemented by the oi-cache-scanner sidecar.
type CacheScannerServer interface {
	Scan(*ScanRequest, CacheScanner_ScanServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

type UnimplementedCacheScannerServer struct{}

func (UnimplementedCacheScannerServer) Scan(_ *ScanRequest, _ CacheScanner_ScanServer) error {
	return nil
}
func (UnimplementedCacheScannerServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterCacheScannerServer binds srv to s.
func RegisterCacheScannerServer(s *grpc.Server, srv CacheScannerServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.CacheScanner",
		HandlerType: (*CacheScannerServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(CacheScannerServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Scan",
				Handler:       cacheScanHandler,
				ServerStreams: true,
			},
		},
	}, srv)
}

func cacheScanHandler(srv any, stream grpc.ServerStream) error {
	req := &ScanRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	return srv.(CacheScannerServer).Scan(req, &cacheScanStream{stream})
}

// ---------------------------------------------------------------------------
// CredentialSpray
// ---------------------------------------------------------------------------

// CredentialSpray_RunServer is the server-side stream for Run.
type CredentialSpray_RunServer interface {
	Send(*Finding) error
	grpc.ServerStream
}

type credSprayStream struct{ grpc.ServerStream }

func (s *credSprayStream) Send(m *Finding) error { return s.ServerStream.SendMsg(m) }

// CredentialSprayServer must be implemented by the oi-cred-spray sidecar.
type CredentialSprayServer interface {
	Run(*CredentialSprayRequest, CredentialSpray_RunServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

type UnimplementedCredentialSprayServer struct{}

func (UnimplementedCredentialSprayServer) Run(_ *CredentialSprayRequest, _ CredentialSpray_RunServer) error {
	return nil
}
func (UnimplementedCredentialSprayServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterCredentialSprayServer binds srv to s.
func RegisterCredentialSprayServer(s *grpc.Server, srv CredentialSprayServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.CredentialSpray",
		HandlerType: (*CredentialSprayServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(CredentialSprayServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Run",
				Handler:       credSprayHandler,
				ServerStreams: true,
			},
		},
	}, srv)
}

func credSprayHandler(srv any, stream grpc.ServerStream) error {
	req := &CredentialSprayRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	return srv.(CredentialSprayServer).Run(req, &credSprayStream{stream})
}

// ---------------------------------------------------------------------------
// ResultIngestion (bidirectional stream + unary)
// ---------------------------------------------------------------------------

// ResultIngestion_SubmitBatchServer handles the bidirectional SubmitBatch RPC.
type ResultIngestion_SubmitBatchServer interface {
	Send(*NormalizedFinding) error
	Recv() (*RawResult, error)
	grpc.ServerStream
}

type resultBatchStream struct{ grpc.ServerStream }

func (s *resultBatchStream) Send(m *NormalizedFinding) error { return s.ServerStream.SendMsg(m) }
func (s *resultBatchStream) Recv() (*RawResult, error) {
	m := &RawResult{}
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ResultIngestionServer must be implemented by oi-ingest.
type ResultIngestionServer interface {
	Submit(context.Context, *RawResult) (*NormalizedFinding, error)
	SubmitBatch(ResultIngestion_SubmitBatchServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

type UnimplementedResultIngestionServer struct{}

func (UnimplementedResultIngestionServer) Submit(_ context.Context, _ *RawResult) (*NormalizedFinding, error) {
	return &NormalizedFinding{}, nil
}
func (UnimplementedResultIngestionServer) SubmitBatch(_ ResultIngestion_SubmitBatchServer) error {
	return nil
}
func (UnimplementedResultIngestionServer) Health(_ context.Context, _ *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{Status: HealthCheckResponse_SERVING}, nil
}

// RegisterResultIngestionServer binds srv to s.
func RegisterResultIngestionServer(s *grpc.Server, srv ResultIngestionServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "oneinfinity.v1.ResultIngestion",
		HandlerType: (*ResultIngestionServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Submit",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &RawResult{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(ResultIngestionServer).Submit(ctx, in)
				},
			},
			{
				MethodName: "Health",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := &HealthCheckRequest{}
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(ResultIngestionServer).Health(ctx, in)
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:     "SubmitBatch",
				Handler:        resultBatchHandler,
				ServerStreams:  true,
				ClientStreams:  true,
			},
		},
	}, srv)
}

func resultBatchHandler(srv any, stream grpc.ServerStream) error {
	return srv.(ResultIngestionServer).SubmitBatch(&resultBatchStream{stream})
}
