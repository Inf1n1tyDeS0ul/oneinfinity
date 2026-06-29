// Package pb — JSON codec + hand-written proto-compatible types for oi-ssrf.
// Mirrors oi-crawler/pb pattern: JSON codec overrides the default "proto" codec
// so plain Go structs work as gRPC messages without protoc.
package pb

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/runtime/protoimpl"
)

func init() {
	encoding.RegisterCodec(JSONCodec{})
}

// JSONCodec overrides the default "proto" codec name so gRPC uses JSON on the wire.
type JSONCodec struct{}

func (JSONCodec) Name() string { return "proto" }

func (JSONCodec) Marshal(v interface{}) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json marshal: %w", err)
	}
	return b, nil
}

func (JSONCodec) Unmarshal(data []byte, v interface{}) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("json unmarshal: %w", err)
	}
	return nil
}

// ─── Finding ──────────────────────────────────────────────────────────────────

type Finding struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id           string            `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Url          string            `protobuf:"bytes,2,opt,name=url,proto3" json:"url,omitempty"`
	VulnType     string            `protobuf:"bytes,3,opt,name=vuln_type,json=vulnType,proto3" json:"vuln_type,omitempty"`
	Severity     string            `protobuf:"bytes,4,opt,name=severity,proto3" json:"severity,omitempty"`
	Evidence     string            `protobuf:"bytes,5,opt,name=evidence,proto3" json:"evidence,omitempty"`
	SourceTool   string            `protobuf:"bytes,6,opt,name=source_tool,json=sourceTool,proto3" json:"source_tool,omitempty"`
	DiscoveredAt int64             `protobuf:"varint,7,opt,name=discovered_at,json=discoveredAt,proto3" json:"discovered_at,omitempty"`
	Metadata     map[string]string `protobuf:"bytes,8,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Confidence   float32           `protobuf:"fixed32,9,opt,name=confidence,proto3" json:"confidence,omitempty"`
	ScanId       string            `protobuf:"bytes,10,opt,name=scan_id,json=scanId,proto3" json:"scan_id,omitempty"`
}

func (x *Finding) Reset()                        { *x = Finding{} }
func (x *Finding) String() string                { return x.Id }
func (x *Finding) ProtoMessage()                 {}
func (x *Finding) ProtoReflect() protoreflect.Message { return nil }

// ─── ScanRequest ──────────────────────────────────────────────────────────────

type ScanRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TargetUrl      string            `protobuf:"bytes,1,opt,name=target_url,json=targetUrl,proto3" json:"target_url,omitempty"`
	ScanId         string            `protobuf:"bytes,2,opt,name=scan_id,json=scanId,proto3" json:"scan_id,omitempty"`
	Options        map[string]string `protobuf:"bytes,3,rep,name=options,proto3" json:"options,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Headers        []string          `protobuf:"bytes,4,rep,name=headers,proto3" json:"headers,omitempty"`
	TimeoutSeconds int32             `protobuf:"varint,5,opt,name=timeout_seconds,json=timeoutSeconds,proto3" json:"timeout_seconds,omitempty"`
}

func (x *ScanRequest) Reset()                        { *x = ScanRequest{} }
func (x *ScanRequest) String() string                { return x.TargetUrl }
func (x *ScanRequest) ProtoMessage()                 {}
func (x *ScanRequest) ProtoReflect() protoreflect.Message { return nil }

// ─── HealthCheckRequest / HealthCheckResponse ─────────────────────────────────

type HealthCheckRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Service string `protobuf:"bytes,1,opt,name=service,proto3" json:"service,omitempty"`
}

func (x *HealthCheckRequest) Reset()                        { *x = HealthCheckRequest{} }
func (x *HealthCheckRequest) String() string                { return x.Service }
func (x *HealthCheckRequest) ProtoMessage()                 {}
func (x *HealthCheckRequest) ProtoReflect() protoreflect.Message { return nil }

type ServingStatus int32

const (
	ServingStatus_UNKNOWN     ServingStatus = 0
	ServingStatus_SERVING     ServingStatus = 1
	ServingStatus_NOT_SERVING ServingStatus = 2
)

type HealthCheckResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status ServingStatus `protobuf:"varint,1,opt,name=status,proto3,enum=oneinfinity.v1.HealthCheckResponse_ServingStatus" json:"status,omitempty"`
}

func (x *HealthCheckResponse) Reset()                        { *x = HealthCheckResponse{} }
func (x *HealthCheckResponse) String() string                { return "HealthCheckResponse" }
func (x *HealthCheckResponse) ProtoMessage()                 {}
func (x *HealthCheckResponse) ProtoReflect() protoreflect.Message { return nil }

// ─── Server interface ─────────────────────────────────────────────────────────

// SSRFScannerServer is the server-side interface for SSRFScanner service.
type SSRFScannerServer interface {
	Scan(*ScanRequest, SSRFScanner_ScanServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

// SSRFScanner_ScanServer is the server-streaming interface for Scan.
type SSRFScanner_ScanServer interface {
	Send(*Finding) error
	grpc.ServerStream
}

type ssrfScannerScanServer struct{ grpc.ServerStream }

func (x *ssrfScannerScanServer) Send(m *Finding) error {
	return x.ServerStream.SendMsg(m)
}

// ─── Service descriptor + registration ───────────────────────────────────────

func RegisterSSRFScannerServer(s *grpc.Server, srv SSRFScannerServer) {
	s.RegisterService(&_SSRFScanner_serviceDesc, srv)
}

var _SSRFScanner_serviceDesc = grpc.ServiceDesc{
	ServiceName: "oneinfinity.v1.SSRFScanner",
	HandlerType: (*SSRFScannerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Health",
			Handler:    _SSRFScanner_Health_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Scan",
			Handler:       _SSRFScanner_Scan_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "oneinfinity.proto",
}

func _SSRFScanner_Health_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HealthCheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SSRFScannerServer).Health(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/oneinfinity.v1.SSRFScanner/Health"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SSRFScannerServer).Health(ctx, req.(*HealthCheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SSRFScanner_Scan_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ScanRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(SSRFScannerServer).Scan(m, &ssrfScannerScanServer{stream})
}
