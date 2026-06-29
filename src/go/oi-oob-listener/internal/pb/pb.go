// Package pb — JSON codec + hand-written proto-compatible types for oi-oob-listener.
// Follows the same pattern as oi-crawler/pb: JSON codec overrides proto codec name
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

// JSONCodec overrides the default "proto" codec with JSON encoding.
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

// ─── OOBStartRequest ──────────────────────────────────────────────────────────

type OOBStartRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ScanId     string `protobuf:"bytes,1,opt,name=scan_id,json=scanId,proto3" json:"scan_id,omitempty"`
	TargetHint string `protobuf:"bytes,2,opt,name=target_hint,json=targetHint,proto3" json:"target_hint,omitempty"`
}

func (x *OOBStartRequest) Reset()        { *x = OOBStartRequest{} }
func (x *OOBStartRequest) String() string { return x.ScanId }
func (x *OOBStartRequest) ProtoMessage()  {}
func (x *OOBStartRequest) ProtoReflect() protoreflect.Message { return nil }

// ─── OOBDomain ────────────────────────────────────────────────────────────────

type OOBDomain struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Domain string `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	ScanId string `protobuf:"bytes,2,opt,name=scan_id,json=scanId,proto3" json:"scan_id,omitempty"`
}

func (x *OOBDomain) Reset()        { *x = OOBDomain{} }
func (x *OOBDomain) String() string { return x.Domain }
func (x *OOBDomain) ProtoMessage()  {}
func (x *OOBDomain) ProtoReflect() protoreflect.Message { return nil }

// ─── PollRequest ──────────────────────────────────────────────────────────────

type PollRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ScanId         string `protobuf:"bytes,1,opt,name=scan_id,json=scanId,proto3" json:"scan_id,omitempty"`
	TimeoutSeconds int32  `protobuf:"varint,2,opt,name=timeout_seconds,json=timeoutSeconds,proto3" json:"timeout_seconds,omitempty"`
}

func (x *PollRequest) Reset()        { *x = PollRequest{} }
func (x *PollRequest) String() string { return x.ScanId }
func (x *PollRequest) ProtoMessage()  {}
func (x *PollRequest) ProtoReflect() protoreflect.Message { return nil }

// ─── Interaction ──────────────────────────────────────────────────────────────

type Interaction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Protocol   string `protobuf:"bytes,1,opt,name=protocol,proto3" json:"protocol,omitempty"`
	SourceIp   string `protobuf:"bytes,2,opt,name=source_ip,json=sourceIp,proto3" json:"source_ip,omitempty"`
	Payload    string `protobuf:"bytes,3,opt,name=payload,proto3" json:"payload,omitempty"`
	ReceivedAt int64  `protobuf:"varint,4,opt,name=received_at,json=receivedAt,proto3" json:"received_at,omitempty"`
	ScanId     string `protobuf:"bytes,5,opt,name=scan_id,json=scanId,proto3" json:"scan_id,omitempty"`
}

func (x *Interaction) Reset()        { *x = Interaction{} }
func (x *Interaction) String() string { return x.Protocol }
func (x *Interaction) ProtoMessage()  {}
func (x *Interaction) ProtoReflect() protoreflect.Message { return nil }

// ─── HealthCheckRequest / HealthCheckResponse ─────────────────────────────────

type HealthCheckRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Service string `protobuf:"bytes,1,opt,name=service,proto3" json:"service,omitempty"`
}

func (x *HealthCheckRequest) Reset()        { *x = HealthCheckRequest{} }
func (x *HealthCheckRequest) String() string { return x.Service }
func (x *HealthCheckRequest) ProtoMessage()  {}
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

func (x *HealthCheckResponse) Reset()        { *x = HealthCheckResponse{} }
func (x *HealthCheckResponse) String() string { return "HealthCheckResponse" }
func (x *HealthCheckResponse) ProtoMessage()  {}
func (x *HealthCheckResponse) ProtoReflect() protoreflect.Message { return nil }

// ─── Server interface ─────────────────────────────────────────────────────────

// OOBServiceServer is the server-side interface for OOBService.
type OOBServiceServer interface {
	Start(context.Context, *OOBStartRequest) (*OOBDomain, error)
	Poll(*PollRequest, OOBService_PollServer) error
	Health(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
}

// OOBService_PollServer is the server-streaming interface for Poll.
type OOBService_PollServer interface {
	Send(*Interaction) error
	grpc.ServerStream
}

type oobServicePollServer struct{ grpc.ServerStream }

func (x *oobServicePollServer) Send(m *Interaction) error {
	return x.ServerStream.SendMsg(m)
}

// ─── Service descriptor + registration ───────────────────────────────────────

func RegisterOOBServiceServer(s *grpc.Server, srv OOBServiceServer) {
	s.RegisterService(&_OOBService_serviceDesc, srv)
}

var _OOBService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "oneinfinity.v1.OOBService",
	HandlerType: (*OOBServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Start",
			Handler:    _OOBService_Start_Handler,
		},
		{
			MethodName: "Health",
			Handler:    _OOBService_Health_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Poll",
			Handler:       _OOBService_Poll_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "oneinfinity.proto",
}

func _OOBService_Start_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(OOBStartRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OOBServiceServer).Start(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/oneinfinity.v1.OOBService/Start"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OOBServiceServer).Start(ctx, req.(*OOBStartRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OOBService_Health_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HealthCheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OOBServiceServer).Health(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/oneinfinity.v1.OOBService/Health"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OOBServiceServer).Health(ctx, req.(*HealthCheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OOBService_Poll_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(PollRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(OOBServiceServer).Poll(m, &oobServicePollServer{stream})
}
