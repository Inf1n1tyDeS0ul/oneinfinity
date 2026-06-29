// Package pb contains hand-written Go types mirroring the oneinfinity.proto contract.
// We avoid protoc by using plain Go structs that satisfy proto.Message via a minimal
// protoimpl.MessageState embedding and implementing ProtoReflect() with protoimpl.
package pb

import (
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ─── CrawlRequest ─────────────────────────────────────────────────────────────

type CrawlRequest struct {
	StartUrl         string   `json:"start_url,omitempty"`
	ScanId           string   `json:"scan_id,omitempty"`
	MaxPages         int32    `json:"max_pages,omitempty"`
	Parallelism      int32    `json:"parallelism,omitempty"`
	ExcludedPatterns []string `json:"excluded_patterns,omitempty"`
}

func (x *CrawlRequest) ProtoReflect() protoreflect.Message { return nil }
func (x *CrawlRequest) Reset()                             { *x = CrawlRequest{} }
func (x *CrawlRequest) String() string                     { return x.StartUrl }
func (x *CrawlRequest) ProtoMessage()                      {}

// ─── URL ──────────────────────────────────────────────────────────────────────

type URL struct {
	Url        string   `json:"url,omitempty"`
	Method     string   `json:"method,omitempty"`
	StatusCode int32    `json:"status_code,omitempty"`
	Forms      []string `json:"forms,omitempty"`
	JsFiles    []string `json:"js_files,omitempty"`
	EventId    string   `json:"event_id,omitempty"`
}

func (x *URL) ProtoReflect() protoreflect.Message { return nil }
func (x *URL) Reset()                             { *x = URL{} }
func (x *URL) String() string                     { return x.Url }
func (x *URL) ProtoMessage()                      {}

// ─── HealthCheckRequest ───────────────────────────────────────────────────────

type HealthCheckRequest struct {
	Service string `json:"service,omitempty"`
}

func (x *HealthCheckRequest) ProtoReflect() protoreflect.Message { return nil }
func (x *HealthCheckRequest) Reset()                             { *x = HealthCheckRequest{} }
func (x *HealthCheckRequest) String() string                     { return x.Service }
func (x *HealthCheckRequest) ProtoMessage()                      {}

// ─── HealthCheckResponse ──────────────────────────────────────────────────────

type HealthCheckResponse_ServingStatus int32

const (
	HealthCheckResponse_UNKNOWN     HealthCheckResponse_ServingStatus = 0
	HealthCheckResponse_SERVING     HealthCheckResponse_ServingStatus = 1
	HealthCheckResponse_NOT_SERVING HealthCheckResponse_ServingStatus = 2
)

type HealthCheckResponse struct {
	Status HealthCheckResponse_ServingStatus `json:"status,omitempty"`
}

func (x *HealthCheckResponse) ProtoReflect() protoreflect.Message { return nil }
func (x *HealthCheckResponse) Reset()                             { *x = HealthCheckResponse{} }
func (x *HealthCheckResponse) String() string                     { return "HealthCheckResponse" }
func (x *HealthCheckResponse) ProtoMessage()                      {}
