// Package pb provides hand-written Go types for all oneinfinity.v1 proto messages
// and service registration helpers. No protoc required — gRPC is wired with a
// JSON codec so structs are plain Go types with json tags.
//
// Wire note: the JSON codec is registered globally in init(). All sidecars that
// import this package will automatically use JSON on the wire. Python clients must
// enable the matching JSON codec (see pb/README.md).
package pb

import (
	"encoding/json"

	"google.golang.org/grpc/encoding"
)

func init() {
	// Replace the default proto codec with JSON so we don't need protoc-generated
	// file descriptor registration. All services in this process share the codec.
	encoding.RegisterCodec(JSONCodec{})
}

// JSONCodec satisfies grpc/encoding.Codec.
type JSONCodec struct{}

func (JSONCodec) Name() string { return "proto" } // named "proto" to be the default

func (JSONCodec) Marshal(v any) ([]byte, error)   { return json.Marshal(v) }
func (JSONCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// ---------------------------------------------------------------------------
// Common messages — field names and numbers match oneinfinity.proto exactly.
// ---------------------------------------------------------------------------

type Finding struct {
	Id          string            `json:"id,omitempty"`
	Url         string            `json:"url,omitempty"`
	VulnType    string            `json:"vuln_type,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	SourceTool  string            `json:"source_tool,omitempty"`
	DiscoveredAt int64            `json:"discovered_at,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Confidence  float32           `json:"confidence,omitempty"`
	ScanId      string            `json:"scan_id,omitempty"`
}

type RawResult struct {
	ToolName   string `json:"tool_name,omitempty"`
	RawOutput  string `json:"raw_output,omitempty"`
	ScanId     string `json:"scan_id,omitempty"`
	TargetUrl  string `json:"target_url,omitempty"`
	CapturedAt int64  `json:"captured_at,omitempty"`
}

type NormalizedFinding struct {
	Finding      *Finding `json:"finding,omitempty"`
	Deduplicated bool     `json:"deduplicated,omitempty"`
	DedupKey     string   `json:"dedup_key,omitempty"`
}

type ScanRequest struct {
	TargetUrl      string            `json:"target_url,omitempty"`
	ScanId         string            `json:"scan_id,omitempty"`
	Options        map[string]string `json:"options,omitempty"`
	Headers        []string          `json:"headers,omitempty"`
	TimeoutSeconds int32             `json:"timeout_seconds,omitempty"`
}

type PhaseRequest struct {
	PhaseName      string            `json:"phase_name,omitempty"`
	ScanId         string            `json:"scan_id,omitempty"`
	TargetUrl      string            `json:"target_url,omitempty"`
	Config         map[string]string `json:"config,omitempty"`
	EnabledModules []string          `json:"enabled_modules,omitempty"`
}

// PhaseEvent_EventType mirrors the proto enum.
type PhaseEvent_EventType int32

const (
	PhaseEvent_EVENT_TYPE_UNSPECIFIED PhaseEvent_EventType = 0
	PhaseEvent_PHASE_STARTED          PhaseEvent_EventType = 1
	PhaseEvent_PHASE_PROGRESS         PhaseEvent_EventType = 2
	PhaseEvent_PHASE_COMPLETED        PhaseEvent_EventType = 3
	PhaseEvent_PHASE_FAILED           PhaseEvent_EventType = 4
	PhaseEvent_FINDING_DISCOVERED     PhaseEvent_EventType = 5
)

type PhaseEvent struct {
	EventType   PhaseEvent_EventType `json:"event_type,omitempty"`
	ScanId      string               `json:"scan_id,omitempty"`
	PhaseName   string               `json:"phase_name,omitempty"`
	Finding     *Finding             `json:"finding,omitempty"`
	ProgressPct int32                `json:"progress_pct,omitempty"`
	Message     string               `json:"message,omitempty"`
	Timestamp   int64                `json:"timestamp,omitempty"`
}

type OOBStartRequest struct {
	ScanId     string `json:"scan_id,omitempty"`
	TargetHint string `json:"target_hint,omitempty"`
}

type OOBDomain struct {
	Domain string `json:"domain,omitempty"`
	ScanId string `json:"scan_id,omitempty"`
}

type PollRequest struct {
	ScanId         string `json:"scan_id,omitempty"`
	TimeoutSeconds int32  `json:"timeout_seconds,omitempty"`
}

type Interaction struct {
	Protocol   string `json:"protocol,omitempty"`
	SourceIp   string `json:"source_ip,omitempty"`
	Payload    string `json:"payload,omitempty"`
	ReceivedAt int64  `json:"received_at,omitempty"`
	ScanId     string `json:"scan_id,omitempty"`
}

type IDORRequest struct {
	TargetUrl        string   `json:"target_url,omitempty"`
	ScanId           string   `json:"scan_id,omitempty"`
	SessionTokens    []string `json:"session_tokens,omitempty"`
	EndpointPatterns []string `json:"endpoint_patterns,omitempty"`
	Parallelism      int32    `json:"parallelism,omitempty"`
}

type Asset struct {
	Url       string            `json:"url,omitempty"`
	AssetType string            `json:"asset_type,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type DiscoverRequest struct {
	TargetUrl   string `json:"target_url,omitempty"`
	ScanId      string `json:"scan_id,omitempty"`
	Depth       int32  `json:"depth,omitempty"`
	Parallelism int32  `json:"parallelism,omitempty"`
}

type CrawlRequest struct {
	StartUrl         string   `json:"start_url,omitempty"`
	ScanId           string   `json:"scan_id,omitempty"`
	MaxPages         int32    `json:"max_pages,omitempty"`
	Parallelism      int32    `json:"parallelism,omitempty"`
	ExcludedPatterns []string `json:"excluded_patterns,omitempty"`
}

type URL struct {
	Url        string   `json:"url,omitempty"`
	Method     string   `json:"method,omitempty"`
	StatusCode int32    `json:"status_code,omitempty"`
	Forms      []string `json:"forms,omitempty"`
	JsFiles    []string `json:"js_files,omitempty"`
}

type CredentialSprayRequest struct {
	TargetUrl     string   `json:"target_url,omitempty"`
	ScanId        string   `json:"scan_id,omitempty"`
	LoginEndpoint string   `json:"login_endpoint,omitempty"`
	Usernames     []string `json:"usernames,omitempty"`
	Passwords     []string `json:"passwords,omitempty"`
	DelayMs       int32    `json:"delay_ms,omitempty"`
}

// HealthCheckRequest / HealthCheckResponse — used by all sidecars.

type HealthCheckRequest struct {
	Service string `json:"service,omitempty"`
}

// HealthCheckResponse_ServingStatus mirrors the proto enum.
type HealthCheckResponse_ServingStatus int32

const (
	HealthCheckResponse_UNKNOWN     HealthCheckResponse_ServingStatus = 0
	HealthCheckResponse_SERVING     HealthCheckResponse_ServingStatus = 1
	HealthCheckResponse_NOT_SERVING HealthCheckResponse_ServingStatus = 2
)

type HealthCheckResponse struct {
	Status HealthCheckResponse_ServingStatus `json:"status,omitempty"`
}
