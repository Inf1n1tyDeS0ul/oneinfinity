# oi-sdk/pb — gRPC Service Registration Without protoc

## Wire Format

This package replaces protoc-generated code with a **JSON-over-gRPC** approach.
The `init()` in `pb.go` registers a codec named `"proto"` (so gRPC selects it
as the default) that marshals/unmarshals with `encoding/json`. No protobuf
binary encoding; no file descriptor registration; no generated code.

**Implication**: any gRPC client calling these services must also use a JSON
codec, or the framing will mismatch. See the Python note below.

---

## Quick-start: adding a new sidecar service

```go
package main

import (
    "context"
    "log"

    "github.com/oneinfinity/oi-sdk/pb"
    "github.com/oneinfinity/oi-sdk/sidecar"
)

// 1. Embed the Unimplemented stub so you only override what you need.
type myService struct {
    pb.UnimplementedReconProbeServer
}

// 2. Implement the stream RPC.
func (s *myService) ScanHTTP(req *pb.ScanRequest, stream pb.ReconProbe_ScanHTTPServer) error {
    finding := &pb.Finding{
        Id:       "f-001",
        Url:      req.TargetUrl,
        VulnType: "open-redirect",
        Severity: "medium",
    }
    return stream.Send(finding)
}

// 3. Health is already implemented by UnimplementedReconProbeServer (returns SERVING).
//    Override only if you need custom logic.

func main() {
    cfg := sidecar.LoadConfig("oi-recon-probe")   // reads env + falls back to port 50052
    srv := sidecar.NewServer(cfg)
    pb.RegisterReconProbeServer(srv, &myService{}) // bind your impl
    log.Fatal(sidecar.ListenAndServe(srv, cfg))
}
```

### go.mod for the sidecar

```
module github.com/oneinfinity/oi-recon-probe

go 1.21

require github.com/oneinfinity/oi-sdk v0.0.0
replace github.com/oneinfinity/oi-sdk => ../oi-sdk
```

The `replace` directive is the local-path override; it is superseded by the
`go.work` workspace at `src/go/go.work` when both are present.

---

## Available Register* functions

| Service (proto)       | Register function                     | Server interface              |
|-----------------------|---------------------------------------|-------------------------------|
| CrawlerService        | `RegisterCrawlerServiceServer`        | `CrawlerServiceServer`        |
| ReconProbe            | `RegisterReconProbeServer`            | `ReconProbeServer`            |
| SSRFScanner           | `RegisterSSRFScannerServer`           | `SSRFScannerServer`           |
| OOBService            | `RegisterOOBServiceServer`            | `OOBServiceServer`            |
| IDOREngine            | `RegisterIDOREngineServer`            | `IDOREngineServer`            |
| TargetDisc (new)      | `RegisterTargetDiscServer`            | `TargetDiscServer`            |
| LiveSurface           | `RegisterLiveSurfaceServer`           | `LiveSurfaceServer`           |
| PhaseRunner           | `RegisterPhaseRunnerServer`           | `PhaseRunnerServer`           |
| CacheScanner          | `RegisterCacheScannerServer`          | `CacheScannerServer`          |
| CredentialSpray       | `RegisterCredentialSprayServer`       | `CredentialSprayServer`       |
| ResultIngestion       | `RegisterResultIngestionServer`       | `ResultIngestionServer`       |
| Health (standalone)   | `RegisterHealthServer`                | `HealthServer`                |

Each service has a matching `UnimplementedXxxServer` struct you can embed.

---

## Stable event_id (Gate 1 requirement)

```go
import "github.com/oneinfinity/oi-sdk/events"

id := events.EventID(req.ScanId, req.TargetUrl+"::open-redirect")
// deterministic SHA-256 hex — same inputs always produce the same id
```

---

## Python client JSON codec

To call these Go services from a Python grpcio client, register a JSON codec
before creating the channel:

```python
import grpc
from grpc import experimental

class JsonCodec(grpc.Codec):
    def encode(self, message):
        import json
        return json.dumps(message).encode()
    def decode(self, data, cls):
        import json
        obj = cls()
        for k, v in json.loads(data).items():
            setattr(obj, k, v)
        return obj
    def name(self):
        return "proto"   # must match the codec name registered in Go

# Register once at startup:
experimental.register_codec(JsonCodec())
```

Alternatively, use the `feature-flagged Python shim` pattern: keep the existing
protobuf-encoded Python stubs and only switch to Go sidecars via an env flag.
