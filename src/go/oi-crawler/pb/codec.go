// Package pb — codec registration for the hand-written proto types.
// We use grpc's default codec (protobuf) but since our structs implement
// proto.Message via protoimpl, we need to provide proper marshaling.
// Instead, we register a JSON codec override for the crawler service so
// the wire format is plain JSON — simple, no protoc needed.
package pb

import (
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/encoding"
)

const JSONCodecName = "proto" // override the default codec name

func init() {
	encoding.RegisterCodec(JSONCodec{})
}

// JSONCodec replaces the default protobuf codec with JSON for simplicity.
// This lets our hand-written structs work as gRPC messages without protoc.
type JSONCodec struct{}

func (JSONCodec) Name() string { return JSONCodecName }

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
