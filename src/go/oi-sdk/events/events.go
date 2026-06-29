// Package events provides stable event-ID generation and timestamps for
// sidecar Finding messages.
package events

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// EventID returns a hex-encoded SHA-256 digest of scanID concatenated with
// data. The result is deterministic: identical (scanID, data) pairs always
// produce the same ID, enabling deduplication across retries.
func EventID(scanID, data string) string {
	h := sha256.New()
	h.Write([]byte(scanID))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Timestamp returns the current time as Unix nanoseconds, matching the
// int64 discovered_at / received_at fields in the proto messages.
func Timestamp() int64 {
	return time.Now().UnixNano()
}
