// Control API protocol: messages are JSON, one per
// frame; a frame is a 4-byte big-endian length followed by that many
// bytes. Requests and responses carry an ID; events are pushed on the same
// connection. The same messages are used over a Unix domain socket, a
// Windows named pipe, and the Android library binding.
//
// A session starts with Hello, which negotiates the API version.

package api

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// APIVersion is the newest API version this build speaks.
const APIVersion = 1

// MaxFrame bounds one message.
const MaxFrame = 16 << 20

// Request is a client call.
type Request struct {
	ProfileID    string          `json:"profile_id,omitempty"`
	ProfileEpoch uint64          `json:"profile_epoch,omitempty"`
	ID           uint64          `json:"id"`
	Method       string          `json:"method"`
	Params       json.RawMessage `json:"params,omitempty"`
}

// Response answers the request with the same ID.
type Response struct {
	ID     uint64 `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  *Error `json:"error,omitempty"`
}

// Message is any frame a client receives: a response (ID set) or an event.
type Message struct {
	ID     uint64          `json:"id,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
	Event  *Event          `json:"event,omitempty"`
}

// ErrFrameTooLarge is returned for a frame over MaxFrame.
var ErrFrameTooLarge = errors.New("api: frame too large")

// WriteFrame writes one length-prefixed frame.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload)))
	copy(buf[4:], payload)
	n, err := w.Write(buf)
	if err == nil && n != len(buf) {
		return io.ErrShortWrite
	}
	return err
}

// ReadFrame reads one length-prefixed frame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Error codes of the control layer (service codes are reused otherwise).
const (
	CodeHelloRequired = "hello_required"
	CodeVersion       = "unsupported_version"
	CodeUnknownMethod = "unknown_method"
	CodeInternal      = "internal"
	CodeDenied        = "denied"
)

// HelloParams opens a session.
type HelloParams struct {
	// Versions the client speaks.
	Versions []int  `json:"versions"`
	Client   string `json:"client,omitempty"`
}

// HelloResult is the negotiated session.
type HelloResult struct {
	Version        int    `json:"version"`
	Server         string `json:"server"`
	SchemaVersions []int  `json:"schema_versions"`
	Epoch          string `json:"epoch"`
}
