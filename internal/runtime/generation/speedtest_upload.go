package generation

import (
	"crypto/rand"
	"io"
	"sync"
)

// Share one immutable MiB across all 10 MB request bodies to limit memory and
// keep random number generation out of the timed transfer.
var speedUploadPayload = sync.OnceValue(func() []byte {
	payload := make([]byte, 1<<20)
	rand.Read(payload)
	return payload
})

func newSpeedUploadBody(payload []byte) io.Reader {
	return io.LimitReader(&speedUploadReader{payload: payload}, speedUploadSize)
}

type speedUploadReader struct {
	payload []byte
	offset  int
}

func (r *speedUploadReader) Read(p []byte) (int, error) {
	n := copy(p, r.payload[r.offset:])
	r.offset = (r.offset + n) % len(r.payload)
	return n, nil
}
