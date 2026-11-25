package sagernet

import (
	"bytes"
	"io"
	"sync/atomic"
)

var mitmBufferBudget = mitmBodyBudget{limit: mitmBodyBufferBytes}

type mitmBodyBudget struct {
	limit int64
	used  atomic.Int64
}

func (b *mitmBodyBudget) reserve(size int64) bool {
	for used := b.used.Load(); size <= b.limit-used; used = b.used.Load() {
		if b.used.CompareAndSwap(used, used+size) {
			return true
		}
	}
	return false
}

func (b *mitmBodyBudget) buffer(body io.ReadCloser, length, limit int64) (mitmBufferedBody, error) {
	buffer := mitmBufferedBody{reader: body}
	if length > limit {
		buffer.truncated = true
		return buffer, nil
	}
	// Read one byte beyond the limit so an exactly sized body still reaches
	// EOF. Reserve capacity as the buffer grows, so a small body without a
	// declared length does not hold the whole limit.
	size := limit + 1
	initial := min(size, 512)
	if length >= 0 {
		size = length + 1
		initial = size
	}
	if !b.reserve(initial) {
		buffer.truncated = true
		return buffer, nil
	}
	held := initial
	data, full, err := readMITMBody(body, make([]byte, 0, initial), int(size), func(grow int) bool {
		if !b.reserve(int64(grow)) {
			return false
		}
		held += int64(grow)
		return true
	})
	if err != nil {
		b.used.Add(-held)
		return buffer, err
	}
	buffer.release = func() { b.used.Add(-held) }
	if !full && int64(len(data)) < size {
		buffer.data = data
	} else {
		// The body is larger than the limit, or the budget ran out first.
		buffer.truncated = true
		buffer.reader = prefixedMITMBody{Reader: io.MultiReader(bytes.NewReader(data), body), Closer: body}
	}
	return buffer, nil
}

// readMITMBody reads up to size bytes. It returns full when the shared budget
// could not cover more capacity before EOF.
func readMITMBody(body io.Reader, data []byte, size int, grow func(int) bool) ([]byte, bool, error) {
	for len(data) < size {
		if len(data) == cap(data) {
			// Keep the capacity within the reservation.
			capacity := min(size, cap(data)*2)
			if !grow(capacity - cap(data)) {
				return data, true, nil
			}
			next := make([]byte, len(data), capacity)
			copy(next, data)
			data = next
		}
		n, err := body.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, err
		}
	}
	return data, false, nil
}

type prefixedMITMBody struct {
	io.Reader
	io.Closer
}
