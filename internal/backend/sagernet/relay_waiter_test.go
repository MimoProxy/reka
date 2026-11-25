package sagernet

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func TestCopyHalfWaiterReturnsBufferBetweenReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		input := make(chan string, 1)
		stopInput := sync.OnceFunc(func() { close(input) })
		defer stopInput()
		writeReady := make(chan struct{}, 1)
		defer close(writeReady)
		source := &relayWaitTestConn{input: input}
		destination := &relayHalfCloseTestConn{writeReady: writeReady}
		var moved rateCounter
		var upload, process atomic.Uint64
		finished := make(chan error, 1)
		drained := false
		go copyHalf(source, destination, &moved, func(err error) { finished <- err }, func() { drained = true }, &upload, &process)

		synctest.Wait()
		if source.waits != 1 || source.outstanding() != 0 {
			t.Fatalf("before input, waits = %d, outstanding buffers = %d, want 1 and 0", source.waits, source.outstanding())
		}

		const payload = "stream payload"
		input <- payload
		synctest.Wait()
		if source.outstanding() != 1 || source.buffers[0].Cap() != buf.BufferSize {
			t.Fatalf("while the write is blocked, outstanding buffers = %d, want one standard-sized buffer", source.outstanding())
		}
		checkRelayTraffic(t, &moved, 0, &upload, &process)

		writeReady <- struct{}{}
		synctest.Wait()
		if source.waits != 2 || source.outstanding() != 0 {
			t.Fatalf("after forwarding, waits = %d, outstanding buffers = %d, want 2 and 0", source.waits, source.outstanding())
		}
		if got := destination.output.String(); got != payload {
			t.Fatalf("forwarded %q, want %q", got, payload)
		}
		checkRelayTraffic(t, &moved, len(payload), &upload, &process)

		stopInput()
		synctest.Wait()
		select {
		case err := <-finished:
			if err != nil {
				t.Fatalf("finish after EOF: %v", err)
			}
		default:
			t.Fatal("copy did not finish after EOF")
		}
		if !destination.halfClosed || destination.closed || drained || source.closed {
			t.Fatal("EOF did not half-close the destination while leaving both connections open")
		}
		if count := source.outstanding(); count != 0 {
			t.Fatalf("after EOF, outstanding buffers = %d, want 0", count)
		}
	})
}

func TestCopyOwnedPreservesWaiterBufferOnWriteFailure(t *testing.T) {
	const payload = "queued stream data"
	writeFailure := errors.New("write failed")
	tests := []struct {
		name     string
		written  int
		writeErr error
		wantErr  error
	}{
		{name: "write error", written: 2, writeErr: writeFailure, wantErr: writeFailure},
		{name: "error after full write", written: len(payload), writeErr: writeFailure, wantErr: writeFailure},
		{name: "short write", written: 2, wantErr: io.ErrShortWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &relayWaitTestConn{input: relayWaitTestInput(payload)}
			var retained []byte
			destination := relayTestWriter(func(p []byte) (int, error) {
				retained = p
				return tt.written, tt.writeErr
			})
			var moved rateCounter
			var upload, process atomic.Uint64
			if err := copyOwned(destination, source, &moved, &upload, &process); err != tt.wantErr {
				t.Fatalf("copy returned %v, want %v", err, tt.wantErr)
			}
			if source.outstanding() != 1 {
				t.Fatalf("outstanding buffers after failed write = %d, want 1", source.outstanding())
			}
			if got := string(retained); got != payload {
				t.Fatalf("writer retained %q, want %q", got, payload)
			}
			checkRelayTraffic(t, &moved, tt.written, &upload, &process)
		})
	}
}

func TestCopyOwnedPrivateBufferFallback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		needCopy bool
	}{
		{name: "unsupported source"},
		{name: "waiter needs copy", needCopy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const payload = "data returned with EOF"
			calls := 0
			read := relayTestReader(func(p []byte) (int, error) {
				calls++
				if len(p) != buf.BufferSize {
					t.Errorf("private buffer size = %d, want %d", len(p), buf.BufferSize)
				}
				return copy(p, payload), io.EOF
			})
			source := io.Reader(read)
			var waiter *relayWaitTestConn
			if tc.needCopy {
				waiter = &relayWaitTestConn{input: relayWaitTestInput(), fallback: read, needCopy: true}
				source = waiter
			}
			var destination strings.Builder
			var moved rateCounter
			var total atomic.Uint64
			if err := copyOwned(&destination, source, &moved, &total); err != nil {
				t.Fatalf("copy: %v", err)
			}
			if calls != 1 || destination.String() != payload {
				t.Fatalf("reads = %d, forwarded %q, want one read forwarding %q", calls, destination.String(), payload)
			}
			if waiter != nil && (!waiter.initialized || waiter.waits != 0) {
				t.Fatalf("waiter initialized = %v, waits = %d, want true and 0", waiter.initialized, waiter.waits)
			}
			checkRelayTraffic(t, &moved, len(payload), &total)
		})
	}
}

func TestCopyOwnedUpgradesAfterSniffReplay(t *testing.T) {
	prefix := strings.Repeat("prefix ", buf.BufferSize/7+1)
	upstream := &relayWaitTestConn{input: relayWaitTestInput("first", "second")}
	source := &sniffReplayConn{Conn: upstream, prefix: []byte(prefix)}
	var destination strings.Builder
	var moved rateCounter
	var total atomic.Uint64
	if err := copyOwned(&destination, source, &moved, &total); err != nil {
		t.Fatalf("copy: %v", err)
	}
	want := prefix + "firstsecond"
	if got := destination.String(); got != want {
		t.Fatalf("forwarded %d bytes, want the %d-byte prefix followed by both payloads in order", len(got), len(prefix))
	}
	if upstream.reads != 0 || upstream.waits != 3 || upstream.outstanding() != 0 {
		t.Fatalf("upstream reads = %d, waits = %d, outstanding buffers = %d, want 0, 3 and 0", upstream.reads, upstream.waits, upstream.outstanding())
	}
	checkRelayTraffic(t, &moved, len(want), &total)
}

func TestCopyOwnedPropagatesWaiterReadError(t *testing.T) {
	const payload = "data before deadline"
	source := &relayWaitTestConn{input: relayWaitTestInput(payload), endErr: os.ErrDeadlineExceeded}
	var destination strings.Builder
	var moved rateCounter
	if err := copyOwned(&destination, source, &moved); err != os.ErrDeadlineExceeded {
		t.Fatalf("copy returned %v, want deadline exceeded", err)
	}
	if got := destination.String(); got != payload {
		t.Fatalf("forwarded %q, want %q", got, payload)
	}
	if count := source.outstanding(); count != 0 {
		t.Fatalf("outstanding buffers after read error = %d, want 0", count)
	}
	checkRelayTraffic(t, &moved, len(payload))
}

type relayWaitTestConn struct {
	net.Conn
	input       <-chan string
	fallback    io.Reader
	endErr      error
	needCopy    bool
	initialized bool
	options     N.ReadWaitOptions
	waits       int
	reads       int
	buffers     []*buf.Buffer
	closed      bool
}

func (c *relayWaitTestConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.initialized = true
	c.options = options
	return c.needCopy
}

func (c *relayWaitTestConn) WaitReadBuffer() (*buf.Buffer, error) {
	c.waits++
	payload, ok := <-c.input
	if !ok {
		if c.endErr != nil {
			return nil, c.endErr
		}
		return nil, io.EOF
	}
	buffer := c.options.NewBuffer()
	_, _ = buffer.WriteString(payload)
	c.options.PostReturn(buffer)
	c.buffers = append(c.buffers, buffer)
	return buffer, nil
}

func (c *relayWaitTestConn) Read(p []byte) (int, error) {
	c.reads++
	if c.fallback != nil {
		return c.fallback.Read(p)
	}
	return 0, io.ErrUnexpectedEOF
}

func (c *relayWaitTestConn) Close() error {
	c.closed = true
	return nil
}

func (c *relayWaitTestConn) outstanding() int {
	count := 0
	for _, buffer := range c.buffers {
		// Release clears a managed buffer after returning its storage to the pool.
		if buffer.RawCap() > 0 {
			count++
		}
	}
	return count
}

func relayWaitTestInput(payloads ...string) <-chan string {
	input := make(chan string, len(payloads))
	for _, payload := range payloads {
		input <- payload
	}
	close(input)
	return input
}

type relayHalfCloseTestConn struct {
	net.Conn
	writeReady <-chan struct{}
	output     strings.Builder
	halfClosed bool
	closed     bool
}

func (c *relayHalfCloseTestConn) Write(p []byte) (int, error) {
	<-c.writeReady
	return c.output.Write(p)
}

func (c *relayHalfCloseTestConn) CloseWrite() error {
	c.halfClosed = true
	return nil
}

func (c *relayHalfCloseTestConn) Close() error {
	c.closed = true
	return nil
}

type relayTestReader func([]byte) (int, error)

func (r relayTestReader) Read(p []byte) (int, error) { return r(p) }

type relayTestWriter func([]byte) (int, error)

func (w relayTestWriter) Write(p []byte) (int, error) { return w(p) }

func checkRelayTraffic(t *testing.T, moved *rateCounter, expected int, totals ...*atomic.Uint64) {
	t.Helper()
	if got := moved.Load(); got != int64(expected) {
		t.Errorf("moved = %d, want %d", got, expected)
	}
	for i, total := range totals {
		if got := total.Load(); got != uint64(expected) {
			t.Errorf("traffic total %d = %d, want %d", i, got, expected)
		}
	}
}
