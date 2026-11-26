package sagernet

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/pipe"
)

// x/crypto's forwarding channels have no deadlines. Routed DNS and DoT
// require them. Keep at most one in-flight operation and one owned buffer
// per direction. A timed-out read can be collected by a later Read. A
// timed-out write's accepted prefix stays ordered before the next Write.
type sshStream struct {
	net.Conn
	read, write sshStreamIO
	unread      []byte
	readErr     error
	closed      chan struct{}
	closeOnce   sync.Once
	closeErr    error
	release     func()
}

type sshIOResult struct {
	n   int
	err error
}

type sshStreamIO struct {
	mu       sync.Mutex
	deadline pipe.Deadline
	buffer   []byte
	result   chan sshIOResult
	pending  bool
}

func newSSHStream(conn net.Conn, release func()) *sshStream {
	direction := func() sshStreamIO {
		return sshStreamIO{deadline: pipe.MakeDeadline(), result: make(chan sshIOResult, 1)}
	}
	return &sshStream{Conn: conn, read: direction(), write: direction(), closed: make(chan struct{}), release: release}
}

func (op *sshStreamIO) resize(size int) []byte {
	// The SSH channel's default packet size bounds the buffered data even
	// if the application reads or writes several megabytes at once.
	size = min(size, 32*1024)
	if cap(op.buffer) < size {
		op.buffer = make([]byte, size)
	}
	op.buffer = op.buffer[:size]
	return op.buffer
}

func (op *sshStreamIO) start(f func([]byte) (int, error)) {
	op.pending = true
	go func(p []byte) {
		n, err := f(p)
		// A late result can always be delivered, even if the application
		// never touches this stream again after a deadline or disconnect.
		op.result <- sshIOResult{n, err}
	}(op.buffer)
}

func (op *sshStreamIO) check(closed <-chan struct{}) error {
	select {
	case <-closed:
		return net.ErrClosed
	case <-op.deadline.Wait():
		return os.ErrDeadlineExceeded
	default:
		return nil
	}
}

func (op *sshStreamIO) wait(closed <-chan struct{}) (int, error) {
	select {
	case result := <-op.result:
		op.pending = false
		return result.n, result.err
	case <-closed:
		return 0, net.ErrClosed
	case <-op.deadline.Wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *sshStream) Read(p []byte) (int, error) {
	op := &c.read
	op.mu.Lock()
	defer op.mu.Unlock()
	if err := op.check(c.closed); err != nil || len(p) == 0 {
		return 0, err
	}
	if len(c.unread) == 0 && c.readErr == nil {
		if !op.pending {
			op.resize(len(p))
			op.start(c.Conn.Read)
		}
		n, err := op.wait(c.closed)
		if op.pending {
			return 0, err
		}
		c.unread, c.readErr = op.buffer[:n], err
	}
	n := copy(p, c.unread)
	c.unread = c.unread[n:]
	if len(c.unread) == 0 {
		return n, c.readErr
	}
	return n, nil
}

func (c *sshStream) Write(p []byte) (int, error) {
	op := &c.write
	op.mu.Lock()
	defer op.mu.Unlock()
	if err := op.check(c.closed); err != nil {
		return 0, err
	}
	if op.pending {
		if _, err := op.wait(c.closed); err != nil {
			return 0, err
		}
	}
	written := 0
	for written < len(p) {
		if err := op.check(c.closed); err != nil {
			return written, err
		}
		chunk := op.resize(len(p) - written)
		copy(chunk, p[written:])
		op.start(c.Conn.Write)
		n, err := op.wait(c.closed)
		if op.pending {
			// This chunk is now in our send buffer. The caller can reuse p
			// immediately and resume at the returned offset after timeout.
			return written + len(chunk), err
		}
		written += n
		if err != nil {
			return written, err
		}
		if n != len(chunk) {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func (c *sshStream) CloseWrite() error {
	op := &c.write
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.pending {
		if _, err := op.wait(c.closed); err != nil {
			return err
		}
	}
	// x/crypto's direct-tcpip connection embeds ssh.Channel. Serialize
	// CloseWrite with Write because both access the channel's EOF state.
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func (c *sshStream) SetReadDeadline(t time.Time) error {
	return c.setDeadline(&c.read.deadline, t)
}

func (c *sshStream) SetWriteDeadline(t time.Time) error {
	return c.setDeadline(&c.write.deadline, t)
}

func (c *sshStream) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *sshStream) setDeadline(d *pipe.Deadline, t time.Time) error {
	d.Set(t)
	// Close may already have stopped this timer before we set it.
	select {
	case <-c.closed:
		d.Set(time.Time{})
		return net.ErrClosed
	default:
		return nil
	}
}

func (c *sshStream) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.read.deadline.Set(time.Time{})
		c.write.deadline.Set(time.Time{})
		c.closeErr = c.Conn.Close()
		c.release()
	})
	return c.closeErr
}
