package sagernet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// ShadowTLS v2 has no server record marker. Keep the negotiated TLS decoder
// until its first non-TLS application record: HTTP/2 SETTINGS and session
// tickets from the camouflage site must not become proxy payload. No TLS keys
// or cipher implementation are duplicated here.
type shadowTLSV2Recorder struct {
	net.Conn
	record   []byte
	partial  []byte
	finished bool
}

func (c *shadowTLSV2Recorder) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.finished {
		// Preserve normal physical reads during the handshake: v2 authenticates
		// those reads, and uTLS can finish with a ticket still in its raw input.
		// Afterwards stop at record boundaries, including any partial record
		// prefetched by the handshake, so the failed proxy record is recoverable.
		remaining := 5 - len(c.partial)
		if len(c.partial) >= 5 {
			remaining = 5 + int(binary.BigEndian.Uint16(c.partial[3:5])) - len(c.partial)
		}
		if len(p) > remaining {
			p = p[:remaining]
		}
	}
	n, err := c.Conn.Read(p)
	for data := p[:n]; len(data) > 0; {
		remaining := 5 - len(c.partial)
		if len(c.partial) >= 5 {
			remaining = 5 + int(binary.BigEndian.Uint16(c.partial[3:5])) - len(c.partial)
		}
		count := min(len(data), remaining)
		c.partial = append(c.partial, data[:count]...)
		data = data[count:]
		if len(c.partial) >= 5 && len(c.partial) == 5+int(binary.BigEndian.Uint16(c.partial[3:5])) {
			c.record = c.partial
			c.partial = nil
		}
	}
	return n, err
}

func (c *shadowTLSV2Recorder) Write(p []byte) (int, error) {
	if c.finished {
		// A bad MAC is the v2 transition, not an alert for the data server.
		// TLS control writes use only this wrapper; proxy writes bypass it.
		return len(p), nil
	}
	return c.Conn.Write(p)
}

type shadowTLSV2DataConn struct {
	net.Conn
	tls      net.Conn
	recorder *shadowTLSV2Recorder
	mu       sync.Mutex
	data     *bytes.Reader
}

func (c *shadowTLSV2DataConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tls != nil {
		var discard [4096]byte
		for {
			_, err := c.tls.Read(discard[:])
			if err == nil {
				continue
			}
			// Only the authenticated TLS decoder's local bad-MAC result marks
			// a raw v2 record. EOF, alerts and network failures remain errors.
			var alert *net.OpError
			if !errors.As(err, &alert) || alert.Op != "local error" || alert.Err.Error() != "tls: bad record MAC" || len(c.recorder.record) < 5 || c.recorder.record[0] != 23 {
				return 0, err
			}
			c.data = bytes.NewReader(c.recorder.record)
			c.tls = nil
			c.recorder = nil
			break
		}
	}
	if c.data != nil {
		if c.data.Len() > 0 {
			return c.data.Read(p)
		}
		c.data = nil
	}
	return c.Conn.Read(p)
}
