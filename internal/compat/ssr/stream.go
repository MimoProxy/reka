package ssr

import (
	"crypto/rand"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
)

type streamConn struct {
	net.Conn
	method          *streamMethod
	readMu, writeMu sync.Mutex
	reader, writer  *keyStream
	writeIV         []byte
}

func (m *streamMethod) wrapStream(conn net.Conn) (net.Conn, []byte, error) {
	if m.ivSize == 0 {
		return conn, nil, nil
	}
	iv := make([]byte, m.ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	writer, err := m.stream(iv, false)
	if err != nil {
		return nil, nil, err
	}
	return &streamConn{Conn: conn, method: m, writer: writer, writeIV: iv}, iv, nil
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.reader == nil {
		iv := make([]byte, c.method.ivSize)
		if n, err := io.ReadFull(c.Conn, iv); err != nil {
			if n > 0 {
				_ = c.Close()
			}
			return 0, err
		}
		stream, err := c.method.stream(iv, true)
		if err != nil {
			_ = c.Close()
			return 0, err
		}
		c.reader = stream
	}
	if c.reader.remaining == 0 {
		_ = c.Close()
		return 0, errCounterLimit
	}
	if uint64(len(p)) > c.reader.remaining {
		p = p[:c.reader.remaining]
	}
	n, err := c.Conn.Read(p)
	if cipherErr := c.reader.xor(p[:n], p[:n]); cipherErr != nil {
		_ = c.Close()
		return 0, cipherErr
	}
	return n, err
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if uint64(len(p)) > c.writer.remaining {
		_ = c.Close()
		return 0, errCounterLimit
	}
	// mihomo emits the IV in its own obfs write before the first ciphertext.
	if c.writeIV != nil {
		n, err := c.Conn.Write(c.writeIV)
		if err == nil && n != len(c.writeIV) {
			err = io.ErrShortWrite
		}
		if err != nil {
			_ = c.Close()
			return 0, err
		}
		c.writeIV = nil
	}
	buffer := buf.NewSize(min(len(p), 32*1024))
	defer buffer.Release()
	written := 0
	for len(p) > 0 {
		part := p[:min(len(p), buffer.Cap())]
		block := buffer.FreeBytes()[:len(part)]
		if err := c.writer.xor(block, part); err != nil {
			_ = c.Close()
			return written, err
		}
		n, err := c.Conn.Write(block)
		written += n
		if err == nil && n != len(block) {
			err = io.ErrShortWrite
		}
		if err != nil {
			_ = c.Close()
			return written, err
		}
		p = p[len(part):]
	}
	return written, nil
}
