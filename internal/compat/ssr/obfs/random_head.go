package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"io"
	randv2 "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
)

func init() { register("random_head", newRandomHead, 0) }

type randomHead struct{}

func newRandomHead(*Base) Obfs { return &randomHead{} }

type randomHeadConn struct {
	net.Conn
	closed              atomic.Bool
	readMu, writeMu     sync.Mutex
	receivedHeader      bool
	sentHeader, flushed bool
	pending             []byte
}

func (r *randomHead) StreamConn(c net.Conn) net.Conn {
	return &randomHeadConn{Conn: c}
}

func (c *randomHeadConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *randomHeadConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if !c.receivedHeader {
		header := buf.Get(32 * 1024)
		_, err := c.Conn.Read(header)
		buf.Put(header)
		if err != nil {
			return 0, err
		}
		if err := c.flush(); err != nil {
			return 0, err
		}
		c.receivedHeader = true
	}
	return c.Conn.Read(b)
}

func (c *randomHeadConn) flush() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(c.pending) == 0 {
		c.flushed = true
		return nil
	}
	n, err := c.Conn.Write(c.pending)
	if err == nil && n != len(c.pending) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.Close()
		return err
	}
	c.pending = nil
	c.flushed = true
	return nil
}

func (c *randomHeadConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.flushed {
		return c.Conn.Write(b)
	}
	if len(b) > maxPending-len(c.pending) {
		c.Close()
		return 0, errPendingFull
	}
	c.pending = append(c.pending, b...)
	if !c.sentHeader {
		dataLength := randv2.IntN(96) + 4
		header := make([]byte, dataLength+4)
		rand.Read(header[:dataLength])
		binary.LittleEndian.PutUint32(header[dataLength:], ^crc32.ChecksumIEEE(header[:dataLength]))
		n, err := c.Conn.Write(header)
		if err != nil {
			c.Close()
			return 0, err
		}
		if n != len(header) {
			c.Close()
			return 0, io.ErrShortWrite
		}
		c.sentHeader = true
	}
	return len(b), nil
}
