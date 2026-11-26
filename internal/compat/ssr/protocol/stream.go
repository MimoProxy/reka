package protocol

import (
	"bytes"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
)

type streamCodec interface {
	Decode(dst, src *bytes.Buffer) error
	Encode(dst *bytes.Buffer, data []byte) error
}

type streamConn struct {
	net.Conn
	codec           streamCodec
	pendingErr      error
	readMu, writeMu sync.Mutex
	// The first outbound auth_chain frame establishes the inbound cipher state.
	codecMu               sync.Mutex
	decoded, underDecoded bytes.Buffer
	readErr               error
}

func (c *streamConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if c.decoded.Len() > 0 {
		return c.decoded.Read(b)
	}
	if c.pendingErr != nil {
		err := c.pendingErr
		c.pendingErr = nil
		return 0, err
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	raw := buf.Get(32 * 1024)
	defer buf.Put(raw)
	for {
		n, err := c.Conn.Read(raw)
		if n > 0 {
			c.underDecoded.Write(raw[:n])
			c.codecMu.Lock()
			decodeErr := c.codec.Decode(&c.decoded, &c.underDecoded)
			c.codecMu.Unlock()
			if decodeErr != nil {
				c.readErr = decodeErr
				c.Conn.Close()
				if c.decoded.Len() > 0 {
					return c.decoded.Read(b)
				}
				return 0, decodeErr
			}
		}
		if err == io.EOF && c.underDecoded.Len() > 0 {
			err = io.ErrUnexpectedEOF
		}
		if c.decoded.Len() > 0 {
			c.pendingErr = err
			return c.decoded.Read(b)
		}
		if err != nil {
			return 0, err
		}
	}
}

func (c *streamConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	var encoded bytes.Buffer
	c.codecMu.Lock()
	err := c.codec.Encode(&encoded, b)
	c.codecMu.Unlock()
	if err == nil {
		_, err = encoded.WriteTo(c.Conn)
	}
	if err != nil {
		c.Conn.Close()
		return 0, err
	}
	return len(b), nil
}
