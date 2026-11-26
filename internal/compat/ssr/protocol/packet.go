package protocol

import (
	"bytes"
	"io"
	"net"
)

type packetCodec interface {
	DecodePacket([]byte) ([]byte, error)
	EncodePacket(*bytes.Buffer, []byte) error
}

type packetConn struct {
	net.PacketConn
	codec packetCodec
}

func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	var encoded bytes.Buffer
	if err := c.codec.EncodePacket(&encoded, b); err != nil {
		return 0, err
	}
	n, err := c.PacketConn.WriteTo(encoded.Bytes(), addr)
	if err != nil {
		return 0, err
	}
	if n != encoded.Len() {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, addr, err
	}
	decoded, err := c.codec.DecodePacket(b[:n])
	if err != nil {
		return 0, addr, err
	}
	return copy(b, decoded), addr, nil
}
