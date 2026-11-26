package ssr

import (
	"crypto/rand"
	"errors"
	"io"
	"net"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

const maxPacketSize = 65535

type cipherPacketConn struct {
	net.PacketConn
	method *streamMethod
}

func (c *cipherPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > maxPacketSize-c.method.ivSize {
		return 0, io.ErrShortBuffer
	}
	buffer := buf.NewSize(c.method.ivSize + len(p))
	defer buffer.Release()
	iv := buffer.Extend(c.method.ivSize)
	if _, err := rand.Read(iv); err != nil {
		return 0, err
	}
	stream, err := c.method.stream(iv, false)
	if err != nil {
		return 0, err
	}
	if err = stream.xor(buffer.Extend(len(p)), p); err != nil {
		return 0, err
	}
	n, err := c.PacketConn.WriteTo(buffer.Bytes(), addr)
	if err != nil {
		return 0, err
	}
	if n != buffer.Len() {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (c *cipherPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, nil, err
	}
	if n < c.method.ivSize {
		return 0, nil, io.ErrUnexpectedEOF
	}
	stream, err := c.method.stream(p[:c.method.ivSize], true)
	if err != nil {
		return 0, nil, err
	}
	payload := p[c.method.ivSize:n]
	if err = stream.xor(payload, payload); err != nil {
		return 0, nil, err
	}
	return copy(p, payload), addr, nil
}

type packetConn struct {
	net.PacketConn
	server net.Addr
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dst := M.SocksaddrFromNet(addr).Unwrap()
	header := M.SocksaddrSerializer.AddrPortLen(dst)
	if len(p) > maxPacketSize-header {
		return 0, io.ErrShortBuffer
	}
	buffer := buf.NewSize(header + len(p))
	defer buffer.Release()
	if err := M.SocksaddrSerializer.WriteAddrPort(buffer, dst); err != nil {
		return 0, err
	}
	copy(buffer.Extend(len(p)), p)
	n, err := c.PacketConn.WriteTo(buffer.Bytes(), c.server)
	if err != nil {
		return 0, err
	}
	if n != buffer.Len() {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// Read the complete wire datagram even when the application requests a
	// short payload. Cipher IVs, authentication tags and addresses need it.
	buffer := buf.NewSize(maxPacketSize)
	defer buffer.Release()
	n, _, err := c.PacketConn.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return 0, nil, err
	}
	buffer.Truncate(n)
	dst, err := M.SocksaddrSerializer.ReadAddrPort(buffer)
	if err != nil {
		return 0, nil, err
	}
	if !dst.IsValid() {
		return 0, nil, errors.New("invalid SSR packet address")
	}
	if dst.IsIP() {
		return copy(p, buffer.Bytes()), dst.UDPAddr(), nil
	}
	return copy(p, buffer.Bytes()), dst, nil
}
