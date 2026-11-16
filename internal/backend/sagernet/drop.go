package sagernet

import (
	"context"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
)

// DropSpec accepts the local connection and discards payloads without opening
// a remote socket or sending an immediate rejection to the local client.
type DropSpec struct{}
type dropOutbound struct{ outbound.Adapter }

func newDropOutbound(tag string) *dropOutbound {
	return &dropOutbound{outbound.NewAdapter("reject-drop", tag, []string{"tcp", "udp"}, nil)}
}

type dropConn struct {
	net.Conn
	peer net.Conn
}

func newDropConn() *dropConn     { a, b := net.Pipe(); go io.Copy(io.Discard, b); return &dropConn{a, b} }
func (c *dropConn) Close() error { c.peer.Close(); return c.Conn.Close() }
func (d *dropOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return newDropConn(), nil
}
func (d *dropOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return &dropPacketConn{newDropConn()}, nil
}

type dropPacketConn struct{ *dropConn }

func (c *dropPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, nil, err
}
func (c *dropPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
