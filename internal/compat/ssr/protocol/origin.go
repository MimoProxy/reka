package protocol

import "net"

type origin struct{}

func init() { register("origin", newOrigin, 0) }

func newOrigin(b *Base) Protocol { return &origin{} }

func (o *origin) StreamConn(c net.Conn, iv []byte) net.Conn { return c }

func (o *origin) PacketConn(c net.PacketConn) net.PacketConn { return c }
