package ssr

import (
	"errors"
	"net"

	"github.com/MimoProxy/reka/internal/compat/ssr/obfs"
	"github.com/MimoProxy/reka/internal/compat/ssr/protocol"
	M "github.com/sagernet/sing/common/metadata"
)

type Config struct {
	Server                  string
	Port                    uint16
	Method, Password        string
	Obfs, ObfsParam         string
	Protocol, ProtocolParam string
}

type Client struct {
	method   *streamMethod
	obfs     obfs.Obfs
	protocol protocol.Protocol
}

func ValidateObfs(name string) error     { return obfs.Validate(name) }
func ValidateProtocol(name string) error { return protocol.Validate(name) }

func New(config Config) (*Client, error) {
	if config.Server == "" || config.Port == 0 {
		return nil, errors.New("SSR server and port are required")
	}
	if config.Password == "" {
		return nil, errors.New("SSR password is required")
	}
	method, err := newMethod(config.Method, config.Password)
	if err != nil {
		return nil, err
	}
	if config.Obfs == "" {
		config.Obfs = "plain"
	}
	if config.Protocol == "" {
		config.Protocol = "origin"
	}
	obfuscator, overhead, err := obfs.PickObfs(config.Obfs, &obfs.Base{
		Host: config.Server, Port: int(config.Port), Key: method.key, IVSize: method.ivSize, Param: config.ObfsParam,
	})
	if err != nil {
		return nil, err
	}
	framing, err := protocol.PickProtocol(config.Protocol, &protocol.Base{
		Key: method.key, Overhead: overhead, Param: config.ProtocolParam,
	})
	if err != nil {
		return nil, err
	}
	return &Client{method: method, obfs: obfuscator, protocol: framing}, nil
}

// StreamConn writes the SOCKS destination through the negotiated layers.
// The caller owns conn and closes it if setup fails.
func (c *Client) StreamConn(conn net.Conn, dst M.Socksaddr) (net.Conn, error) {
	encrypted, iv, err := c.method.wrapStream(c.obfs.StreamConn(conn))
	if err != nil {
		return nil, err
	}
	stream := c.protocol.StreamConn(encrypted, iv)
	if err = M.SocksaddrSerializer.WriteAddrPort(stream, dst.Unwrap()); err != nil {
		return nil, err
	}
	return stream, nil
}

// PacketConn sends each addressed datagram to server. SSR obfs is TCP-only.
func (c *Client) PacketConn(conn net.PacketConn, server net.Addr) net.PacketConn {
	if c.method.ivSize != 0 {
		conn = &cipherPacketConn{PacketConn: conn, method: c.method}
	}
	return &packetConn{PacketConn: c.protocol.PacketConn(conn), server: server}
}
