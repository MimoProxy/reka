// JLS clients authenticate their peer using the configured JLS credentials.
package jls

import (
	"context"
	"errors"
	"net"
	"time"

	tls "github.com/metacubex/jls-tls"
)

type User = tls.JLSUser

var DefaultALPN = []string{"h2", "http/1.1"}
var ErrJLSAuthFailed = tls.ErrJLSAuthFailed

type ClientConfig struct {
	ServerName        string
	User              User
	ALPN              []string
	ClientFingerprint string
}

func NewClient(ctx context.Context, raw net.Conn, config *ClientConfig) (net.Conn, error) {
	if config == nil || config.ServerName == "" || config.User.Username == "" || config.User.Password == "" {
		return nil, errors.New("JLS requires server name, username and password")
	}
	if c, ok, err := newUTLSClient(ctx, raw, config); ok {
		return c, err
	}
	alpn := config.ALPN
	if alpn == nil {
		alpn = DefaultALPN
	}
	c := tls.Client(raw, &tls.Config{ServerName: config.ServerName, NextProtos: append([]string(nil), alpn...), Time: time.Now, JLSConfig: &tls.JLSConfig{Enable: true, User: config.User}})
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if c.ConnectionState().JLS.Status != tls.JLSAuthenticated {
		return nil, ErrJLSAuthFailed
	}
	return c, nil
}
