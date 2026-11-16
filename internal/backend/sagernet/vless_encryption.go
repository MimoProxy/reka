package sagernet

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	VE "github.com/MimoProxy/reka/internal/compat/vlessenc"
)

func newEncryptionClient(value string) (*VE.ClientInstance, error) {
	client, err := VE.NewClient(value)
	if err != nil {
		return nil, errors.New("invalid VLESS encryption configuration")
	}
	return client, nil
}
func encryptionHandshake(client *VE.ClientInstance) func(context.Context, net.Conn) (net.Conn, error) {
	return func(ctx context.Context, c net.Conn) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		result, err := client.HandshakeContext(ctx, c)
		if err != nil {
			c.Close()
		}
		return result, err
	}
}
func configureEncryptionContext(ctx context.Context, value string) (context.Context, *atomic.Bool, error) {
	client, err := newEncryptionClient(value)
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return ctx, nil, nil
	}
	configured := &atomic.Bool{}
	handshake := encryptionHandshake(client)
	hook := func() func(context.Context, net.Conn) (net.Conn, error) { configured.Store(true); return handshake }
	return context.WithValue(ctx, "reka.vless.encryption.v1", hook), configured, nil
}
