package sagernet

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	RT "github.com/metacubex/restls-client-go"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func newRestlsPlugin(base N.Dialer, dst M.Socksaddr, s SSPluginSpec) (func(context.Context) (net.Conn, error), error) {
	config, err := RT.NewRestlsConfig(s.Host, s.Password, s.VersionHint, s.RestlsScript, s.ClientFingerprint)
	if err != nil {
		return nil, err
	}
	config.ForceTLS12 = s.ForceTLS12
	if spec := s.TLS; spec != nil {
		if spec.ECH != nil || spec.Reality != nil || spec.Fingerprint != "" {
			return nil, errors.New("Restls does not use ECH, REALITY or generic TLS fingerprints")
		}
		if spec.ServerName != "" {
			config.ServerName = spec.ServerName
		}
		config.InsecureSkipVerify = spec.Insecure
		if spec.ALPN != nil {
			config.NextProtos = append([]string{}, spec.ALPN...)
		}
		if spec.Certificate != "" || spec.PrivateKey != "" {
			cert, err := RT.X509KeyPair([]byte(spec.Certificate), []byte(spec.PrivateKey))
			if err != nil {
				return nil, err
			}
			config.Certificates = []RT.Certificate{cert}
		}
		if spec.CertificatePin != "" || spec.VerifyName != "" {
			ctx, _ := configureTLSContext(context.Background(), spec)
			standard := &tls.Config{ServerName: config.ServerName}
			if err := ctx.Value("reka.tls.configure.v1").(func(any) error)(standard); err != nil {
				return nil, err
			}
			config.InsecureSkipVerify = true
			config.VerifyConnection = func(state RT.ConnectionState) error {
				raw := make([][]byte, len(state.PeerCertificates))
				for i, cert := range state.PeerCertificates {
					raw[i] = cert.Raw
				}
				return standard.VerifyPeerCertificate(raw, nil)
			}
		}
	}
	return func(ctx context.Context) (net.Conn, error) {
		raw, err := base.DialContext(ctx, "tcp", dst)
		if err != nil {
			return nil, err
		}
		clone := config.Clone()
		hello := RT.HelloChrome_Auto
		if id := clone.ClientID.Load(); id != nil {
			hello = *id
		}
		c := RT.UClient(raw, clone, hello)
		started := time.Now()
		if err := c.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		observeTLS(ctx, raw, started, time.Now(), c.ConnectionState().ServerName, "restls")
		return c, nil
	}, nil
}
