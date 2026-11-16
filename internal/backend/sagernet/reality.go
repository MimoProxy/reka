package sagernet

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

// realityClient is Reka's REALITY client. It follows sing-box's
// common/tls/reality_client.go, with one addition: when mlkem is set the
// X25519MLKEM768 key share stays in the ClientHello, as current Xray servers
// may require. sing-box always strips it.
type realityClient struct {
	alpn        []string
	serverName  string
	fingerprint utls.ClientHelloID
	publicKey   *ecdh.PublicKey
	shortID     [8]byte
	mlkem       bool
	timeout     time.Duration
}

const realityHandshakeTimeout = 15 * time.Second

func newRealityClient(t *TLSSpec) (*realityClient, error) {
	if t.Carrier != nil {
		return nil, errors.New("REALITY is mutually exclusive with other security carriers")
	}
	if t.ServerName == "" {
		return nil, errors.New("reality: server_name is required")
	}
	fp, err := clientHelloID(t.Fingerprint)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(t.Reality.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("reality: decode public key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("reality: invalid public key: %w", err)
	}
	c := &realityClient{
		serverName:  t.ServerName,
		alpn:        append([]string{}, t.ALPN...),
		fingerprint: fp,
		publicKey:   pub,
		mlkem:       t.Reality.X25519MLKEM768,
		timeout:     realityHandshakeTimeout,
	}
	if len(t.Reality.ShortID) > 16 {
		return nil, errors.New("reality: short id longer than 8 bytes")
	}
	if _, err := hex.Decode(c.shortID[:], []byte(t.Reality.ShortID)); err != nil {
		return nil, fmt.Errorf("reality: decode short id: %w", err)
	}
	return c, nil
}

// clientHelloID maps share-link fingerprint names to uTLS parrots.
func clientHelloID(name string) (utls.ClientHelloID, error) {
	switch name {
	case "", "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "360":
		return utls.Hello360_Auto, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "random", "randomized":
		id := utls.HelloRandomized
		seed, err := utls.NewPRNGSeed()
		if err != nil {
			return utls.ClientHelloID{}, err
		}
		id.Seed = seed
		return id, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("reality: unknown fingerprint %q", name)
	}
}

// Handshake runs a REALITY handshake over conn. On success the returned
// connection unwraps to *utls.UConn, which Vision needs.
func (c *realityClient) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	verifier := &realityVerifier{serverName: c.serverName}
	config := &utls.Config{
		ServerName:             c.serverName,
		InsecureSkipVerify:     true, // verifier below does the real check
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  verifier.verify,
	}
	uConn := utls.UClient(conn, config, c.fingerprint)
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	if len(c.alpn) > 0 {
		for _, ext := range uConn.Extensions {
			if a, ok := ext.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = c.alpn
			}
		}
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, err
		}
	}
	if !c.mlkem {
		removeMLKEM(uConn)
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, err
		}
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId) // session id sits at a fixed offset

	now := time.Now()
	binary.BigEndian.PutUint64(hello.SessionId, uint64(now.Unix()))
	hello.SessionId[0] = 1 // client version 1.8.1, as sing-box sends
	hello.SessionId[1] = 8
	hello.SessionId[2] = 1
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(now.Unix()))
	copy(hello.SessionId[8:], c.shortID[:])

	keys := uConn.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		return nil, errors.New("reality: no key share keys")
	}
	ecdheKey := keys.Ecdhe
	if ecdheKey == nil {
		// Only the hybrid share was generated; its X25519 half authenticates.
		ecdheKey = keys.MlkemEcdhe
	}
	if ecdheKey == nil {
		return nil, errors.New("reality: no X25519 key share")
	}
	authKey, err := ecdheKey.ECDH(c.publicKey)
	if err != nil {
		return nil, err
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, err
	}
	verifier.authKey = authKey
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !verifier.verified {
		// Look like a browser that got a real site, then hang up.
		go realityFallback(uConn, c.serverName, c.fingerprint)
		return nil, errRealityVerification
	}
	return &realityConn{uConn: uConn}, nil
}

var errRealityVerification = errors.New("reality verification failed")

// removeMLKEM drops X25519MLKEM768 from supported groups and key shares,
// for older REALITY servers that cannot handle it.
func removeMLKEM(uConn *utls.UConn) {
	for _, ext := range uConn.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			curves := e.Curves[:0]
			for _, id := range e.Curves {
				if id != utls.X25519MLKEM768 {
					curves = append(curves, id)
				}
			}
			e.Curves = curves
		case *utls.KeyShareExtension:
			shares := e.KeyShares[:0]
			for _, s := range e.KeyShares {
				if s.Group != utls.X25519MLKEM768 {
					shares = append(shares, s)
				}
			}
			e.KeyShares = shares
		}
	}
}

type realityVerifier struct {
	serverName string
	authKey    []byte
	verified   bool
}

// verify accepts the server's temporary ed25519 certificate when its
// signature is the HMAC of its key under the shared auth key. Anything else
// must be a valid certificate for serverName (the server fell back to the
// real site); the handshake then succeeds but Handshake reports failure.
func (v *realityVerifier) verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("reality: no server certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, v.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			v.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{DNSName: v.serverName, Intermediates: x509.NewCertPool()}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(opts)
	return err
}

func realityFallback(uConn *utls.UConn, serverName string, fp utls.ClientHelloID) {
	defer uConn.Close()
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http2.Transport{
			DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+serverName, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", fp.Client)
	req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", mrand.IntN(32)+30)})
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// realityConn exposes the uTLS connection to Vision via Upstream. It wraps
// rather than embeds *utls.UConn so that uTLS's CloseWrite (a TLS
// close_notify) is not promoted: REALITY servers mishandle it and leak the
// connection. sing-box closes the whole connection instead, which drops the
// reply still in flight; without CloseWrite Reka's relay keeps reading until
// the download goes idle, then closes.
type realityConn struct {
	uConn *utls.UConn
}

var _ net.Conn = (*realityConn)(nil)

func (c *realityConn) Read(b []byte) (int, error)         { return c.uConn.Read(b) }
func (c *realityConn) Write(b []byte) (int, error)        { return c.uConn.Write(b) }
func (c *realityConn) Close() error                       { return c.uConn.Close() }
func (c *realityConn) LocalAddr() net.Addr                { return c.uConn.LocalAddr() }
func (c *realityConn) RemoteAddr() net.Addr               { return c.uConn.RemoteAddr() }
func (c *realityConn) SetDeadline(t time.Time) error      { return c.uConn.SetDeadline(t) }
func (c *realityConn) SetReadDeadline(t time.Time) error  { return c.uConn.SetReadDeadline(t) }
func (c *realityConn) SetWriteDeadline(t time.Time) error { return c.uConn.SetWriteDeadline(t) }

func (c *realityConn) Upstream() any           { return c.uConn }
func (c *realityConn) ReaderReplaceable() bool { return true }
func (c *realityConn) WriterReplaceable() bool { return false }
