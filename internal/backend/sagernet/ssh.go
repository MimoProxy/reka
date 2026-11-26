package sagernet

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/ssh"
)

var (
	_ adapter.OutboundWithMultiplex = (*sshOutbound)(nil)
	_ adapter.IdleConnectionKeeper  = (*sshOutbound)(nil)
)

type sshOutbound struct {
	outbound.Adapter
	dialer N.Dialer
	server M.Socksaddr
	config *ssh.ClientConfig

	mu        sync.Mutex
	pending   *sshHandshake
	session   *sshSession
	closeIdle bool
	closed    bool
}

type sshSession struct {
	*ssh.Client
	transport *sshTransportConn
	streams   int
	probing   bool
}

type sshHandshake struct {
	done           chan struct{}
	cancel         context.CancelFunc
	err            error
	callerCanceled bool
}

func newSSHOutbound(ctx context.Context, tag string, data []byte) (adapter.Outbound, error) {
	var options struct {
		option.SSHOutboundOptions
		InsecureSkipHostKey bool `json:"reka_insecure_skip_host_key"`
	}
	if err := json.UnmarshalContext(ctx, data, &options); err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User: options.User, ClientVersion: options.ClientVersion, HostKeyAlgorithms: options.HostKeyAlgorithms,
	}
	if config.User == "" {
		config.User = "root"
	}
	if config.ClientVersion == "" {
		config.ClientVersion = sshRandomVersion()
	}
	if options.PrivateKeyPath != "" {
		return nil, errors.New("SSH private key must be inline")
	}
	if options.PrivateKeyPassphrase != "" && len(options.PrivateKey) == 0 {
		return nil, errors.New("SSH private key passphrase requires a private key")
	}
	if len(options.PrivateKey) > 0 {
		raw := []byte(strings.Join(options.PrivateKey, "\n"))
		var signer ssh.Signer
		var err error
		if options.PrivateKeyPassphrase == "" {
			signer, err = ssh.ParsePrivateKey(raw)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(raw, []byte(options.PrivateKeyPassphrase))
		}
		if err != nil {
			return nil, errors.New("invalid SSH private key or passphrase")
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}
	if options.Password != "" {
		config.Auth = append(config.Auth, ssh.Password(options.Password))
	}
	if len(config.Auth) == 0 {
		return nil, errors.New("SSH requires a private key or password")
	}
	if len(options.HostKey) == 0 && !options.InsecureSkipHostKey {
		return nil, errors.New("SSH requires host-key or explicit insecure-skip-host-key")
	}
	if options.InsecureSkipHostKey {
		if len(options.HostKey) > 0 {
			return nil, errors.New("SSH host-key and insecure-skip-host-key are mutually exclusive")
		}
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		var pins [][]byte
		for _, line := range options.HostKey {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				return nil, fmt.Errorf("parse SSH host key: %w", err)
			}
			pins = append(pins, key.Marshal())
			if len(options.HostKeyAlgorithms) == 0 {
				// Prefer the pinned key types, as OpenSSH does for known hosts.
				// A server can offer several keys but sends only the negotiated one.
				for _, algo := range sshAlgorithmsForKey(key.Type()) {
					if !slices.Contains(config.HostKeyAlgorithms, algo) {
						config.HostKeyAlgorithms = append(config.HostKeyAlgorithms, algo)
					}
				}
			}
		}
		config.HostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
			wire := key.Marshal()
			for _, pin := range pins {
				if bytes.Equal(wire, pin) {
					return nil
				}
			}
			return fmt.Errorf("SSH host key mismatch, server sent %s %s", key.Type(), base64.StdEncoding.EncodeToString(wire))
		}
	}
	d, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	server := options.ServerOptions.Build()
	if server.Port == 0 {
		server.Port = 22
	}
	return &sshOutbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeSSH, tag, []string{N.NetworkTCP}, options.DialerOptions),
		dialer:  d, server: server, config: config,
	}, nil
}

func sshAlgorithmsForKey(keyType string) []string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	case ssh.CertAlgoRSAv01:
		return []string{ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSAv01}
	default:
		return []string{keyType}
	}
}

// Match the OpenSSH version distribution used by sing-box and mihomo.
func sshRandomVersion() string {
	if rand.Intn(2) == 0 {
		return "SSH-2.0-OpenSSH_7." + strconv.Itoa(rand.Intn(10))
	}
	return "SSH-2.0-OpenSSH_8." + strconv.Itoa(rand.Intn(9))
}

// As in mihomo, a failed transport write must wake the SSH reader. Otherwise
// the mux can keep returning the cached write error while Wait never exits.
type sshTransportConn struct {
	net.Conn
	failed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (c *sshTransportConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.failed.Store(true)
	}
	return n, err
}

func (c *sshTransportConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.failed.Store(true)
		_ = c.Close()
	}
	return n, err
}

func (c *sshTransportConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

func (s *sshOutbound) handshake(ctx context.Context) (*sshSession, error) {
	conn, err := s.dialer.DialContext(adapter.ContextForMultiplexSession(ctx), N.NetworkTCP, s.server)
	if err != nil {
		return nil, err
	}
	physical := &sshTransportConn{Conn: conn}
	stop := context.AfterFunc(ctx, func() { _ = physical.Close() })
	transport, channels, requests, err := ssh.NewClientConn(physical, s.server.String(), s.config)
	if !stop() || ctx.Err() != nil {
		_ = physical.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return &sshSession{Client: ssh.NewClient(transport, channels, requests), transport: physical, streams: 1}, nil
}

// acquire reserves a stream before releasing the lock, so idle cleanup cannot
// close a session between selecting it and opening the forwarding channel.
func (s *sshOutbound) acquire(ctx context.Context) (*sshSession, bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, false, net.ErrClosed
		}
		if session := s.session; session != nil {
			if session.transport.failed.Load() {
				s.session = nil
				s.mu.Unlock()
				_ = session.Close()
				continue
			}
			session.streams++
			s.mu.Unlock()
			return session, true, nil
		}
		if pending := s.pending; pending != nil {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-pending.done:
				if pending.err != nil && !pending.callerCanceled {
					return nil, false, pending.err
				}
				continue
			}
		}

		// Bound the dial and SSH handshake by sing-box's TCPTimeout (15s).
		handshakeCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
		pending := &sshHandshake{done: make(chan struct{}), cancel: cancel}
		s.pending = pending
		s.mu.Unlock()

		session, err := s.handshake(handshakeCtx)
		cancel()
		s.mu.Lock()
		if s.closed {
			err = net.ErrClosed
		}
		if err == nil {
			s.session = session
			go func() {
				_ = session.Wait()
				s.discard(session)
			}()
		}
		pending.err = err
		pending.callerCanceled = ctx.Err() != nil
		s.pending = nil
		close(pending.done)
		s.mu.Unlock()
		if err != nil && session != nil {
			_ = session.Close()
		}
		return session, false, err
	}
}

func (s *sshOutbound) discard(session *sshSession) {
	s.mu.Lock()
	if s.session == session {
		s.session = nil
	}
	s.mu.Unlock()
	_ = session.Close()
}

func (s *sshOutbound) probe(session *sshSession) {
	s.mu.Lock()
	if s.session != session || session.probing {
		s.mu.Unlock()
		return
	}
	session.probing = true
	s.mu.Unlock()
	go func() {
		// Give a silent peer sing-box's TCPConnectTimeout (5s) to answer.
		// A negative SSH reply also proves that the mux is responsive.
		timer := time.AfterFunc(C.TCPConnectTimeout, func() { s.discard(session) })
		_, _, err := session.SendRequest("keepalive@openssh.com", true, nil)
		timer.Stop()
		if err != nil {
			s.discard(session)
		}
		s.mu.Lock()
		session.probing = false
		s.mu.Unlock()
	}()
}

func (s *sshOutbound) release(session *sshSession, keepSession bool) {
	s.mu.Lock()
	session.streams--
	closeIdle := s.session == session && session.streams == 0 && s.closeIdle && !keepSession
	if closeIdle {
		s.session = nil
	}
	s.mu.Unlock()
	if closeIdle {
		_ = session.Close()
	}
}

func (s *sshOutbound) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, errors.New("SSH carries TCP only")
	}
	for attempt := 0; ; attempt++ {
		session, reused, err := s.acquire(ctx)
		if err != nil {
			return nil, err
		}
		conn, err := session.DialContext(ctx, N.NetworkTCP, dst.String())
		if err == nil {
			keep := adapter.KeepSessionFromContext(ctx)
			return newSSHStream(conn, func() { s.release(session, keep) }), nil
		}
		s.release(session, false)
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == context.DeadlineExceeded {
			s.probe(session)
		}
		// Wait may still be about to observe EOF on a reused session. No
		// channel was opened, so it is safe to retry once on a fresh client.
		if attempt == 0 && reused && ctx.Err() == nil && (session.transport.failed.Load() || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)) {
			s.discard(session)
			continue
		}
		return nil, err
	}
}

func (s *sshOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("SSH carries TCP only")
}

func (s *sshOutbound) MultiplexEnabled() bool { return true }

func (s *sshOutbound) SetKeepIdleConnections(keep bool) {
	s.mu.Lock()
	s.closeIdle = !keep
	var idle *sshSession
	if !keep {
		idle = s.takeIdleLocked()
	}
	s.mu.Unlock()
	if idle != nil {
		_ = idle.Close()
	}
}

func (s *sshOutbound) CloseIdleConnections() {
	s.mu.Lock()
	idle := s.takeIdleLocked()
	s.mu.Unlock()
	if idle != nil {
		_ = idle.Close()
	}
}

func (s *sshOutbound) takeIdleLocked() *sshSession {
	session := s.session
	if session == nil || session.streams != 0 {
		return nil
	}
	s.session = nil
	return session
}

func (s *sshOutbound) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.pending != nil {
		s.pending.cancel()
	}
	session := s.session
	s.session = nil
	s.mu.Unlock()
	if session != nil {
		return session.Close()
	}
	return nil
}
