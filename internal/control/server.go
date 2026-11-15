package control

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/MimoProxy/reka/internal/api"
)

// Listen opens a control endpoint that only accepts the current user.
func Listen(addr string) (net.Listener, error) {
	network, target, err := api.ParseAddress(addr)
	if err != nil {
		return nil, err
	}
	if network == "pipe" {
		return listenPipe(target)
	}
	return listenUnix(target)
}

func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// A socket left by a crashed process blocks the bind; remove it if no
	// one answers on it.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return nil, fmt.Errorf("control: %s is in use by another process", path)
		}
		os.Remove(path)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	if err := ownSocket(path); err != nil {
		l.Close()
		return nil, err
	}
	return &peerListener{Listener: l}, nil
}

// peerListener drops connections from other users.
type peerListener struct{ net.Listener }

// ErrPeerDenied is the reason a connection from another user is dropped.
var ErrPeerDenied = errors.New("control: connection from another user refused")

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err := checkPeer(c); err != nil {
			slog.Warn("control: refused connection", "err", err)
			c.Close()
			continue
		}
		return c, nil
	}
}

// Server serves the control API on listeners.
type Server struct {
	h      *Handler
	mu     sync.Mutex
	lns    []net.Listener
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
	closed bool
}

// NewServer serves h.
func NewServer(h *Handler) *Server { return &Server{h: h, conns: map[net.Conn]struct{}{}} }

// Serve accepts connections on ln until Close.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return net.ErrClosed
	}
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.ServeConn(c)
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
}

// ServeConn runs one session on c until the client disconnects.
func (s *Server) ServeConn(c net.Conn) {
	defer c.Close()
	var wmu sync.Mutex
	sess := s.h.NewSession(func(b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return WriteFrame(c, b)
	})
	defer sess.Close()
	for {
		frame, err := ReadFrame(c)
		if err != nil {
			return
		}
		sess.Handle(frame)
	}
}

// Close stops all listeners and connections.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	for _, ln := range s.lns {
		ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
