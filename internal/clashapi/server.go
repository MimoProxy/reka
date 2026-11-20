// Package clashapi adapts Reka's native state and transactions for local Clash
// dashboards.
package clashapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/config/service"
)

type Options struct {
	Listen       string
	Token        string
	AllowOrigins []string
	Version      string
}

type Server struct {
	svc      *service.Service
	http     *http.Server
	ln       net.Listener
	cancel   context.CancelFunc
	opts     Options
	origins  map[string]bool
	streams  chan struct{}
	mu       sync.Mutex
	closing  bool
	requests sync.WaitGroup
	viewMu   sync.Mutex
	view     *projection
}

func Listen(svc *service.Service, opts Options) (*Server, error) {
	addr, err := netip.ParseAddrPort(opts.Listen)
	if err != nil || !addr.Addr().IsLoopback() {
		return nil, errors.New("Clash API listen must be a numeric loopback IP and port")
	}
	if len(opts.Token) < 16 || len(opts.Token) > 512 || strings.ContainsFunc(opts.Token, func(r rune) bool { return r < '!' || r > '~' }) {
		return nil, errors.New("Clash API requires a token of at least 16 printable non-space characters")
	}
	origins := map[string]bool{}
	for _, raw := range opts.AllowOrigins {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
			u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
			return nil, errors.New("Clash API origins must be exact HTTP(S) origins")
		}
		origins[raw] = true
	}
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{svc: svc, ln: ln, cancel: cancel, opts: opts, origins: origins, streams: make(chan struct{}, 32)}
	s.http = &http.Server{
		Handler:           s.authenticate(s.routes()),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	return s, nil
}

func (s *Server) Addr() string { return s.ln.Addr().String() }

func (s *Server) Serve() error {
	err := s.http.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Close() {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	s.cancel()
	_ = s.http.Close()
	_ = s.ln.Close()
	s.requests.Wait()
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"hello": "reka"})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"meta": true, "version": s.opts.Version, "name": "Reka"})
	})
	mux.HandleFunc("GET /configs", s.withProfile(s.configs))
	mux.HandleFunc("GET /proxies", s.withProfile(s.proxies))
	mux.HandleFunc("GET /proxies/{name}", s.withProfile(s.proxy))
	mux.HandleFunc("GET /proxies/{name}/delay", s.withProfile(s.delay))
	mux.HandleFunc("PUT /proxies/{name}", s.withProfile(s.selectMember))
	mux.HandleFunc("GET /group", s.withProfile(s.groups))
	mux.HandleFunc("GET /group/{name}", s.withProfile(s.group))
	mux.HandleFunc("GET /rules", s.withProfile(s.rules))
	mux.HandleFunc("GET /connections", s.connections)
	mux.HandleFunc("DELETE /connections", s.withProfile(s.closeConnections))
	mux.HandleFunc("DELETE /connections/{id}", s.withProfile(s.closeConnections))
	mux.HandleFunc("GET /traffic", s.traffic)
	mux.HandleFunc("GET /logs", s.logs)
	mux.HandleFunc("GET /memory", s.memory)
	for _, kind := range []string{"proxies", "rules"} {
		mux.HandleFunc("GET /providers/"+kind, s.withProfile(func(w http.ResponseWriter, r *http.Request) {
			s.providers(w, r, kind)
		}))
		mux.HandleFunc("GET /providers/"+kind+"/{name}", s.withProfile(func(w http.ResponseWriter, r *http.Request) {
			s.providers(w, r, kind)
		}))
		mux.HandleFunc("PUT /providers/"+kind+"/{name}", s.withProfile(func(w http.ResponseWriter, r *http.Request) {
			s.refreshProvider(w, r, kind)
		}))
	}
	return mux
}

func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.IsLoopback()
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !loopbackHost(r.Host) {
			writeError(w, http.StatusForbidden, "loopback Host required")
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" {
			if origin != "http://"+r.Host && !s.origins[origin] {
				writeError(w, http.StatusForbidden, "origin is not allowed")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
					w.Header().Set("Access-Control-Allow-Private-Network", "true")
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		token := ""
		if scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
			token = value
		} else if isWebSocket(r) {
			token = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.opts.Token)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			writeError(w, http.StatusServiceUnavailable, "controller is stopping")
			return
		}
		s.requests.Add(1)
		s.mu.Unlock()
		defer s.requests.Done()
		if !isWebSocket(r) {
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withProfile(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		release, err := s.svc.AcquireProfileCall("", 0)
		if err != nil {
			writeError(w, http.StatusConflict, "active profile changed")
			return
		}
		defer release()
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"message": message})
}

func readJSON(w http.ResponseWriter, r *http.Request, value any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}
