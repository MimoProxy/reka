// referencepeer is a test fixture in the separate pinned-reference module.
// It unwraps the original peer protocols and forwards to a loopback SS node.
// It is never linked into Reka product binaries.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	MH "github.com/metacubex/http"
	SH "github.com/metacubex/mihomo/transport/shadowtls"
	OB "github.com/metacubex/mihomo/transport/simple-obfs"
	WS "github.com/metacubex/mihomo/transport/vmess"
	VM "github.com/metacubex/sing-vmess"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/smux"
	MT "github.com/metacubex/tls"
)

type request struct {
	Type, Mode, Forward, Password string
	Version                       int
	Mux, TLS, HTTPUpgrade         bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	var config request
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 8192)).Decode(&config); err != nil {
		return err
	}
	addr, err := netipLoopback(config.Forward)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	forward := handler{target: addr}
	pin := ""
	var serve func() error
	switch config.Type {
	case "obfs":
		serve = func() error {
			for {
				c, err := listener.Accept()
				if err != nil {
					return err
				}
				if config.Mode == "tls" {
					c = OB.NewTLSObfsServer(c)
				} else {
					c = OB.NewHTTPObfsServer(c)
				}
				forward.accept(c)
			}
		}
	case "shadow-tls":
		target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		if config.Version == 1 {
			target.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
		}
		target.StartTLS()
		defer target.Close()
		digest := sha256.Sum256(target.TLS.Certificates[0].Certificate[0])
		pin = hex.EncodeToString(digest[:])
		peer, err := SH.NewServerConfig(config.Version, config.Password, []SH.User{{Name: "test", Password: config.Password}}, SH.HandshakeConfig{Server: target.Listener.Addr().String(), DialContext: (&net.Dialer{}).DialContext}, nil, false, SH.WildcardSNIOff)
		if err != nil {
			return err
		}
		serve = func() error {
			for {
				raw, err := listener.Accept()
				if err != nil {
					return err
				}
				go func() {
					c, err := SH.Server(context.Background(), raw, peer)
					if err != nil {
						raw.Close()
						return
					}
					forward.accept(c)
				}()
			}
		}
	case "v2ray-plugin", "gost-plugin":
		server := &MH.Server{Handler: MH.HandlerFunc(func(w MH.ResponseWriter, r *MH.Request) {
			if r.URL.Path != "/plugin" || r.Host != "plugin.test" {
				MH.Error(w, "invalid websocket target", 400)
				return
			}
			c, err := WS.StreamUpgradedWebsocketConn(w, r)
			if err != nil {
				return
			}
			if !config.Mux {
				forward.accept(c)
				return
			}
			if config.Type == "v2ray-plugin" {
				go func() { VM.HandleMuxConnection(context.Background(), c, M.Metadata{}, forward); c.Close() }()
				return
			}
			options := smux.DefaultConfig()
			options.KeepAliveDisabled = true
			session, err := smux.Server(c, options)
			if err != nil {
				c.Close()
				return
			}
			go func() {
				defer session.Close()
				for {
					stream, err := session.AcceptStream()
					if err != nil {
						return
					}
					forward.accept(stream)
				}
			}()
		})}
		if config.TLS {
			certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			certificate := certificateServer.TLS.Certificates[0]
			certificateServer.Close()
			server.TLSConfig = &MT.Config{Certificates: []MT.Certificate{{Certificate: certificate.Certificate, PrivateKey: certificate.PrivateKey}}}
			digest := sha256.Sum256(certificate.Certificate[0])
			pin = hex.EncodeToString(digest[:])
			go server.ServeTLS(listener, "", "")
		} else {
			go server.Serve(listener)
		}

		defer server.Close()
		serve = func() error { select {} }
	default:
		return fmt.Errorf("unsupported fixture protocol")
	}
	if err = json.NewEncoder(os.Stdout).Encode(map[string]string{"address": listener.Addr().String(), "pin": pin}); err != nil {
		return err
	}
	return serve()
}
func netipLoopback(address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("reference fixture accepts only loopback forwarding")
	}
	return address, nil
}

type handler struct{ target string }

func (h handler) accept(c net.Conn) {
	go func() {
		defer c.Close()
		up, err := net.DialTimeout("tcp", h.target, time.Second)
		if err != nil {
			return
		}
		defer up.Close()
		go func() { copyStream(up, c); up.Close() }()
		copyStream(c, up)
	}()
}
func (h handler) NewConnection(_ context.Context, c net.Conn, _ M.Metadata) error {
	h.accept(c)
	return nil
}
func (h handler) NewPacketConnection(_ context.Context, c N.PacketConn, _ M.Metadata) error {
	return c.Close()
}
func (h handler) NewError(context.Context, error) {}
func copyStream(dst io.Writer, src io.Reader) {
	// Exercise the reference's ordinary protocol writer. Its own optimized
	// read-wait paths are unrelated to the Reka carrier under test.
	buffer := make([]byte, 32768)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			written, e := dst.Write(buffer[:n])
			if e != nil || written != n {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
