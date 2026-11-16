package acceptance

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	JT "github.com/metacubex/jls-tls"
	VL "github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type carrierTestRelay struct{}

func (carrierTestRelay) NewConnectionEx(_ context.Context, c net.Conn, _, destination M.Socksaddr, done N.CloseHandlerFunc) {
	go func() {
		defer c.Close()
		if !destination.IsIP() || !destination.Addr.IsLoopback() {
			return
		}
		up, err := net.DialTimeout("tcp", destination.String(), time.Second)
		if err != nil {
			return
		}
		defer up.Close()
		go func() {
			if _, err := io.Copy(up, c); err != nil {
				up.Close()
			} else {
				up.(*net.TCPConn).CloseWrite()
			}
		}()
		_, err = io.Copy(c, up)
		if done != nil {
			done(err)
		}
	}()
}
func (carrierTestRelay) NewPacketConnectionEx(_ context.Context, c N.PacketConn, _, _ M.Socksaddr, done N.CloseHandlerFunc) {
	c.Close()
	if done != nil {
		done(nil)
	}
}

func TestTLSCarrierCredentialRotationDrainsExistingFlow(t *testing.T) {
	certServer := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	certServer.StartTLS()
	certificate := certServer.TLS.Certificates[0]
	certServer.Close()
	config := &JT.Config{Certificates: []JT.Certificate{{Certificate: certificate.Certificate, PrivateKey: certificate.PrivateKey}}, MinVersion: JT.VersionTLS13, JLSConfig: &JT.JLSConfig{Enable: true, ServerName: "carrier.test", Users: []JT.JLSUser{{Username: "old-user", Password: "old-password"}, {Username: "new-user", Password: "new-password"}}}}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var sockets []net.Conn
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range sockets {
			c.Close()
		}
	})
	service := VL.NewService[string](nil, carrierTestRelay{})
	service.UpdateUsers([]string{"test"}, []string{"b831381d-6324-4d53-ad4f-8cda48b30811"}, []string{""})
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			sockets = append(sockets, raw)
			mu.Unlock()
			go func() {
				c := JT.Server(raw, config)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				err := c.HandshakeContext(ctx)
				cancel()
				if err != nil {
					raw.Close()
					return
				}
				if err = service.NewConnection(context.Background(), c, M.Socksaddr{}, nil); err != nil {
					c.Close()
				}
			}()
		}
	}()
	profile := fmt.Sprintf(`schema-version: 1
outbounds:
 - {id: secured, type: vless, server: 127.0.0.1, port: %d, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: {server-name: carrier.test, carrier: {type: jls, username: old-user, password: old-password}}}
rules: [{id: final, match: {all: true}, outbound: secured}]
`, listener.Addr().(*net.TCPAddr).Port)
	h := newHarness(t, profile)
	target := echoServer(t)
	oldInstance := h.engine().OutboundInstance("secured")
	old := openStream(t, h.proxy(), target)
	h.mustCommit(patch("/outbounds/secured/tls/carrier/username", `"new-user"`, "/outbounds/secured/tls/carrier/password", `"new-password"`))
	if h.engine().OutboundInstance("secured") == oldInstance || !oldInstance.Lease().Retired() {
		t.Fatal("credential rotation reused old carrier")
	}
	fresh := openStream(t, h.proxy(), target)
	if err := old.finish(); err != nil {
		t.Fatal("security rotation interrupted old flow", err)
	}
	if err := fresh.finish(); err != nil {
		t.Fatal("new credentials did not work", err)
	}
	waitFor(t, "old security carrier drained", 5*time.Second, func() bool { return h.engine().Status().Draining == 0 })
	if h.engine().Status().Forced != 0 {
		t.Fatal("security rotation forced old connection closed")
	}
}
