package sagernet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	ST "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	HY "github.com/sagernet/sing-quic/hysteria2"
	R "github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Use a distinct certificate from httptest's static identity, so swapping
// proxy/control pins fails rather than accidentally trusting the same leaf.
func hy2TestCertificate(t *testing.T) (string, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"proxy.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), hex.EncodeToString(pin[:])
}

type hy2EchoHandler struct{}

func (hy2EchoHandler) NewConnectionEx(_ context.Context, c net.Conn, _, _ M.Socksaddr, close N.CloseHandlerFunc) {
	go func() {
		_, err := io.Copy(c, c)
		c.Close()
		if close != nil {
			close(err)
		}
	}()
}
func (hy2EchoHandler) NewPacketConnectionEx(_ context.Context, c N.PacketConn, _, _ M.Socksaddr, close N.CloseHandlerFunc) {
	go func() {
		defer c.Close()
		for {
			buffer := buf.NewPacket()
			dst, err := c.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				if close != nil {
					close(err)
				}
				return
			}
			if err = c.WritePacket(buffer, dst); err != nil {
				return
			}
		}
	}()
}
func hy2WireService(t *testing.T, packet net.PacketConn, obfs ...string) *HY.Service[int] {
	t.Helper()
	cert, key, _ := hy2TestCertificate(t)
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { b.Close() })
	config, err := ST.NewServer(b.ctx, b.logger, option.InboundTLSOptions{Enabled: true, Certificate: []string{cert}, Key: []string{key}, ALPN: []string{"h3"}})
	if err != nil {
		t.Fatal(err)
	}
	options := HY.ServiceOptions{Context: b.ctx, Logger: b.logger, TLSConfig: config, Handler: hy2EchoHandler{}, UDPTimeout: time.Second}
	if len(obfs) > 0 {
		if obfs[0] == "gecko" {
			options.GeckoPassword = "obfs-secret"
		} else {
			options.SalamanderPassword = "obfs-secret"
		}
	}
	service, err := HY.NewService[int](options)
	if err != nil {
		t.Fatal(err)
	}
	service.UpdateUsers([]int{1}, []string{"hy-secret"})
	if err = service.Start(packet); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { service.Close(); packet.Close() })
	return service
}

// A small RFC 5389 fixture reports the real source address. No public STUN
// endpoint, node credentials or external network is used by these tests.
func realmSTUNServer(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, peer, err := c.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint32(buffer[4:8]) != 0x2112a442 {
				continue
			}
			response := make([]byte, 32)
			copy(response, buffer[:20])
			binary.BigEndian.PutUint16(response, 0x101)
			binary.BigEndian.PutUint16(response[2:], 12)
			binary.BigEndian.PutUint16(response[20:], 0x20)
			binary.BigEndian.PutUint16(response[22:], 8)
			response[25] = 1
			binary.BigEndian.PutUint16(response[26:], uint16(peer.Port)^0x2112)
			ip := peer.IP.To4()
			for i := 0; i < 4; i++ {
				response[28+i] = ip[i] ^ response[4+i]
			}
			c.WriteToUDP(response, peer)
		}
	}()
	return c.LocalAddr().String()
}

func TestHysteriaRealmRealPunchTCPUDPIsolatedTLSAndTokenNegative(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	punch := R.NewPunchPacketConn(packet, 16)
	cert, key, proxyPin := hy2TestCertificate(t)
	bserver := New(Options{Logger: testLogger(t)})
	defer bserver.Close()
	config, err := ST.NewServer(bserver.ctx, bserver.logger, option.InboundTLSOptions{Enabled: true, Certificate: []string{cert}, Key: []string{key}, ALPN: []string{"h3"}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := HY.NewService[int](HY.ServiceOptions{Context: bserver.ctx, Logger: bserver.logger, TLSConfig: config, Handler: hy2EchoHandler{}, UDPTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service.UpdateUsers([]int{1}, []string{"hy-secret"})
	if err = service.Start(punch); err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	defer packet.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	responder := R.NewServerPuncher(ctx, punch)
	defer responder.Close()
	var blockedOnce sync.Once
	blocked := make(chan struct{})
	var authorized atomic.Int32
	clientCertificate, clientKey, _ := testClientCertificate(t)
	control := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "Bearer realm-token" {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v1/blocked/connect" {
			io.Copy(io.Discard, r.Body)
			blockedOnce.Do(func() { close(blocked) })
			<-r.Context().Done()
			return
		}
		if r.URL.Path != "/v1/test/connect" {
			http.NotFound(w, r)
			return
		}
		var request struct {
			Addresses []netip.AddrPort `json:"addresses"`
			Nonce     string           `json:"nonce"`
			Obfs      string           `json:"obfs"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		nonce, e1 := hex.DecodeString(request.Nonce)
		obfs, e2 := hex.DecodeString(request.Obfs)
		if e1 != nil || e2 != nil || len(nonce) != 16 || len(obfs) != 32 {
			http.Error(w, "bad metadata", 400)
			return
		}
		metadata := R.PunchMetadata{}
		copy(metadata.Nonce[:], nonce)
		copy(metadata.ObfuscationKey[:], obfs)
		authorized.Add(1)
		go func() { responder.Respond(ctx, request.Nonce, request.Addresses, metadata) }()
		json.NewEncoder(w).Encode(map[string]any{"addresses": []string{packet.LocalAddr().String()}, "nonce": request.Nonce, "obfs": request.Obfs})
	}))
	control.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	control.StartTLS()
	defer control.Close()
	controlDigest := sha256.Sum256(control.TLS.Certificates[0].Certificate[0])
	controlPin := hex.EncodeToString(controlDigest[:])
	stun := realmSTUNServer(t)
	for _, tc := range []struct {
		name, token, controlPin, proxyPin string
		valid                             bool
	}{
		{"valid", "realm-token", controlPin, proxyPin, true}, {"wrong-token", "wrong", controlPin, proxyPin, false}, {"wrong-control-pin", "realm-token", proxyPin, proxyPin, false}, {"wrong-proxy-pin", "realm-token", controlPin, controlPin, false},
		{"missing-control-identity", "realm-token", controlPin, proxyPin, false},
		{"control-insecure-scoped", "realm-token", "", proxyPin, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var protected atomic.Int32
			b := New(Options{Logger: testLogger(t), ProtectFD: func(int) error { protected.Add(1); return nil }})
			defer b.Close()
			up, down := uint64(62500), uint64(2000000)
			realmTLS := &TLSSpec{ServerName: "control.test", CertificatePin: tc.controlPin, Certificate: clientCertificate, PrivateKey: clientKey}
			if tc.name == "missing-control-identity" {
				realmTLS.Certificate, realmTLS.PrivateKey = "", ""
			}
			if tc.name == "control-insecure-scoped" {
				realmTLS.Insecure = true
			}
			out, err := b.NewOutbound("realm", ProxySpec{Type: "hysteria2", Password: "hy-secret", TLS: &TLSSpec{ServerName: "proxy.test", CertificatePin: tc.proxyPin}, UpBPS: &up, DownBPS: &down, Realm: &RealmSpec{ServerURL: control.URL, RealmID: "test", Token: tc.token, STUNServers: []string{stun}, TLS: realmTLS}})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := out.Dial(deadline, "tcp", "127.0.0.1:80")
			if !tc.valid {
				if err == nil {
					c.Close()
					t.Fatal("invalid Realm authentication accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			c.Write([]byte("punch"))
			reply := make([]byte, 5)
			if _, err = io.ReadFull(c, reply); err != nil || string(reply) != "punch" {
				t.Fatal("Realm TCP", err)
			}
			udp, err := out.out.ListenPacket(deadline, M.ParseSocksaddr("127.0.0.1:53"))
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			udp.SetDeadline(time.Now().Add(time.Second))
			udp.WriteTo([]byte("packet"), M.ParseSocksaddr("127.0.0.1:53"))
			buffer := make([]byte, 1500)
			n, _, err := udp.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != "packet" {
				t.Fatal("Realm UDP", err)
			}
			if protected.Load() < 2 {
				t.Fatal("Realm control and UDP sockets bypassed protection", protected.Load())
			}
			c.Close()
			udp.Close()
			before := protected.Load()
			out.out.(adapter.InterfaceUpdateListener).InterfaceUpdated(deadline)
			fresh, err := out.Dial(deadline, "tcp", "127.0.0.1:80")
			if err != nil {
				t.Fatal("Realm network recovery", err)
			}
			fresh.SetDeadline(time.Now().Add(time.Second))
			fresh.Write([]byte("reset"))
			_, err = io.ReadFull(fresh, reply)
			fresh.Close()
			if err != nil || string(reply) != "reset" || protected.Load() <= before {
				t.Fatal("Realm reset did not use fresh protected sockets", err)
			}

		})
	}
	if authorized.Load() < 2 {
		t.Fatal("control path was not exercised")
	}
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	out, err := b.NewOutbound("cancel", ProxySpec{Type: "hysteria2", Password: "hy-secret", TLS: &TLSSpec{ServerName: "proxy.test", CertificatePin: proxyPin}, Realm: &RealmSpec{ServerURL: control.URL, RealmID: "blocked", Token: "realm-token", STUNServers: []string{stun}, TLS: &TLSSpec{CertificatePin: controlPin, Certificate: clientCertificate, PrivateKey: clientKey}}})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	finished := make(chan error, 1)
	go func() {
		c, err := out.Dial(context.Background(), "tcp", "127.0.0.1:80")
		if c != nil {
			c.Close()
		}
		finished <- err
	}()
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("Realm control request did not start")
	}
	out.Close()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("closed Realm request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("node close did not cancel Realm control request")
	}

}

// Preserve one server-side QUIC endpoint while packets arrive on several
// advertised UDP ports, as with server DNAT. Record the actual destination
// ports so successful traffic alone cannot be mistaken for a hopping pass.
type hoppingFront struct {
	mu       sync.Mutex
	latest   net.PacketConn
	peer     net.Addr
	seen     map[string]bool
	sockets  []net.PacketConn
	upstream *net.UDPConn
}

func newHoppingFront(t *testing.T, target net.Addr) *hoppingFront {
	t.Helper()
	up, err := net.DialUDP("udp4", nil, target.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	h := &hoppingFront{seen: map[string]bool{}, upstream: up}
	for i := 0; i < 3; i++ {
		c, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		h.sockets = append(h.sockets, c)
		go func() {
			buffer := make([]byte, 65535)
			for {
				n, peer, err := c.ReadFrom(buffer)
				if err != nil {
					return
				}
				h.mu.Lock()
				h.latest, h.peer = c, peer
				h.seen[c.LocalAddr().String()] = true
				h.mu.Unlock()
				up.Write(buffer[:n])
			}
		}()
	}
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, err := up.Read(buffer)
			if err != nil {
				return
			}
			h.mu.Lock()
			c, peer := h.latest, h.peer
			h.mu.Unlock()
			if c != nil {
				c.WriteTo(buffer[:n], peer)
			}
		}
	}()
	t.Cleanup(func() {
		for _, c := range h.sockets {
			c.Close()
		}
		up.Close()
	})
	return h
}
func TestHysteriaPortHoppingRealTCPUDP(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hy2WireService(t, packet)
	front := newHoppingFront(t, packet.LocalAddr())
	ports := make([]string, 0, 3)
	for _, c := range front.sockets {
		port := c.LocalAddr().(*net.UDPAddr).Port
		ports = append(ports, fmt.Sprintf("%d:%d", port, port))
	}
	options, _ := json.Marshal(map[string]any{"server_ports": ports, "hop_interval": "5s", "hop_interval_max": "5s"})
	var protected atomic.Int32
	b := New(Options{Logger: testLogger(t), ProtectFD: func(int) error { protected.Add(1); return nil }})
	defer b.Close()
	out, err := b.NewOutbound("hopping", ProxySpec{Type: "hysteria2", Server: "127.0.0.1", Password: "hy-secret", TLS: &TLSSpec{ServerName: "proxy.test", Insecure: true}, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := out.Dial(ctx, "tcp", "127.0.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	udp, err := out.out.ListenPacket(ctx, M.ParseSocksaddr("127.0.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(20 * time.Second))
	for i := 0; i < 60; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 1000)
		if _, err = c.Write(payload); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(payload))
		if _, err = io.ReadFull(c, reply); err != nil || !bytes.Equal(payload, reply) {
			t.Fatal("TCP across hops", err)
		}
		udp.WriteTo(payload, M.ParseSocksaddr("127.0.0.1:53"))
		buffer := make([]byte, 1500)
		n, _, err := udp.ReadFrom(buffer)
		if err != nil || !bytes.Equal(payload, buffer[:n]) {
			t.Fatal("UDP across hops", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	front.mu.Lock()
	seen := len(front.seen)
	front.mu.Unlock()
	if seen < 2 || protected.Load() < 2 {
		t.Fatal("no actual protected port hop observed", seen, protected.Load())
	}
}

func TestHysteriaExactBandwidthAdvertisedWithoutMbpsRounding(t *testing.T) {
	cert, key, _ := hy2TestCertificate(t)
	bserver := New(Options{Logger: testLogger(t)})
	defer bserver.Close()
	config, err := ST.NewServer(bserver.ctx, bserver.logger, option.InboundTLSOptions{Enabled: true, Certificate: []string{cert}, Key: []string{key}, ALPN: []string{"h3"}})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 1)
	service, err := HY.NewService[int](HY.ServiceOptions{Context: bserver.ctx, Logger: bserver.logger, TLSConfig: config, Handler: hy2EchoHandler{}, MasqueradeHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Hysteria-CC-RX")
		http.Error(w, "expected test rejection", http.StatusForbidden)
	})})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Start(packet); err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	defer packet.Close()
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	up, down := uint64(62500), uint64(93751)
	out, err := b.NewOutbound("exact", ProxySpec{Type: "hysteria2", Server: "127.0.0.1", Port: uint16(packet.LocalAddr().(*net.UDPAddr).Port), Password: "capture", TLS: &TLSSpec{ServerName: "proxy.test", Insecure: true}, UpBPS: &up, DownBPS: &down})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := out.Dial(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		c.Close()
		t.Fatal("fixture should reject auth")
	}
	select {
	case value := <-seen:
		if value != "93751" {
			t.Fatal("bandwidth was rounded or disabled", value)
		}
	case <-time.After(time.Second):
		t.Fatal("bandwidth header was not transmitted")
	}
}

func TestHysteriaObfsTCPUDPAndWrongPassword(t *testing.T) {
	for _, kind := range []string{"salamander", "gecko"} {
		t.Run(kind, func(t *testing.T) {
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			hy2WireService(t, packet, kind)
			for _, correct := range []bool{true, false} {
				password := "obfs-secret"
				if !correct {
					password = "wrong"
				}
				options, _ := json.Marshal(map[string]any{"obfs": map[string]any{"type": kind, "password": password}})
				b := New(Options{Logger: testLogger(t)})
				defer b.Close()
				out, err := b.NewOutbound("obfs", ProxySpec{Type: "hysteria2", Server: "127.0.0.1", Port: uint16(packet.LocalAddr().(*net.UDPAddr).Port), Password: "hy-secret", TLS: &TLSSpec{ServerName: "proxy.test", Insecure: true}, Options: options})
				if err != nil {
					t.Fatal(err)
				}
				defer out.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				c, err := out.Dial(ctx, "tcp", "127.0.0.1:80")
				if !correct {
					cancel()
					if err == nil {
						c.Close()
						t.Fatal("wrong obfs password accepted")
					}
					continue
				}
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				c.SetDeadline(time.Now().Add(time.Second))
				c.Write([]byte("obfs"))
				reply := make([]byte, 4)
				_, err = io.ReadFull(c, reply)
				c.Close()
				if err != nil || string(reply) != "obfs" {
					cancel()
					t.Fatal(err)
				}
				udp, err := out.out.ListenPacket(ctx, M.ParseSocksaddr("127.0.0.1:53"))
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				udp.SetDeadline(time.Now().Add(time.Second))
				udp.WriteTo([]byte("udp"), M.ParseSocksaddr("127.0.0.1:53"))
				buffer := make([]byte, 1500)
				n, _, err := udp.ReadFrom(buffer)
				udp.Close()
				cancel()
				if err != nil || string(buffer[:n]) != "udp" {
					t.Fatal(err)
				}
			}
		})
	}
}
