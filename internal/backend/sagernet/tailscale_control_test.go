//go:build with_gvisor && !ios

package sagernet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/testnet"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/tailscale/control/controlhttp/controlhttpserver"
	"github.com/sagernet/tailscale/derp/derpserver"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/tsnet"
	"github.com/sagernet/tailscale/types/key"
	"github.com/sagernet/tailscale/types/logger"
	"github.com/sagernet/tailscale/util/zstdframe"
	"golang.org/x/net/http2"
)

const (
	testTailnetLoginURL = "https://login.example.test/authorize"
	testTailnetAuthKey  = "test-auth-key"
	testTailnetRegion   = 901
)

// The pinned fork ships the Noise transport and DERP server. This control
// server handles registration and map updates on those real transports.
type testTailnet struct {
	url     string
	derpMap *tailcfg.DERPMap

	mu      sync.Mutex
	nodes   []*tailcfg.Node
	updated chan struct{}
}

func tailnetTestHTTP(t *testing.T, handler http.Handler, secure bool) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("loopback sockets unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	if secure {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

func newTestTailnet(t *testing.T) *testTailnet {
	t.Helper()
	relay := derpserver.New(key.NewNode(), logger.Discard)
	t.Cleanup(func() { relay.Close() })
	relayServer := tailnetTestHTTP(t, derpserver.Handler(relay), true)
	relayAddress := relayServer.Listener.Addr().(*net.TCPAddr).AddrPort()

	control := &testTailnet{
		updated: make(chan struct{}),
		derpMap: &tailcfg.DERPMap{
			OmitDefaultRegions: true,
			Regions: map[int]*tailcfg.DERPRegion{testTailnetRegion: {
				RegionID: testTailnetRegion, RegionCode: "test", RegionName: "Test relay",
				Nodes: []*tailcfg.DERPNode{{
					Name: "test-relay", RegionID: testTailnetRegion,
					HostName: relayAddress.Addr().String(), IPv4: relayAddress.Addr().String(), IPv6: "none",
					DERPPort: int(relayAddress.Port()), STUNPort: -1,
					CertName: fmt.Sprintf("sha256-raw:%x", sha256.Sum256(relayServer.Certificate().Raw)),
				}},
			}},
		},
	}
	controlKey := key.NewMachine()
	noise := &http2.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /key", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tailcfg.OverTLSPublicKeyResponse{PublicKey: controlKey.Public()})
	})
	mux.HandleFunc("POST /ts2021", func(w http.ResponseWriter, r *http.Request) {
		conn, err := controlhttpserver.AcceptHTTP(r.Context(), w, r, controlKey, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		handlers := http.NewServeMux()
		handlers.HandleFunc("POST /machine/register", func(w http.ResponseWriter, r *http.Request) {
			control.register(w, r, conn.Peer())
		})
		handlers.HandleFunc("POST /machine/map", control.serveMap)
		noise.ServeConn(conn, &http2.ServeConnOpts{Context: r.Context(), Handler: handlers})
	})
	control.url = tailnetTestHTTP(t, mux, false).URL
	return control
}

func (c *testTailnet) register(w http.ResponseWriter, r *http.Request, machine key.MachinePublic) {
	var request tailcfg.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.Auth == nil || request.Auth.AuthKey != testTailnetAuthKey {
		_ = json.NewEncoder(w).Encode(tailcfg.RegisterResponse{AuthURL: testTailnetLoginURL})
		return
	}
	c.mu.Lock()
	if !slices.ContainsFunc(c.nodes, func(node *tailcfg.Node) bool { return node.Key == request.NodeKey }) {
		id := len(c.nodes) + 1
		address := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, byte(id)}), 32)
		online := true
		c.nodes = append(c.nodes, &tailcfg.Node{
			ID: tailcfg.NodeID(id), StableID: tailcfg.StableNodeID(fmt.Sprint(id)), User: 1,
			Name: request.Hostinfo.Hostname + ".tailnet.test.", Hostinfo: request.Hostinfo.View(),
			Key: request.NodeKey, Machine: machine, Addresses: []netip.Prefix{address},
			HomeDERP: testTailnetRegion, Online: &online, MachineAuthorized: true, Cap: request.Version,
		})
	}
	c.mu.Unlock()
	_ = json.NewEncoder(w).Encode(tailcfg.RegisterResponse{
		User: tailcfg.User{ID: 1}, Login: tailcfg.Login{ID: 1, LoginName: "test@tailnet.test"}, MachineAuthorized: true,
	})
}

func (c *testTailnet) serveMap(w http.ResponseWriter, r *http.Request) {
	var request tailcfg.MapRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for {
		c.mu.Lock()
		index := slices.IndexFunc(c.nodes, func(node *tailcfg.Node) bool { return node.Key == request.NodeKey })
		if index == -1 {
			c.mu.Unlock()
			http.Error(w, "unknown node", http.StatusNotFound)
			return
		}
		node := c.nodes[index]
		// The test control server approves all advertised subnet routes.
		routes := node.PrimaryRoutes
		if !request.Stream && request.Hostinfo != nil {
			routes = request.Hostinfo.RoutableIPs
		}
		discoKey := node.DiscoKey
		if !request.DiscoKey.IsZero() {
			discoKey = request.DiscoKey
		}
		if node.DiscoKey != discoKey || !slices.Equal(node.PrimaryRoutes, routes) {
			node.DiscoKey = discoKey
			node.PrimaryRoutes = routes
			node.AllowedIPs = append(slices.Clone(node.Addresses), routes...)
			close(c.updated)
			c.updated = make(chan struct{})
		}
		update := c.updated
		response := tailcfg.MapResponse{
			Node: node.Clone(), DERPMap: c.derpMap, Domain: "tailnet.test",
			PacketFilter: tailcfg.FilterAllowAll, UserProfiles: []tailcfg.UserProfile{{ID: 1, LoginName: "test@tailnet.test"}},
		}
		for peerIndex, peer := range c.nodes {
			if peerIndex != index && !peer.DiscoKey.IsZero() {
				response.Peers = append(response.Peers, peer.Clone())
			}
		}
		c.mu.Unlock()
		if request.OmitPeers && !request.Stream && !request.ReadOnly {
			return
		}
		body, err := json.Marshal(response)
		if err != nil {
			return
		}
		if request.Compress == "zstd" {
			body = zstdframe.AppendEncode(nil, body)
		}
		frame := binary.LittleEndian.AppendUint32(nil, uint32(len(body)))
		if _, err := w.Write(append(frame, body...)); err != nil || !request.Stream {
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-update:
		}
	}
}

func waitTailscaleState(t *testing.T, ctx context.Context, node TailscaleNode, state string, withPeer bool) api.TailscaleStatus {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		status := node.Status()
		if status.State == state && (!withPeer || len(status.Peers) > 0) &&
			(state != api.TailscaleNeedsLogin || status.AuthURL != "") {
			return status
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for Tailscale state %q: %+v", state, status)
		case <-ticker.C:
		}
	}
}

func TestTailscalePeer(t *testing.T) {
	control := newTestTailnet(t)
	backend := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { backend.Close() })
	var inboundRoutes atomic.Int32
	backend.SetRoute(func(context.Context, Metadata) Route {
		inboundRoutes.Add(1)
		return Route{}
	})
	node, err := backend.NewTailscaleNode("tailscale/test", TailscaleOptions{
		StateDirectory: t.TempDir(), ControlURL: control.url, AuthKey: testTailnetAuthKey,
		Hostname: "reka-test", AcceptRoutes: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { node.Close() })
	out := backend.NewTailscaleOutbound("tailscale/test", node)
	t.Cleanup(func() { out.Close() })
	peer := &tsnet.Server{
		Dir: t.TempDir(), Hostname: "echo-test", ControlURL: control.url, AuthKey: testTailnetAuthKey, UserLogf: logger.Discard,
	}
	t.Cleanup(func() { peer.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	subnet := netip.MustParsePrefix("192.0.2.0/24")
	if err := peer.Start(); err != nil {
		t.Fatal("start echo peer:", err)
	}
	if _, err := peer.ExportLocalBackend().EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{AdvertiseRoutes: []netip.Prefix{subnet}}, AdvertiseRoutesSet: true,
	}); err != nil {
		t.Fatal("advertise subnet:", err)
	}
	peerStatus, err := peer.Up(ctx)
	if err != nil {
		t.Fatal("start echo peer:", err)
	}
	peerIP := peerStatus.TailscaleIPs[0]
	status := waitTailscaleState(t, ctx, node, api.TailscaleRunning, true)
	if len(status.TailscaleIPs) == 0 || !slices.Contains(status.Peers[0].TailscaleIPs, peerIP) ||
		status.Peers[0].Hostname != "echo-test" || !status.Peers[0].Online {
		t.Fatalf("unexpected Tailscale status: %+v", status)
	}
	target := netip.AddrPortFrom(peerIP, 27001)
	subnetTarget := netip.MustParseAddrPort("192.0.2.20:27001")
	// Keep the peer's temporary subnet IP installed until the copy finishes.
	removeEcho := peer.RegisterFallbackTCPHandler(func(_, dst netip.AddrPort) (func(net.Conn), bool) {
		if dst != target && dst != subnetTarget {
			return nil, false
		}
		return func(conn net.Conn) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}, true
	})
	t.Cleanup(removeEcho)
	assertTailnetTCPEcho(t, ctx, out, target)
	assertTailnetTCPEcho(t, ctx, out, subnetTarget)

	packetListener, err := peer.ListenPacket("udp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packetListener.Close() })
	go func() {
		var buffer [64]byte
		n, source, err := packetListener.ReadFrom(buffer[:])
		if err == nil {
			_, _ = packetListener.WriteTo(buffer[:n], source)
		}
	}()

	deadline, _ := ctx.Deadline()
	var buffer [8]byte
	packet, err := out.out.ListenPacket(ctx, M.SocksaddrFrom(target.Addr(), target.Port()))
	if err != nil {
		t.Fatal("Tailscale UDP open:", err)
	}
	defer packet.Close()
	if err := packet.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.WriteTo([]byte("udp echo"), net.UDPAddrFromAddrPort(target)); err != nil {
		t.Fatal(err)
	}
	n, source, err := packet.ReadFrom(buffer[:])
	if err != nil || string(buffer[:n]) != "udp echo" || source.String() != target.String() {
		t.Fatalf("Tailscale UDP echo %q from %v: %v", buffer[:n], source, err)
	}

	// The same flow socket must reach a second destination, not only the
	// one it was opened for.
	second := netip.AddrPortFrom(target.Addr(), target.Port()+1)
	secondListener, err := peer.ListenPacket("udp", second.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secondListener.Close() })
	go func() {
		var buffer [64]byte
		for {
			n, source, err := secondListener.ReadFrom(buffer[:])
			if err != nil {
				return
			}
			_, _ = secondListener.WriteTo(buffer[:n], source)
		}
	}()
	// UDP may drop the first datagram to a new port on slow runners, so
	// resend until the echo arrives or the test deadline passes.
	for {
		if _, err := packet.WriteTo([]byte("udp two!"), net.UDPAddrFromAddrPort(second)); err != nil {
			t.Fatal(err)
		}
		attempt := time.Now().Add(time.Second)
		if attempt.After(deadline) {
			attempt = deadline
		}
		if err := packet.SetReadDeadline(attempt); err != nil {
			t.Fatal(err)
		}
		n, source, err = packet.ReadFrom(buffer[:])
		if err == nil {
			if string(buffer[:n]) != "udp two!" || source.String() != second.String() {
				t.Fatalf("Tailscale UDP second destination %q from %v", buffer[:n], source)
			}
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("Tailscale UDP second destination: %v", err)
		}
	}
	if err := packet.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	// The exchange established the peer path in both directions. A host
	// listener would accept these attempts if they escaped the tailnet stack.
	_, hostPacket := testnet.ListenTCPUDP(t)
	inboundCtx, cancelInbound := context.WithTimeout(ctx, time.Second)
	defer cancelInbound()
	destination := netip.AddrPortFrom(status.TailscaleIPs[0], hostPacket.LocalAddr().(*net.UDPAddr).AddrPort().Port()).String()
	inboundUDP, err := peer.Dial(inboundCtx, "udp", destination)
	if err != nil {
		t.Fatal("peer UDP setup:", err)
	}
	defer inboundUDP.Close()
	if _, err := inboundUDP.Write([]byte("inbound UDP")); err != nil {
		t.Fatal("peer UDP write:", err)
	}
	inbound, err := peer.Dial(inboundCtx, "tcp", destination)
	if err == nil {
		inbound.Close()
		t.Fatal("remote peer opened an inbound Tailscale TCP connection")
	}
	if err := hostPacket.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := hostPacket.ReadFrom(buffer[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unsolicited Tailscale UDP reached the host: %d bytes, %v", n, err)
	}
	if inboundRoutes.Load() != 0 {
		t.Fatal("the remote peer reached the Reka rule engine")
	}
}

func assertTailnetTCPEcho(t *testing.T, ctx context.Context, outbound *Outbound, target netip.AddrPort) {
	t.Helper()
	conn, err := outbound.Dial(ctx, "tcp", target.String())
	if err != nil {
		t.Fatalf("Tailscale TCP dial to %v: %v", target, err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "tcp echo"); err != nil {
		t.Fatal(err)
	}
	var buffer [8]byte
	if _, err := io.ReadFull(conn, buffer[:]); err != nil || string(buffer[:]) != "tcp echo" {
		t.Fatalf("Tailscale TCP echo from %v got %q: %v", target, buffer, err)
	}
}

func TestTailscaleInteractiveLogin(t *testing.T) {
	for _, name := range []string{"TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET", "TS_CLIENT_ID", "TS_ID_TOKEN", "TS_AUDIENCE"} {
		t.Setenv(name, "")
	}
	control := newTestTailnet(t)
	backend := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { backend.Close() })
	node, err := backend.NewTailscaleNode("tailscale/test", TailscaleOptions{
		StateDirectory: t.TempDir(), ControlURL: control.url, Hostname: "reka-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { node.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	status := waitTailscaleState(t, ctx, node, api.TailscaleNeedsLogin, false)
	if status.AuthURL != testTailnetLoginURL {
		t.Fatalf("authentication URL = %q, want %q", status.AuthURL, testTailnetLoginURL)
	}
	out := backend.NewTailscaleOutbound("tailscale/test", node)
	defer out.Close()
	dialCtx, cancelDial := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancelDial()
	target := M.ParseSocksaddr("100.64.0.1:27001")
	conn, err := out.Dial(dialCtx, "tcp", target.String())
	if conn != nil {
		conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), api.TailscaleNeedsLogin) || dialCtx.Err() != nil {
		t.Fatalf("unauthenticated TCP dial = %v, context = %v", err, dialCtx.Err())
	}
	packet, err := out.out.ListenPacket(dialCtx, target)
	if packet != nil {
		packet.Close()
	}
	if err == nil || !strings.Contains(err.Error(), api.TailscaleNeedsLogin) || dialCtx.Err() != nil {
		t.Fatalf("unauthenticated UDP dial = %v, context = %v", err, dialCtx.Err())
	}
}
