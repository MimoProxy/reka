package generation

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	quic "github.com/sagernet/quic-go"
)

func TestRecommendBlockQUIC(t *testing.T) {
	ok := IPCheck{Status: ipCheckOK}
	failed := IPCheck{Status: ipCheckFailed}
	for _, tc := range []struct {
		name      string
		local     IPCheck
		node      *IPCheck
		nodeWorks bool
		want      QUICRecommendation
	}{
		{"local QUIC blocked", failed, &ok, true, QUICRecommendation{"all", "local-quic-blocked"}},
		{"node QUIC blocked", ok, &failed, true, QUICRecommendation{"proxy", "node-quic-unavailable"}},
		{"both paths support QUIC", ok, &ok, false, QUICRecommendation{"off", "quic-ok"}},
		{"node offline", ok, &failed, false, QUICRecommendation{}},
		{"no node", ok, nil, false, QUICRecommendation{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recommendBlockQUIC(tc.local, tc.node, tc.nodeWorks)
			if tc.want.BlockQUIC == "" {
				if got != nil {
					t.Fatalf("unexpected recommendation %+v", got)
				}
				return
			}
			if got == nil || *got != tc.want {
				t.Fatalf("recommendation = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestRecommendIPVersion(t *testing.T) {
	families := func(ipv4, ipv6 string) IPFamilyChecks {
		return IPFamilyChecks{IPv4: IPCheck{Status: ipv4}, IPv6: IPCheck{Status: ipv6}}
	}
	dual := families(ipCheckOK, ipCheckOK)
	only4 := families(ipCheckOK, ipCheckFailed)
	only6 := families(ipCheckUnavailable, ipCheckOK)
	down := families(ipCheckFailed, ipCheckFailed)
	skipped := families(ipCheckSkipped, ipCheckSkipped)
	node4 := &IPCheckNode{Server: families(ipCheckOK, ipCheckUnavailable), Exit: only4}
	node6 := &IPCheckNode{Server: only6, Exit: only4}
	exit4 := &IPCheckNode{Server: dual, Exit: only4}
	for _, tc := range []struct {
		name    string
		local   IPFamilyChecks
		node    *IPCheckNode
		dnsMode string
		want    IPCheckRecommendation
	}{
		{"local IPv4 only", only4, node6, "normal", IPCheckRecommendation{"ipv4", "local-ipv6-unavailable"}},
		{"local IPv6 only", only6, node4, "normal", IPCheckRecommendation{"ipv6", "local-ipv4-unavailable"}},
		{"server has no IPv6 address", dual, node4, "redir-host", IPCheckRecommendation{"ipv4-prefer", "server-ipv4-only"}},
		{"server IPv6 dial failed", dual, &IPCheckNode{Server: only4, Exit: dual}, "fake-ip", IPCheckRecommendation{"ipv4-prefer", "server-ipv4-only"}},
		{"server IPv6 only", dual, node6, "normal", IPCheckRecommendation{"ipv6-prefer", "server-ipv6-only"}},
		{"exit IPv6 failed with real DNS", dual, exit4, "redir-host", IPCheckRecommendation{"ipv4", "exit-ipv6-unavailable"}},
		{"exit IPv6 unavailable with normal DNS", dual, &IPCheckNode{Server: skipped, Exit: node4.Server}, "normal", IPCheckRecommendation{"ipv4", "exit-ipv6-unavailable"}},
		{"exit IPv6 failed with fake IP", dual, exit4, "fake-ip", IPCheckRecommendation{"dual", "exit-ipv6-unavailable-fake-ip"}},
		{"local dual stack", dual, nil, "normal", IPCheckRecommendation{"dual", "dual-ok"}},
		{"dual stack with a node", dual, &IPCheckNode{Server: dual, Exit: dual}, "normal", IPCheckRecommendation{"dual", "dual-ok"}},
		{"dual exits without server dial", dual, &IPCheckNode{Server: skipped, Exit: dual}, "normal", IPCheckRecommendation{"dual", "dual-ok"}},
		{"both local families failed", down, node6, "normal", IPCheckRecommendation{}},
		{"both exit families failed", dual, &IPCheckNode{Server: dual, Exit: down}, "normal", IPCheckRecommendation{}},
		{"exit IPv6 only", dual, &IPCheckNode{Server: dual, Exit: only6}, "normal", IPCheckRecommendation{}},
		{"exit IPv6 unknown", dual, &IPCheckNode{Server: skipped, Exit: families(ipCheckOK, ipCheckSkipped)}, "normal", IPCheckRecommendation{}},
		{"server IPv6 unknown", dual, &IPCheckNode{Server: families(ipCheckOK, ipCheckSkipped), Exit: dual}, "normal", IPCheckRecommendation{"dual", "dual-ok"}},
		{"local IPv6 unknown", families(ipCheckOK, ipCheckSkipped), nil, "normal", IPCheckRecommendation{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recommendIPVersion(tc.local, tc.node, tc.dnsMode)
			if tc.want.IPVersion == "" {
				if got != nil {
					t.Fatalf("unexpected recommendation %+v", got)
				}
				return
			}
			if got == nil || *got != tc.want {
				t.Fatalf("recommendation = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestIPCheckServerAddressFamily(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	many := []netip.Addr{{}, ips[1], netip.MustParseAddr("::ffff:192.0.2.1")}
	var firstEight []string
	for i := 1; i <= 9; i++ {
		address := fmt.Sprintf("192.0.2.%d", i)
		many = append(many, netip.MustParseAddr(address))
		if i <= 8 {
			firstEight = append(firstEight, address)
		}
	}
	for _, tc := range []struct {
		name      string
		family    string
		target    compile.Outbound
		lookup    bool
		answers   []netip.Addr
		dnsErr    error
		dialAddr  string
		dialErr   error
		status    string
		reason    string
		addresses []string
	}{
		{name: "IPv4 literal", family: "ip4", target: compile.Outbound{Server: "192.0.2.1"}, dialAddr: "192.0.2.1:443", status: ipCheckOK, addresses: []string{"192.0.2.1"}},
		{name: "IPv6 literal", family: "ip6", target: compile.Outbound{Server: "2001:db8::1"}, dialAddr: "[2001:db8::1]:443", status: ipCheckOK, addresses: []string{"2001:db8::1"}},
		{name: "mapped literal", family: "ip4", target: compile.Outbound{Server: "::ffff:192.0.2.1"}, dialAddr: "192.0.2.1:443", status: ipCheckOK, addresses: []string{"192.0.2.1"}},
		{name: "IPv4 only literal", family: "ip6", target: compile.Outbound{Server: "192.0.2.1"}, status: ipCheckUnavailable, reason: "no address"},
		{name: "IPv6 only literal", family: "ip4", target: compile.Outbound{Server: "2001:db8::1"}, status: ipCheckUnavailable, reason: "no address"},
		{name: "hostname IPv4", family: "ip4", target: compile.Outbound{Server: "proxy.test"}, lookup: true, answers: ips,
			dialAddr: "192.0.2.1:443", status: ipCheckOK, addresses: []string{"192.0.2.1"}},
		{name: "deduplicate and cap answers", family: "ip4", target: compile.Outbound{Server: "proxy.test"}, lookup: true, answers: many,
			dialAddr: "192.0.2.1:443", status: ipCheckOK, addresses: firstEight},
		{name: "hostname IPv6 refused", family: "ip6", target: compile.Outbound{Server: "proxy.test"}, lookup: true, answers: ips,
			dialAddr: "[2001:db8::1]:443", dialErr: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, status: ipCheckFailed, reason: "refused", addresses: []string{"2001:db8::1"}},
		{name: "hostname without AAAA", family: "ip6", target: compile.Outbound{Server: "proxy.test"}, lookup: true, answers: ips[:1],
			status: ipCheckUnavailable, reason: "no address"},
		{name: "hostname not found", family: "ip4", target: compile.Outbound{Server: "proxy.test"}, lookup: true, dnsErr: &net.DNSError{IsNotFound: true},
			status: ipCheckUnavailable, reason: "no address"},
		{name: "DNS failure", family: "ip4", target: compile.Outbound{Server: "proxy.test"}, lookup: true, dnsErr: errors.New("resolver failed for proxy.test"),
			status: ipCheckFailed, reason: "dns"},
		{name: "hysteria address only", family: "ip6", target: compile.Outbound{Type: "hysteria2", Server: "proxy.test"}, lookup: true, answers: ips[1:],
			status: ipCheckSkipped, reason: "udp transport", addresses: []string{"2001:db8::1"}},
		{name: "tuic address missing", family: "ip6", target: compile.Outbound{Type: "tuic", Server: "192.0.2.1"},
			status: ipCheckUnavailable, reason: "no address"},
		{name: "tuic address only", family: "ip4", target: compile.Outbound{Type: "tuic", Server: "192.0.2.1"},
			status: ipCheckSkipped, reason: "udp transport", addresses: []string{"192.0.2.1"}},
		{name: "kcptun address only", family: "ip4", target: compile.Outbound{Type: "shadowsocks", Server: "192.0.2.1", Plugin: &model.SSPlugin{Type: "kcptun"}},
			status: ipCheckSkipped, reason: "udp transport", addresses: []string{"192.0.2.1"}},
		{name: "dialer proxy", family: "ip4", target: compile.Outbound{Server: "proxy.test", Dialer: &model.Dialer{Proxy: "parent"}},
			status: ipCheckSkipped, reason: "dialer proxy"},
		{name: "no server", family: "ip6", target: compile.Outbound{Type: "direct"}, status: ipCheckSkipped, reason: "no server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookupCalls, dialCalls := 0, 0
			lookup := func(_ context.Context, network, host string) ([]netip.Addr, error) {
				lookupCalls++
				if network != tc.family || host != tc.target.Server {
					t.Fatalf("lookup got %q %q", network, host)
				}
				return tc.answers, tc.dnsErr
			}
			dial := func(_ context.Context, network, address string) (net.Conn, error) {
				dialCalls++
				if network != "tcp" || address != tc.dialAddr {
					t.Fatalf("dial got %q %q, want tcp %s", network, address, tc.dialAddr)
				}
				if tc.dialErr != nil {
					return nil, tc.dialErr
				}
				conn, peer := net.Pipe()
				peer.Close()
				return conn, nil
			}
			tc.target.Port = 443
			got := ipCheckServer(t.Context(), tc.target, tc.family, lookup, dial)
			if got.Status != tc.status || got.Error != tc.reason {
				t.Fatalf("server check = %+v, want %s %q", got, tc.status, tc.reason)
			}
			if !slices.Equal(got.Addresses, tc.addresses) {
				t.Fatalf("addresses = %v, want %v", got.Addresses, tc.addresses)
			}
			if lookupCalls > 1 || (lookupCalls == 1) != tc.lookup || dialCalls > 1 || (dialCalls == 1) != (tc.dialAddr != "") {
				t.Fatalf("unexpected lookup and dial counts %d, %d", lookupCalls, dialCalls)
			}
			if (got.DelayMS != nil) != (dialCalls == 1) || got.DelayMS != nil && *got.DelayMS < 1 {
				t.Fatalf("unexpected delay %v after %d dials", got.DelayMS, dialCalls)
			}
		})
	}
}

func TestParseIPCheckBody(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		address string
		country string
	}{
		{"IPv4 trace", "fl=example\nip=192.0.2.1\nloc=SG\nhttp=http/2\n", "192.0.2.1", "SG"},
		{"IPv6 trace", "loc=US\r\nip=2001:0db8::1\r\n", "2001:db8::1", "US"},
		{"mapped address", "ip=::ffff:192.0.2.1\n", "192.0.2.1", ""},
		{"unknown country", "ip=192.0.2.1\nloc=XX\n", "192.0.2.1", ""},
		{"lowercase country", "ip=192.0.2.1\nloc=sg\n", "192.0.2.1", ""},
		{"malformed country", "ip=192.0.2.1\nloc=S1\n", "192.0.2.1", ""},
		{"invalid IP", "ip=300.0.2.1\nloc=GB\n", "", "GB"},
		{"scoped address", "ip=fe80::1%eth0\n", "", ""},
		{"plain IP", "  2001:db8::1\r\n", "2001:db8::1", ""},
		{"invalid plain text", "192.0.2.1, 192.0.2.2", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var want netip.Addr
			if tc.address != "" {
				want = netip.MustParseAddr(tc.address)
			}
			address, country := parseIPCheckBody(tc.body)
			if address != want || country != tc.country {
				t.Fatalf("parsed (%v, %q), want (%v, %q)", address, country, want, tc.country)
			}
		})
	}
}

func TestIPCheckNodeJSON(t *testing.T) {
	unavailable := IPCheck{Status: ipCheckUnavailable}
	node := IPCheckNode{
		Host: "proxy.test", Port: 443,
		Server: IPFamilyChecks{
			IPv4: IPCheck{Status: ipCheckOK, Addresses: []string{"192.0.2.1"}},
			IPv6: unavailable,
		},
		Exit: IPFamilyChecks{
			IPv4: IPCheck{Status: ipCheckOK, Addresses: []string{"192.0.2.2"}, Country: "SG"},
			IPv6: unavailable,
		},
	}
	for _, tt := range []struct {
		name    string
		node    IPCheckNode
		want    map[string]string
		omitted []string
	}{
		{"server", node, map[string]string{
			"host": `"proxy.test"`, "port": `443`, "udp": `false`,
			"server": `{"ipv4":{"status":"ok","addresses":["192.0.2.1"]},"ipv6":{"status":"unavailable"}}`,
			"exit":   `{"ipv4":{"status":"ok","addresses":["192.0.2.2"],"country":"SG"},"ipv6":{"status":"unavailable"}}`,
		}, nil},
		{"built-in", IPCheckNode{Type: "direct", UDP: true}, map[string]string{"udp": `true`}, []string{"host", "port"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.node)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]json.RawMessage
			if err := json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			for field, want := range tt.want {
				if got := string(wire[field]); got != want {
					t.Errorf("%s = %s, want %s", field, got, want)
				}
			}
			for _, field := range tt.omitted {
				if _, ok := wire[field]; ok {
					t.Errorf("unexpected field %s in %s", field, data)
				}
			}
		})
	}
}

func TestLocalTargets(t *testing.T) {
	if got, err := localTargets(nil, defaultLocal4, true); err != nil || len(got) != len(defaultLocal4) {
		t.Fatalf("defaults = %v, %v", got, err)
	}
	for _, targets := range defaultLocal4 {
		if _, err := localTargets([]string{targets}, nil, true); err != nil {
			t.Fatalf("default IPv4 target %s rejected: %v", targets, err)
		}
	}
	for _, targets := range defaultLocal6 {
		if _, err := localTargets([]string{targets}, nil, false); err != nil {
			t.Fatalf("default IPv6 target %s rejected: %v", targets, err)
		}
	}
	for name, test := range map[string]struct {
		targets []string
		ipv4    bool
	}{
		"hostname":     {[]string{"dns.example:443"}, true},
		"no port":      {[]string{"192.0.2.1"}, true},
		"zero port":    {[]string{"192.0.2.1:0"}, true},
		"wrong family": {[]string{"[2001:db8::1]:443"}, true},
		"mapped IPv4":  {[]string{"[::ffff:192.0.2.1]:443"}, false},
		"too many":     {[]string{"1.0.0.1:1", "1.0.0.2:1", "1.0.0.3:1", "1.0.0.4:1", "1.0.0.5:1", "1.0.0.6:1", "1.0.0.7:1", "1.0.0.8:1", "1.0.0.9:1"}, true},
	} {
		if _, err := localTargets(test.targets, nil, test.ipv4); err == nil {
			t.Errorf("%s: accepted %v", name, test.targets)
		}
	}
}

func TestQUICTargets(t *testing.T) {
	for _, defaults := range [][]string{defaultLocalQUIC, defaultNodeQUIC} {
		if got, err := quicTargets(nil, defaults); err != nil || len(got) != len(defaults) {
			t.Fatalf("defaults = %v, %v", got, err)
		}
	}
	mixed := []string{"127.0.0.1:443", "[::1]:443"}
	if got, err := quicTargets(mixed, nil); err != nil || len(got) != 2 || !got[0].Addr().Is4() || !got[1].Addr().Is6() {
		t.Fatalf("mixed address families = %v, %v", got, err)
	}
	for name, targets := range map[string][]string{
		"hostname":  {"dns.test:443"},
		"no port":   {"127.0.0.1"},
		"zero port": {"127.0.0.1:0"},
		"too many":  append([]string{"127.0.0.1:443"}, defaultLocalQUIC...),
	} {
		if _, err := quicTargets(targets, nil); err == nil {
			t.Errorf("%s: accepted %v", name, targets)
		}
	}
}

func TestIPCheckQUIC(t *testing.T) {
	silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	silentTarget := silent.LocalAddr().(*net.UDPAddr).AddrPort()
	var listenConfig net.ListenConfig
	listen := func(ctx context.Context, _ string) (net.PacketConn, error) {
		return listenConfig.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	}
	https := httptest.NewTLSServer(http.NotFoundHandler())
	cert := https.TLS.Certificates[0]
	https.Close()
	for _, protocol := range []string{"h3", "doq"} {
		t.Run(protocol, func(t *testing.T) {
			server, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{cert}, NextProtos: []string{protocol},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			targets := []netip.AddrPort{silentTarget, server.Addr().(*net.UDPAddr).AddrPort()}
			if check := ipCheckQUIC(ctx, listen, targets); check.Status != ipCheckOK || check.Error != "" || check.DelayMS == nil || *check.DelayMS < 1 {
				t.Fatalf("QUIC server should count as reachable: %+v", check)
			}
		})
	}
	t.Run("timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		if check := ipCheckQUIC(ctx, listen, []netip.AddrPort{silentTarget}); check.Status != ipCheckFailed || check.Error != "timeout" || check.DelayMS != nil {
			t.Fatalf("silent UDP target should time out: %+v", check)
		}
	})
}

func TestIPCheckQUICListenFailure(t *testing.T) {
	listen := func(context.Context, string) (net.PacketConn, error) { return nil, errors.New("no UDP transport") }
	target := netip.MustParseAddrPort("127.0.0.1:443")
	if check := ipCheckQUIC(t.Context(), listen, []netip.AddrPort{target}); check.Status != ipCheckFailed || check.Error != "udp unsupported" || check.DelayMS != nil {
		t.Fatalf("UDP listener failure: %+v", check)
	}
}

func TestQUICResponded(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{&quic.TransportError{Remote: true}, true},
		{&quic.TransportError{}, false},
		{&quic.ApplicationError{Remote: true}, true},
		{&quic.ApplicationError{}, false},
		{&quic.VersionNegotiationError{}, true},
		{context.DeadlineExceeded, false},
	} {
		if got := quicResponded(tc.err); got != tc.want {
			t.Errorf("quicResponded(%v) = %t, want %t", tc.err, got, tc.want)
		}
	}
}

func TestIPCheckLocalUsesAnyTarget(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	// A middlebox that completes the TCP handshake but cannot reach the target.
	silent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	errs := map[string]error{
		"192.0.2.1:443": syscall.ECONNREFUSED,
		"192.0.2.2:443": context.DeadlineExceeded,
		"192.0.2.3:443": syscall.ENETUNREACH,
	}
	routes := map[string]string{
		"192.0.2.8:443": silent.Addr().String(),
		"192.0.2.9:443": server.Listener.Addr().String(),
	}
	var dialer net.Dialer
	dial := func(ctx context.Context, network, target string) (net.Conn, error) {
		if err, ok := errs[target]; ok {
			return nil, err
		}
		return dialer.DialContext(ctx, network, routes[target])
	}
	if check := ipCheckLocal(context.Background(), dial, []string{"192.0.2.1:443", "192.0.2.9:443"}); check.Status != ipCheckOK || check.DelayMS == nil {
		t.Fatalf("one working target should pass: %+v", check)
	}
	if check := ipCheckLocal(context.Background(), dial, []string{"192.0.2.8:443"}); check.Status != ipCheckFailed {
		t.Fatalf("an accepted connection without a TLS answer should fail: %+v", check)
	}
	if check := ipCheckLocal(context.Background(), dial, []string{"192.0.2.1:443", "192.0.2.3:443", "192.0.2.2:443"}); check.Status != ipCheckFailed || check.Error != "no route" {
		t.Fatalf("missing route should win: %+v", check)
	}
	if check := ipCheckLocal(context.Background(), dial, []string{"192.0.2.1:443"}); check.Status != ipCheckFailed || check.Error != "refused" {
		t.Fatalf("refused target: %+v", check)
	}
}
