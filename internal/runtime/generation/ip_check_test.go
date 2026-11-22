package generation

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
)

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
	for _, tc := range []struct {
		name     string
		family   string
		target   compile.Outbound
		lookup   bool
		answers  []netip.Addr
		dnsErr   error
		dialAddr string
		dialErr  error
		status   string
		reason   string
	}{
		{name: "IPv4 literal", family: "ip4", target: compile.Outbound{Server: "192.0.2.1"}, dialAddr: "192.0.2.1:443", status: ipCheckOK},
		{name: "IPv6 literal", family: "ip6", target: compile.Outbound{Server: "2001:db8::1"}, dialAddr: "[2001:db8::1]:443", status: ipCheckOK},
		{name: "mapped literal", family: "ip4", target: compile.Outbound{Server: "::ffff:192.0.2.1"}, dialAddr: "192.0.2.1:443", status: ipCheckOK},
		{name: "IPv4 only literal", family: "ip6", target: compile.Outbound{Server: "192.0.2.1"}, status: ipCheckUnavailable, reason: "no address"},
		{name: "IPv6 only literal", family: "ip4", target: compile.Outbound{Server: "2001:db8::1"}, status: ipCheckUnavailable, reason: "no address"},
		{name: "hostname IPv4", family: "ip4", target: compile.Outbound{Server: "proxy.test"}, lookup: true, answers: ips,
			dialAddr: "192.0.2.1:443", status: ipCheckOK},
		{name: "hostname IPv6 refused", family: "ip6", target: compile.Outbound{Server: "proxy.test"}, lookup: true, answers: ips,
			dialAddr: "[2001:db8::1]:443", dialErr: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, status: ipCheckFailed, reason: "refused"},
		{name: "hostname without AAAA", family: "ip6", target: compile.Outbound{Server: "proxy.test"}, lookup: true, answers: ips[:1],
			status: ipCheckUnavailable, reason: "no address"},
		{name: "hostname not found", family: "ip4", target: compile.Outbound{Server: "proxy.test"}, lookup: true, dnsErr: &net.DNSError{IsNotFound: true},
			status: ipCheckUnavailable, reason: "no address"},
		{name: "DNS failure", family: "ip4", target: compile.Outbound{Server: "proxy.test"}, lookup: true, dnsErr: errors.New("resolver failed for proxy.test"),
			status: ipCheckFailed, reason: "dns"},
		{name: "hysteria address only", family: "ip6", target: compile.Outbound{Type: "hysteria2", Server: "proxy.test"}, lookup: true, answers: ips[1:],
			status: ipCheckSkipped, reason: "udp transport"},
		{name: "tuic address missing", family: "ip6", target: compile.Outbound{Type: "tuic", Server: "192.0.2.1"},
			status: ipCheckUnavailable, reason: "no address"},
		{name: "tuic address only", family: "ip4", target: compile.Outbound{Type: "tuic", Server: "192.0.2.1"},
			status: ipCheckSkipped, reason: "udp transport"},
		{name: "kcptun address only", family: "ip4", target: compile.Outbound{Type: "shadowsocks", Server: "192.0.2.1", Plugin: &model.SSPlugin{Type: "kcptun"}},
			status: ipCheckSkipped, reason: "udp transport"},
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
			if lookupCalls > 1 || (lookupCalls == 1) != tc.lookup || dialCalls > 1 || (dialCalls == 1) != (tc.dialAddr != "") {
				t.Fatalf("unexpected lookup and dial counts %d, %d", lookupCalls, dialCalls)
			}
			if (got.DelayMS != nil) != (dialCalls == 1) || got.DelayMS != nil && *got.DelayMS < 1 {
				t.Fatalf("unexpected delay %v after %d dials", got.DelayMS, dialCalls)
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

func TestIPCheckLocalUsesAnyTarget(t *testing.T) {
	errs := map[string]error{
		"192.0.2.1:443": syscall.ECONNREFUSED,
		"192.0.2.2:443": context.DeadlineExceeded,
		"192.0.2.3:443": syscall.ENETUNREACH,
	}
	dial := func(_ context.Context, _, target string) (net.Conn, error) {
		if err, ok := errs[target]; ok {
			return nil, err
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	if check := ipCheckLocal(context.Background(), dial, []string{"192.0.2.1:443", "192.0.2.9:443"}); check.Status != ipCheckOK || check.DelayMS == nil {
		t.Fatalf("one working target should pass: %+v", check)
	}
	if check := ipCheckLocal(context.Background(), dial, []string{"192.0.2.1:443", "192.0.2.3:443", "192.0.2.2:443"}); check.Status != ipCheckFailed || check.Error != "no route" {
		t.Fatalf("missing route should win: %+v", check)
	}
	if check := ipCheckLocal(context.Background(), dial, []string{"192.0.2.1:443"}); check.Status != ipCheckFailed || check.Error != "refused" {
		t.Fatalf("refused target: %+v", check)
	}
}
