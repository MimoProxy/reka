//go:build with_gvisor

package packettunnel

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/mobile/profile"
	"github.com/miekg/dns"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	tun "github.com/sagernet/sing-tun"
)

func TestProfileRestoresFakeIPStateAcrossSessions(t *testing.T) {
	const raw = `
schema-version: 1
dns: {nameserver: [192.0.2.53], enhanced-mode: fake-ip, fake-ip-range: 198.18.0.0/16}
rules:
  - {match: {domain: cached.test}, outbound: reject}
  - {match: {all: true}, outbound: reject-drop}
`
	dir := t.TempDir()
	controls := profile.Controls{FakeIPState: filepath.Join(dir, "fake-ip.json")}
	session, err := StartProfile(prepareSnapshot(t, raw), controls, false)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	lookup := func() netip.Addr {
		t.Helper()
		query := new(dns.Msg).SetQuestion("cached.test.", dns.TypeA)
		answer, err := session.profile.engine.ExchangeDNS(t.Context(), query)
		if err != nil || len(answer.Answer) != 1 {
			t.Fatalf("fake DNS reply: %v, %v", answer, err)
		}
		addr, ok := netip.AddrFromSlice(answer.Answer[0].(*dns.A).A)
		if !ok {
			t.Fatalf("invalid address in fake DNS reply: %v", answer)
		}
		return addr.Unmap()
	}
	oldIP := lookup()
	if err := session.ApplyControls(profile.Controls{BlockQUIC: "all"}); err != nil {
		t.Fatal(err)
	}
	if got := lookup(); got != oldIP {
		t.Fatalf("routing update changed the fake IP from %s to %s", oldIP, got)
	}
	newRange := netip.MustParsePrefix("198.19.0.0/16")
	replacement := prepareSnapshot(t, strings.Replace(raw, "198.18.0.0/16", newRange.String(), 1))
	otherPath := filepath.Join(dir, "other.json")
	if err := session.ReplaceProfile(replacement, profile.Controls{FakeIPState: otherPath}); err != nil {
		t.Fatal(err)
	}
	if got := lookup(); !newRange.Contains(got) {
		t.Fatalf("replacement profile gave address %s outside %s", got, newRange)
	}
	session.Close()
	if _, err := os.Stat(controls.FakeIPState); err != nil {
		t.Fatalf("closing the session did not save its mappings: %v", err)
	}
	if _, err := os.Stat(otherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("profile replacement changed the state path: %v", err)
	}

	reopened, err := StartProfile(replacement, controls, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	client, ctx := attachTestClient(t, reopened, "192.0.2.2")
	destination := tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(oldIP), Port: 80}
	conn, err := gonet.DialUDP(client, nil, &destination, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("cached address")); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := reopened.ProfileStatus()
		if err != nil {
			t.Fatal(err)
		}
		if len(status.Routes) > 0 {
			hit := status.Routes[0]
			if hit.Address != oldIP.String() || hit.Destination != "cached.test" || hit.Failure != "" || hit.Outbound != "reject" {
				t.Fatalf("old fake IP %s routed as %+v", oldIP, hit)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("no route was recorded for fake IP %s", oldIP)
		case <-ticker.C:
		}
	}
}

func TestProfileStartsWithInvalidFakeIPState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-ip.json")
	const invalid = `{"version":1,"mappings":[{"ip":"198.18.0.1","domain":"valid.test"},{}],"ranges":["198.18.0.0/16"]}`
	if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := prepareSnapshot(t, "schema-version: 1\ndns: {nameserver: [192.0.2.53], enhanced-mode: fake-ip}\n")
	session, err := StartProfile(snapshot, profile.Controls{FakeIPState: path}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	query := new(dns.Msg).SetQuestion("memory.test.", dns.TypeA)
	answer, err := session.profile.engine.ExchangeDNS(t.Context(), query)
	if err != nil || len(answer.Answer) != 1 || answer.Answer[0].(*dns.A).A.String() != "198.18.0.1" {
		t.Fatalf("expected a reply from the empty in-memory pool: %v, %v", answer, err)
	}
	session.Close()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != invalid {
		t.Fatalf("opening invalid state changed the file: %q, %v", data, err)
	}
}
