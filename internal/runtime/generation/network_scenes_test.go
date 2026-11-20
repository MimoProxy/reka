package generation

import (
	"net/netip"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestNetworkSceneMatchesInterfaceAndAddressInConfiguredOrder(t *testing.T) {
	scenes := []compile.NetworkScene{
		{ID: "manual-only"},
		{ID: "office", Interface: "en0", CIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}},
		{ID: "ethernet", Interface: "en0"},
		{ID: "ula", CIDRs: []netip.Prefix{netip.MustParsePrefix("fd00::/8")}},
	}
	for _, item := range []struct{ iface, addr, want string }{
		{"en0", "192.168.10.8", "office"}, {"en0", "192.168.11.8", "ethernet"},
		{"en1", "192.168.10.8", ""}, {"en1", "fd00::1234", "ula"},
	} {
		if got := matchNetworkScene(scenes, &sceneObservation{name: item.iface, addresses: []netip.Addr{netip.MustParseAddr(item.addr)}}); got != item.want {
			t.Fatalf("%s %s selected %q, want %q", item.iface, item.addr, got, item.want)
		}
	}
}
