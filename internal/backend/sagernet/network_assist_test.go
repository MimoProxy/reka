package sagernet

import (
	"net"
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestHostNetworksReport(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skip("no interfaces")
	}
	first := interfaces[0]
	var h hostNetworks
	if got := h.list(); len(got) != 1 || got[0].Index != 0 || h.defaultInterface().Index != 0 {
		t.Fatal("unreported networks must stand in for the default interface", got)
	}
	got := h.set([]NetworkInterface{
		{Name: first.Name, Index: 999999, Type: "wifi"},
		{Name: first.Name, Type: "cellular"},
		{Name: "reka-missing0", Type: "cellular"},
		{Name: "", Type: "wifi"},
	})
	if len(got) != 1 || got[0].Index != first.Index || got[0].Type != C.InterfaceTypeWIFI {
		t.Fatal("report not normalized", got)
	}
	if d := h.defaultInterface(); d == nil || d.Index != first.Index {
		t.Fatal("default interface", d)
	}
	h.set([]NetworkInterface{{Name: first.Name, Type: "wifi", Label: "Home"}, {Name: "reka-missing0", Type: "cellular"}})
	if got := h.describe(first.Name); got.NetworkType != "wifi" || got.NetworkName != "Home" {
		t.Fatal("description", got)
	}
	// A reported network that cannot be dialed is still named for connections.
	if got := h.describe("reka-missing0"); got.NetworkType != "cellular" {
		t.Fatal("description of an undialable network", got)
	}
	if got := h.describe("reka-unknown0"); got.NetworkType != "" {
		t.Fatal("unreported interface described", got)
	}
	if len(interfaces) > 1 {
		second := interfaces[1]
		got = h.set([]NetworkInterface{
			{Name: first.Name, Type: "wifi", Constrained: true},
			{Name: second.Name, Type: "cellular", Constrained: true},
		})
		if len(got) != 1 || !got[0].Constrained {
			t.Fatal("a constrained network other than the preferred one must be skipped", got)
		}
	}
	if got = h.set(nil); len(got) != 0 || h.defaultInterface() != nil || len(h.list()) != 0 {
		t.Fatal("an empty report means no network", got)
	}
}
