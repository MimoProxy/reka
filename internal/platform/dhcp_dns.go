package platform

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
)

func DHCPDNSSupported() bool {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		return true
	default:
		return false
	}
}

// DHCPv4DNS reads DNS servers from the current IPv4 lease for one interface.
// The effective system resolver may already point to a TUN or to this process.
func DHCPv4DNS(ctx context.Context, name string) ([]netip.Addr, error) {
	if !DHCPDNSSupported() {
		return nil, errors.New("DHCP DNS is unavailable on this platform")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
		return nil, errors.New("DHCP DNS requires an active physical interface")
	}
	for _, prefix := range []string{"utun", "tun", "tap", "tailscale", "wireguard", "reka"} {
		if strings.HasPrefix(strings.ToLower(iface.Name), prefix) {
			return nil, errors.New("DHCP DNS is unavailable on VPN interfaces")
		}
	}
	raw, err := dhcpv4LeaseDNS(ctx, iface)
	if err != nil {
		return nil, err
	}
	servers := parseDHCPv4DNS(raw)
	if len(servers) == 0 {
		return nil, errors.New("the DHCP lease has no usable IPv4 DNS servers")
	}
	return servers, nil
}

func parseDHCPv4DNS(raw string) []netip.Addr {
	var servers []netip.Addr
	for _, token := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '{' || r == '}'
	}) {
		address, err := netip.ParseAddr(token)
		if err == nil && address.Is4() && address.IsGlobalUnicast() && !slices.Contains(servers, address) {
			servers = append(servers, address)
			if len(servers) == 8 {
				break
			}
		}
	}
	return servers
}
