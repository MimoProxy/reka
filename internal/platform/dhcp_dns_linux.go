//go:build linux && !android

package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func dhcpv4LeaseDNS(ctx context.Context, iface *net.Interface) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/run/systemd/netif/leases/%d", iface.Index))
	if err == nil {
		for line := range strings.Lines(string(raw)) {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line), "DNS="); ok && value != "" {
				return value, nil
			}
		}
	}
	// Read only the DHCP4 option, not NetworkManager's effective IP4.DNS.
	for _, executable := range []string{"/usr/bin/nmcli", "/bin/nmcli"} {
		if _, err := os.Stat(executable); err != nil {
			continue
		}
		cmd := exec.CommandContext(ctx, executable, "-t", "-e", "no", "-f", "DHCP4.OPTION", "device", "show", iface.Name)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.Output()
		if err == nil {
			for line := range strings.Lines(string(out)) {
				_, value, ok := strings.Cut(line, "domain_name_servers =")
				if ok {
					return strings.TrimSpace(value), nil
				}
			}
		}
		break
	}
	return "", errors.New("no DHCPv4 DNS option in the systemd-networkd or NetworkManager lease")
}
