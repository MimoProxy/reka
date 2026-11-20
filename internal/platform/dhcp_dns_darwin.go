package platform

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
)

func dhcpv4LeaseDNS(ctx context.Context, iface *net.Interface) (string, error) {
	raw, err := exec.CommandContext(ctx, "/usr/sbin/ipconfig", "getpacket", iface.Name).Output()
	if err != nil {
		return "", errors.New("no readable DHCPv4 lease on the interface")
	}
	for line := range strings.Lines(string(raw)) {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && (name == "domain_name_server (ip_mult)" || name == "domain_name_server (ip)") {
			return value, nil
		}
	}
	return "", errors.New("the DHCPv4 lease has no DNS option")
}
