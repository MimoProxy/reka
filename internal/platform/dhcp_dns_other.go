//go:build !darwin && !windows && (!linux || android)

package platform

import (
	"context"
	"errors"
	"net"
)

func dhcpv4LeaseDNS(context.Context, *net.Interface) (string, error) {
	return "", errors.New("DHCP DNS is unavailable on this platform")
}
