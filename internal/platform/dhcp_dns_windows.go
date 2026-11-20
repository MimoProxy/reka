package platform

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func dhcpv4LeaseDNS(ctx context.Context, iface *net.Interface) (string, error) {
	size := uint32(15 << 10)
	for range 3 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		data := make([]byte, size)
		head := (*windows.IpAdapterAddresses)(unsafe.Pointer(&data[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_SKIP_DNS_SERVER, 0, head, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) && size <= 4<<20 {
			continue
		}
		if err != nil {
			break
		}
		for entry := head; entry != nil; entry = entry.Next {
			if entry.IfIndex == uint32(iface.Index) && entry.IfType != windows.IF_TYPE_TUNNEL {
				id := windows.BytePtrToString(entry.AdapterName)
				if id != "" && !strings.ContainsAny(id, "/\\") {
					return readWindowsDNSLease(id)
				}
			}
		}
		break
	}
	return "", errors.New("the interface has no Windows DHCPv4 adapter")
}

func readWindowsDNSLease(id string) (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`+id, registry.QUERY_VALUE)
	if err != nil {
		return "", errors.New("no readable DHCPv4 lease on the interface")
	}
	defer key.Close()
	on, _, err := key.GetIntegerValue("EnableDHCP")
	if err != nil || on != 1 {
		return "", errors.New("DHCPv4 is disabled on the interface")
	}
	expiration, _, err := key.GetIntegerValue("LeaseTerminatesTime")
	if err == nil && expiration != 0 && expiration != 0xffffffff && expiration <= uint64(time.Now().Unix()) {
		return "", errors.New("the interface DHCPv4 lease expired")
	}
	value, _, err := key.GetStringValue("DhcpNameServer")
	if err != nil {
		return "", errors.New("the DHCPv4 lease has no DNS option")
	}
	return value, nil
}
