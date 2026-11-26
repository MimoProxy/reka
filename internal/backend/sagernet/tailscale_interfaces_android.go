//go:build with_gvisor && android && cgo

package sagernet

/*
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stddef.h>

static unsigned char *rekaInterfaceIP(struct sockaddr *addr, int *size) {
	if (addr == NULL) {
		return NULL;
	}
	switch (addr->sa_family) {
	case AF_INET:
		*size = 4;
		return (unsigned char *)&((struct sockaddr_in *)addr)->sin_addr;
	case AF_INET6:
		*size = 16;
		return (unsigned char *)&((struct sockaddr_in6 *)addr)->sin6_addr;
	default:
		return NULL;
	}
}
*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/tailscale/net/netmon"
)

func installTailscaleInterfaceGetter(scope *adapter.Scope) error {
	// net.Interfaces uses a netlink request Android disallows for apps
	// targeting SDK 30 or later. Bionic getifaddrs provides address snapshots.
	if _, err := tailscaleAndroidInterfaces(); err != nil {
		return err
	}
	netmon.RegisterInterfaceGetter(tailscaleAndroidInterfaces)
	scope.Add(func() error {
		netmon.RegisterInterfaceGetter(nil)
		return nil
	})
	return nil
}

func tailscaleAndroidInterfaces() ([]netmon.Interface, error) {
	var head *C.struct_ifaddrs
	if result, err := C.getifaddrs(&head); result != 0 {
		return nil, fmt.Errorf("list Android network interfaces: %w", err)
	}
	defer C.freeifaddrs(head)

	var interfaces []netmon.Interface
	indexes := make(map[string]int)
	for it := head; it != nil; it = it.ifa_next {
		if it.ifa_name == nil {
			continue
		}
		var addrSize, maskSize C.int
		addr := C.rekaInterfaceIP(it.ifa_addr, &addrSize)
		mask := C.rekaInterfaceIP(it.ifa_netmask, &maskSize)
		if addr == nil || mask == nil || addrSize != maskSize {
			continue
		}
		name := C.GoString(it.ifa_name)
		index, exists := indexes[name]
		if !exists {
			index = len(interfaces)
			indexes[name] = index
			interfaces = append(interfaces, netmon.Interface{
				Interface: &net.Interface{
					Name:  name,
					Index: int(C.if_nametoindex(it.ifa_name)),
					Flags: tailscaleAndroidInterfaceFlags(it.ifa_flags),
				},
			})
		}
		iface := &interfaces[index]
		iface.AltAddrs = append(iface.AltAddrs, &net.IPNet{
			IP:   C.GoBytes(unsafe.Pointer(addr), addrSize),
			Mask: C.GoBytes(unsafe.Pointer(mask), maskSize),
		})
	}
	return interfaces, nil
}

func tailscaleAndroidInterfaceFlags(raw C.uint) (flags net.Flags) {
	if raw&C.IFF_UP != 0 {
		flags |= net.FlagUp
	}
	if raw&C.IFF_RUNNING != 0 {
		flags |= net.FlagRunning
	}
	if raw&C.IFF_LOOPBACK != 0 {
		flags |= net.FlagLoopback
	}
	if raw&C.IFF_POINTOPOINT != 0 {
		flags |= net.FlagPointToPoint
	}
	if raw&C.IFF_BROADCAST != 0 {
		flags |= net.FlagBroadcast
	}
	if raw&C.IFF_MULTICAST != 0 {
		flags |= net.FlagMulticast
	}
	return flags
}
