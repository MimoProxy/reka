//go:build ios && cgo

package dns

/*
#cgo LDFLAGS: -lresolv
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>

struct system_dns_servers {
    char hosts[MAXNS][NI_MAXHOST];
};

static int read_system_dns_servers(struct system_dns_servers *output) {
    struct __res_state resolver = {0};
    if (res_ninit(&resolver) != 0) {
        return 0;
    }

    union res_sockaddr_union servers[MAXNS] = {0};
    int count = res_getservers(&resolver, servers, MAXNS);
    res_ndestroy(&resolver);

    int written = 0;
    for (int i = 0; i < count && i < MAXNS; i++) {
        const struct sockaddr *address = (const struct sockaddr *)&servers[i];
        if (address->sa_family != AF_INET && address->sa_family != AF_INET6) {
            continue;
        }
        if (getnameinfo(address, address->sa_len, output->hosts[written],
                        sizeof(output->hosts[written]), NULL, 0, NI_NUMERICHOST) == 0) {
            written++;
        }
    }
    return written;
}
*/
import "C"

import (
	"net/netip"
	"slices"
)

// systemResolverServers reports the configured default servers. The native
// address lookup does not report which server answered an individual question.
func systemResolverServers() []string {
	var output C.struct_system_dns_servers
	count := int(C.read_system_dns_servers(&output))
	var servers []string
	for i := range count {
		ip, err := netip.ParseAddr(C.GoString(&output.hosts[i][0]))
		if err != nil || ip.Unmap().IsUnspecified() {
			continue
		}
		server := ip.Unmap().String()
		if !slices.Contains(servers, server) {
			servers = append(servers, server)
		}
	}
	return servers
}
