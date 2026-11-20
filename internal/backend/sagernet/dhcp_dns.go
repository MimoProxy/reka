package sagernet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/platform"
	D "github.com/miekg/dns"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sync/singleflight"
)

type dhcpLeaseResult struct {
	servers []netip.Addr
	err     error
	until   time.Time
}

// DHCPDNS refreshes OS lease information independently of the DNS answer cache.
type DHCPDNS struct {
	mu     sync.Mutex
	leases map[string]dhcpLeaseResult
	reads  singleflight.Group
	epoch  uint64
}

func (d *DHCPDNS) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.leases = nil
	d.epoch++
}

func (d *DHCPDNS) servers(ctx context.Context, iface string) ([]netip.Addr, error) {
	d.mu.Lock()
	cached, epoch := d.leases[iface], d.epoch
	d.mu.Unlock()
	if time.Now().Before(cached.until) {
		return cached.servers, cached.err
	}
	key := strconv.FormatUint(epoch, 10) + "/" + iface
	ready := d.reads.DoChan(key, func() (any, error) {
		d.mu.Lock()
		entry := d.leases[iface]
		d.mu.Unlock()
		if time.Now().Before(entry.until) {
			return entry, nil
		}
		// One short OS lease read serves concurrent queries, even if a
		// particular DNS caller gives up waiting for it.
		readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		addresses, err := platform.DHCPv4DNS(readCtx, iface)
		ttl := 10 * time.Second
		if err != nil {
			ttl = 2 * time.Second
		}
		entry = dhcpLeaseResult{addresses, err, time.Now().Add(ttl)}
		d.mu.Lock()
		if epoch == d.epoch {
			if d.leases == nil {
				d.leases = make(map[string]dhcpLeaseResult)
			}
			d.leases[iface] = entry
		}
		d.mu.Unlock()
		return entry, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ready:
		lease := res.Val.(dhcpLeaseResult)
		return lease.servers, lease.err
	}
}

func (d *DHCPDNS) Exchange(ctx context.Context, ep RD.Endpoint, q *D.Msg) (*D.Msg, error) {
	servers, err := d.servers(ctx, ep.Host)
	if err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(ep.Host)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return nil, errors.New("DHCP DNS interface is no longer available")
	}
	dialer := net.Dialer{Control: control.BindToInterface(nil, iface.Name, iface.Index)}
	return exchangeDHCPDNS(ctx, servers, ep.Port, q, dialer.DialContext)
}

func exchangeDHCPDNS(ctx context.Context, servers []netip.Addr, port string, q *D.Msg, dial func(context.Context, string, string) (net.Conn, error)) (*D.Msg, error) {
	var last error
	for _, ip := range servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attempt, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		m, err := ExchangeDNS(attempt, RD.Endpoint{Scheme: "udp", Host: ip.String(), Port: port}, q, nil,
			func(ctx context.Context, netw, address, _ string) (net.Conn, error) {
				return dial(ctx, netw, address)
			})
		cancel()
		if err == nil && (m.Rcode == D.RcodeSuccess || m.Rcode == D.RcodeNameError) {
			RD.ReportUpstream(ctx, "direct", "dhcp")
			for _, section := range [][]D.RR{m.Answer, m.Ns, m.Extra} {
				for _, rr := range section {
					if rr.Header().Rrtype != D.TypeOPT {
						rr.Header().Ttl = min(rr.Header().Ttl, 30)
					}
				}
			}
			return m, nil
		}
		if err == nil {
			err = errors.New("DHCP DNS server returned a failure response")
		}
		last = err
	}
	if last == nil {
		last = errors.New("the DHCP lease has no DNS servers")
	}
	return nil, last
}
