package compile

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

const mitmClientSourcePath = "/mitm/client-source-address"

// ClientSourceMatcher selects the client IP addresses eligible for MITM.
type ClientSourceMatcher struct {
	include []netip.Prefix
	exclude []netip.Prefix
}

// Match allows every source when the list is empty. Exclusions take precedence,
// and a list with inclusions requires a matching inclusion.
func (m *ClientSourceMatcher) Match(addr netip.Addr) bool {
	if m == nil {
		return true
	}
	if !addr.IsValid() {
		return false
	}
	addr = addr.WithZone("").Unmap()
	for _, prefix := range m.exclude {
		if prefix.Contains(addr) {
			return false
		}
	}
	for _, prefix := range m.include {
		if prefix.Contains(addr) {
			return true
		}
	}
	return len(m.include) == 0
}

func (c *compiler) compileMITMClientSources(entries []string) *ClientSourceMatcher {
	matcher := &ClientSourceMatcher{}
	for i, entry := range entries {
		value, exclude := strings.CutPrefix(entry, "-")
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			addr, err := netip.ParseAddr(value)
			if err != nil || addr.Zone() != "" {
				path := model.JoinPath(mitmClientSourcePath, "#"+strconv.Itoa(i))
				c.errorf(model.DocProfile, path, "mitm.client-source-address", "MITM client source must be an IP address or CIDR, optionally prefixed by -")
				continue
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		addr, bits := prefix.Addr(), prefix.Bits()
		if addr.Is4In6() && bits >= 96 {
			prefix = netip.PrefixFrom(addr.Unmap(), bits-96)
		}
		if exclude {
			matcher.exclude = append(matcher.exclude, prefix.Masked())
		} else {
			matcher.include = append(matcher.include, prefix.Masked())
		}
	}
	return matcher
}
