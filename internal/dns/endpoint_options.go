package dns

import (
	"fmt"
	D "github.com/miekg/dns"
	"net/netip"
	"strconv"
	"strings"
)

func endpointOptions(ep *Endpoint, fragment string) error {
	ep.Params = map[string]string{}
	for _, part := range strings.Split(fragment, "&") {
		if part == "" {
			continue
		}
		key, value, option := strings.Cut(part, "=")
		if !option {
			if ep.Via != "" {
				return fmt.Errorf("multiple DNS outbound selectors")
			}
			ep.Via = key
			continue
		}
		if _, exists := ep.Params[key]; exists {
			return fmt.Errorf("duplicate DNS endpoint option")
		}
		switch key {
		case "h3", "skip-cert-verify", "ecs-override", "disable-ipv4", "disable-ipv6", "disable-reuse":
			if value != "true" && value != "false" {
				return fmt.Errorf("DNS option %s requires true or false", key)
			}
		case "name-cert-verify":
			if value == "" || len(value) > 253 || strings.ContainsAny(value, " /\t\r\n") {
				return fmt.Errorf("invalid DNS certificate verification name")
			}
		case "ecs":
			if _, err := endpointSubnet(value); err != nil {
				return err
			}
		default:
			if !strings.HasPrefix(key, "disable-qtype-") {
				return fmt.Errorf("unsupported DNS endpoint option %q", key)
			}
			typ, e := strconv.ParseUint(strings.TrimPrefix(key, "disable-qtype-"), 10, 16)
			if e != nil || D.TypeToRR[uint16(typ)] == nil || (value != "true" && value != "false") {
				return fmt.Errorf("invalid DNS query type option")
			}
		}
		ep.Params[key] = value
	}
	encrypted := ep.Scheme == "tls" || ep.Scheme == "https" || ep.Scheme == "quic" || ep.Scheme == "h3"
	if !encrypted && (ep.Params["skip-cert-verify"] == "true" || ep.Params["name-cert-verify"] != "") {
		return fmt.Errorf("certificate options require encrypted DNS")
	}
	if ep.Params["h3"] == "true" {
		if ep.Scheme != "https" && ep.Scheme != "h3" {
			return fmt.Errorf("h3 requires HTTPS DNS")
		}
		ep.Scheme = "h3"
	}
	return nil
}

func endpointSubnet(value string) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(value)
	if e != nil {
		ip, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid DNS ECS address or prefix")
		}
		p = netip.PrefixFrom(ip, ip.BitLen())
	}
	return p.Masked(), nil
}

// RemapEndpointTarget preserves transport options while scoping only the
// bare outbound selector in the fragment.
func RemapEndpointTarget(raw string, f func(string) string) string {
	endpoint, fragment, found := strings.Cut(raw, "#")
	if !found {
		return raw
	}
	parts := strings.Split(fragment, "&")
	for i, p := range parts {
		if p != "" && !strings.Contains(p, "=") {
			parts[i] = f(p)
		}
	}
	return endpoint + "#" + strings.Join(parts, "&")
}

func (ep Endpoint) Disabled(typ uint16) bool {
	return ep.Params["disable-qtype-"+strconv.Itoa(int(typ))] == "true" || typ == D.TypeA && ep.Params["disable-ipv4"] == "true" || typ == D.TypeAAAA && ep.Params["disable-ipv6"] == "true"
}

func (ep Endpoint) Request(q *D.Msg) *D.Msg {
	value := ep.Params["ecs"]
	if value == "" {
		return q
	}
	p, _ := endpointSubnet(value)
	result := q.Copy()
	opt := result.IsEdns0()
	if opt == nil {
		result.SetEdns0(1232, false)
		opt = result.IsEdns0()
	}
	var subnet *D.EDNS0_SUBNET
	for _, o := range opt.Option {
		if ecs, ok := o.(*D.EDNS0_SUBNET); ok {
			subnet = ecs
			break
		}
	}
	if subnet != nil && ep.Params["ecs-override"] != "true" {
		return q
	}
	if subnet == nil {
		subnet = &D.EDNS0_SUBNET{Code: D.EDNS0SUBNET}
		opt.Option = append(opt.Option, subnet)
	}
	subnet.Family = 2
	if p.Addr().Is4() {
		subnet.Family = 1
	}
	subnet.SourceNetmask = uint8(p.Bits())
	subnet.SourceScope = 0
	subnet.Address = p.Addr().AsSlice()
	return result
}
