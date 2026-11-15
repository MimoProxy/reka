package rulesdata

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/MimoProxy/reka/internal/router"
	"google.golang.org/protobuf/encoding/protowire"
)

type wireField struct {
	n protowire.Number
	t protowire.Type
	b []byte
	v uint64
}

func fields(data []byte) ([]wireField, error) {
	var out []wireField
	for len(data) > 0 {
		n, t, k := protowire.ConsumeTag(data)
		if k < 0 {
			return nil, errors.New("invalid geodata tag")
		}
		data = data[k:]
		f := wireField{n: n, t: t}
		switch t {
		case protowire.BytesType:
			f.b, k = protowire.ConsumeBytes(data)
		case protowire.VarintType:
			f.v, k = protowire.ConsumeVarint(data)
		default:
			k = protowire.ConsumeFieldValue(n, t, data)
		}
		if k < 0 {
			return nil, errors.New("invalid geodata field")
		}
		data = data[k:]
		out = append(out, f)
		if len(out) > MaxEntries {
			return nil, errors.New("too many geodata fields")
		}
	}
	return out, nil
}
func decodeGeo(behavior, selector string, data []byte) ([]router.RuleSpec, error) {
	names := strings.Split(strings.ToLower(selector), "@")
	names[0] = strings.TrimSpace(names[0])
	if names[0] == "" {
		return nil, errors.New("geodata code required")
	}
	entries, err := fieldsTyped(data, protowire.BytesType)
	if err != nil {
		return nil, err
	}
	var out []router.RuleSpec
	found := false
	for _, entry := range entries {
		if entry.n != 1 {
			continue
		}
		fs, e := fieldsTyped(entry.b, protowire.BytesType, protowire.BytesType, protowire.VarintType)
		if e != nil {
			return nil, e
		}
		code := ""
		reverse := false
		for _, f := range fs {
			if f.n == 1 {
				code = string(f.b)
			}
			if f.n == 3 && f.v != 0 {
				reverse = true
			}
		}
		if !strings.EqualFold(code, names[0]) {
			continue
		}
		found = true
		if behavior == "geoip" {
			if len(names) != 1 {
				return nil, errors.New("GeoIP attributes unsupported")
			}
			var cidrs []string
			for _, f := range fs {
				if f.n != 2 {
					continue
				}
				cs, e := fieldsTyped(f.b, protowire.BytesType, protowire.VarintType)
				if e != nil {
					return nil, e
				}
				var ip []byte
				var prefix uint64
				for _, c := range cs {
					if c.n == 1 {
						ip = c.b
					}
					if c.n == 2 {
						prefix = c.v
					}
				}
				a, ok := netip.AddrFromSlice(ip)
				if !ok || prefix > uint64(a.BitLen()) {
					return nil, errors.New("invalid GeoIP CIDR")
				}
				cidrs = append(cidrs, netip.PrefixFrom(a, int(prefix)).Masked().String())
			}
			if len(cidrs) == 0 {
				return nil, errors.New("empty GeoIP code")
			}
			r := router.RuleSpec{Kind: router.KindIPCIDR, Values: cidrs}
			if reverse {
				r.IPInverse = true
			}
			out = append(out, r)
		} else {
			for _, f := range fs {
				if f.n != 2 {
					continue
				}
				ds, e := fieldsTyped(f.b, protowire.VarintType, protowire.BytesType, protowire.BytesType)
				if e != nil {
					return nil, e
				}
				typ := uint64(0)
				value := ""
				attrs := map[string]bool{}
				for _, d := range ds {
					switch d.n {
					case 1:
						typ = d.v
					case 2:
						value = string(d.b)
					case 3:
						as, e := fieldsTyped(d.b, protowire.BytesType, protowire.VarintType, protowire.VarintType)
						if e != nil {
							return nil, e
						}
						key := ""

						for _, a := range as {
							if a.n == 1 {
								key = strings.ToLower(string(a.b))
							}
						}
						attrs[key] = true
					}
				}
				include := true
				for _, a := range names[1:] {
					a = strings.TrimSpace(a)
					if a != "" && !attrs[a] {
						include = false
					}
				}

				if !include {
					continue
				}
				kinds := []router.Kind{router.KindDomainKeyword, router.KindDomainRegex, router.KindDomainSuffix, router.KindDomain}
				if typ >= uint64(len(kinds)) {
					return nil, errors.New("invalid GeoSite domain type")
				}
				out = append(out, router.RuleSpec{Kind: kinds[typ], Values: []string{value}})
			}
		}
	}
	if !found || len(out) == 0 {
		return nil, fmt.Errorf("geodata code or attributes not found: %s", selector)
	}
	return checked(out)
}

func fieldsTyped(data []byte, types ...protowire.Type) ([]wireField, error) {
	fs, err := fields(data)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		if f.n > 0 && int(f.n) <= len(types) && f.t != types[f.n-1] {
			return nil, errors.New("invalid geodata wire type")
		}
	}
	return fs, nil
}
