package rulesdata

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"google.golang.org/protobuf/encoding/protowire"
)

type wireField struct {
	n protowire.Number
	b []byte
	v uint64
}

// SubsetDatabase returns a DAT containing the requested geodata selectors.
// ASN and country MMDB networks are encoded as GeoIP DAT records.
func SubsetDatabase(kind string, data []byte, selectors []string) ([]byte, error) {
	if len(data) == 0 || len(data) > resource.MaxSize {
		return nil, errors.New("database size outside limit")
	}
	switch kind {
	case "asn":
		codes := make([]string, 0, len(selectors))
		for _, selector := range selectors {
			code, err := asnCode(selector)
			if err != nil {
				return nil, err
			}
			codes = append(codes, code)
		}
		selectors = codes
	case "geoip", "geosite":
	default:
		return nil, errors.New("unsupported database kind")
	}
	if GeodataFormat(kind, data) == "mmdb" {
		return subsetMMDB(kind, data, selectors)
	}
	return SubsetDAT(data, selectors)
}

// SubsetDAT retains the country/category records required by a profile. A
// GeoSite category keeps all attributes so the normal decoder can match them.
func SubsetDAT(data []byte, selectors []string) ([]byte, error) {
	wanted := make(map[string]bool, len(selectors))
	for _, selector := range selectors {
		code, _, _ := strings.Cut(strings.ToLower(selector), "@")
		wanted[strings.TrimSpace(code)] = true
	}
	var filtered []byte
	err := walkFields(data, []protowire.Type{protowire.BytesType}, func(entry wireField) error {
		if entry.n != 1 {
			return nil
		}
		// Country/category is normally first; accept other field ordering.
		rest := entry.b
		for len(rest) > 0 {
			n, t, k := protowire.ConsumeTag(rest)
			if k < 0 {
				return errors.New("invalid geodata entry")
			}
			rest = rest[k:]
			if n == 1 && t == protowire.BytesType {
				value, size := protowire.ConsumeBytes(rest)
				if size < 0 {
					return errors.New("invalid geodata selector")
				}
				if wanted[strings.ToLower(string(value))] {
					filtered = protowire.AppendTag(filtered, 1, protowire.BytesType)
					filtered = protowire.AppendBytes(filtered, entry.b)
				}
				return nil
			}
			k = protowire.ConsumeFieldValue(n, t, rest)
			if k < 0 {
				return errors.New("invalid geodata entry")
			}
			rest = rest[k:]
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(filtered) == 0 {
		return nil, errors.New("geodata does not contain the required selectors")
	}
	return filtered, nil
}

// walkFields validates and visits the fields without retaining the record.
func walkFields(data []byte, types []protowire.Type, visit func(wireField) error) error {
	for count := 0; len(data) > 0; count++ {
		n, t, k := protowire.ConsumeTag(data)
		if k < 0 {
			return errors.New("invalid geodata tag")
		}
		data = data[k:]
		f := wireField{n: n}
		switch t {
		case protowire.BytesType:
			f.b, k = protowire.ConsumeBytes(data)
		case protowire.VarintType:
			f.v, k = protowire.ConsumeVarint(data)
		default:
			k = protowire.ConsumeFieldValue(n, t, data)
		}
		if k < 0 {
			return errors.New("invalid geodata field")
		}
		data = data[k:]
		if count >= MaxEntries {
			return errors.New("too many geodata fields")
		}
		if n > 0 && int(n) <= len(types) && t != types[n-1] {
			return errors.New("invalid geodata wire type")
		}
		if err := visit(f); err != nil {
			return err
		}
	}
	return nil
}

func decodeGeo(behavior, selector string, data []byte, visit func(router.RuleSpec) error, domain func(router.Kind, string) error, reserve func(int)) error {
	names := strings.Split(strings.ToLower(selector), "@")
	code := strings.TrimSpace(names[0])
	if code == "" {
		return errors.New("geodata code required")
	}
	attrs := make(map[string]bool)
	for _, name := range names[1:] {
		if name = strings.TrimSpace(name); name != "" {
			attrs[name] = true
		}
	}
	count := 0
	err := walkFields(data, []protowire.Type{protowire.BytesType}, func(entry wireField) error {
		if entry.n != 1 {
			return nil
		}
		var name []byte
		var reverse bool
		var members int
		types := []protowire.Type{protowire.BytesType, protowire.BytesType, protowire.VarintType}
		if err := walkFields(entry.b, types, func(f wireField) error {
			switch f.n {
			case 1:
				name = f.b
			case 2:
				members++
			case 3:
				reverse = reverse || f.v != 0
			}
			return nil
		}); err != nil {
			return err
		}
		if !strings.EqualFold(string(name), code) {
			return nil
		}
		if behavior != "geosite" {
			if len(names) != 1 {
				return errors.New("GeoIP attributes unsupported")
			}
			spec, err := decodeGeoIP(entry.b, types, reverse)
			if err != nil {
				return err
			}
			count++
			return visit(spec)
		}
		if reserve != nil && len(attrs) == 0 {
			reserve(members)
		}
		return walkFields(entry.b, types, func(f wireField) error {
			if f.n != 2 {
				return nil
			}
			kind, value, err := decodeGeoDomain(f.b, attrs)
			if err != nil || kind == 0 {
				return err
			}
			count++
			return domain(kind, string(value))
		})
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("geodata code or attributes not found: %s", selector)
	}
	return nil
}

func decodeGeoIP(data []byte, types []protowire.Type, reverse bool) (router.RuleSpec, error) {
	spec := router.RuleSpec{Kind: router.KindIPCIDR, IPInverse: reverse}
	err := walkFields(data, types, func(f wireField) error {
		if f.n != 2 {
			return nil
		}
		var ip []byte
		var prefix uint64
		if err := walkFields(f.b, []protowire.Type{protowire.BytesType, protowire.VarintType}, func(c wireField) error {
			switch c.n {
			case 1:
				ip = c.b
			case 2:
				prefix = c.v
			}
			return nil
		}); err != nil {
			return err
		}
		a, ok := netip.AddrFromSlice(ip)
		if !ok || prefix > uint64(a.BitLen()) {
			return errors.New("invalid GeoIP CIDR")
		}
		spec.Values = append(spec.Values, netip.PrefixFrom(a, int(prefix)).Masked().String())
		return nil
	})
	if err == nil && len(spec.Values) == 0 {
		err = errors.New("empty GeoIP code")
	}
	return spec, err
}

func decodeGeoDomain(data []byte, attrs map[string]bool) (router.Kind, []byte, error) {
	var typ uint64
	var value []byte
	var matched map[string]bool
	err := walkFields(data, []protowire.Type{protowire.VarintType, protowire.BytesType, protowire.BytesType}, func(d wireField) error {
		switch d.n {
		case 1:
			typ = d.v
		case 2:
			value = d.b
		case 3:
			var key []byte
			if err := walkFields(d.b, []protowire.Type{protowire.BytesType, protowire.VarintType, protowire.VarintType}, func(a wireField) error {
				if a.n == 1 {
					key = a.b
				}
				return nil
			}); err != nil {
				return err
			}
			if len(attrs) > 0 {
				name := strings.ToLower(string(key))
				if attrs[name] {
					if matched == nil {
						matched = make(map[string]bool)
					}
					matched[name] = true
				}
			}
		}
		return nil
	})
	if err != nil || len(matched) != len(attrs) {
		return 0, nil, err
	}
	kinds := [...]router.Kind{router.KindDomainKeyword, router.KindDomainRegex, router.KindDomainSuffix, router.KindDomain}
	if typ >= uint64(len(kinds)) {
		return 0, nil, errors.New("invalid GeoSite domain type")
	}
	return kinds[typ], value, nil
}
