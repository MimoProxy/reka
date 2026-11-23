package rulesdata

import (
	"bytes"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/router"
	"github.com/oschwald/maxminddb-golang"
	"github.com/sagernet/sing-box/common/srs"
	"google.golang.org/protobuf/encoding/protowire"
)

func GeodataFormat(kind string, data []byte) string {
	if (kind == "geoip" || kind == "geosite") && bytes.HasPrefix(data, srs.MagicBytes[:]) {
		return "srs"
	}
	if (kind == "geoip" || kind == "asn") && bytes.Contains(data[max(0, len(data)-128*1024):], []byte("\xab\xcd\xefMaxMind.com")) {
		return "mmdb"
	}
	return "dat"
}

func asnCode(code string) (string, error) {
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(code)), "AS"), 10, 32)
	if err != nil || n == 0 {
		return "", fmt.Errorf("ASN must be between 1 and 4294967295")
	}
	return strconv.FormatUint(n, 10), nil
}

func decodeNetworkDB(kind, code string, data []byte) ([]router.RuleSpec, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" || strings.Contains(code, "@") {
		return nil, fmt.Errorf("MMDB requires one country code")
	}
	selected := map[string][]netip.Prefix{code: nil}
	if err := scanMMDB(kind, data, selected); err != nil {
		return nil, err
	}
	networks := selected[code]
	if len(networks) == 0 {
		return nil, fmt.Errorf("selector not present in MMDB")
	}
	prefixes := make([]string, 0, len(networks))
	for _, prefix := range networks {
		prefixes = append(prefixes, prefix.String())
	}
	return []router.RuleSpec{{Kind: router.KindIPCIDR, Values: prefixes}}, nil
}

func subsetMMDB(kind string, data []byte, selectors []string) ([]byte, error) {
	selected := make(map[string][]netip.Prefix, len(selectors))
	for _, selector := range selectors {
		code := strings.ToUpper(strings.TrimSpace(selector))
		if code == "" || strings.Contains(code, "@") {
			return nil, fmt.Errorf("MMDB requires unqualified codes")
		}
		selected[code] = nil
	}
	if err := scanMMDB(kind, data, selected); err != nil {
		return nil, err
	}
	var result []byte
	for _, code := range slices.Sorted(maps.Keys(selected)) {
		prefixes := selected[code]
		if len(prefixes) == 0 {
			continue
		}
		record := protowire.AppendTag(nil, 1, protowire.BytesType)
		record = protowire.AppendString(record, code)
		for _, prefix := range prefixes {
			cidr := protowire.AppendTag(nil, 1, protowire.BytesType)
			cidr = protowire.AppendBytes(cidr, prefix.Addr().AsSlice())
			cidr = protowire.AppendTag(cidr, 2, protowire.VarintType)
			cidr = protowire.AppendVarint(cidr, uint64(prefix.Bits()))
			record = protowire.AppendTag(record, 2, protowire.BytesType)
			record = protowire.AppendBytes(record, cidr)
		}
		result = protowire.AppendTag(result, 1, protowire.BytesType)
		result = protowire.AppendBytes(result, record)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("geodata does not contain the required selectors")
	}
	return result, nil
}

func openMMDB(data []byte) (*maxminddb.Reader, error) {
	db, err := maxminddb.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("invalid MMDB: %w", err)
	}
	if err = db.Verify(); err != nil {
		db.Close()
		return nil, fmt.Errorf("corrupt MMDB: %w", err)
	}
	return db, nil
}

// scanMMDB collects all selected networks in a single pass over the database.
func scanMMDB(kind string, data []byte, selected map[string][]netip.Prefix) error {
	db, err := openMMDB(data)
	if err != nil {
		return err
	}
	defer db.Close()
	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	count := 0
	for networks.Next() {
		count++
		if count > 8*MaxEntries {
			return fmt.Errorf("MMDB exceeds network budget")
		}
		var value any
		network, e := networks.Network(&value)
		if e != nil {
			return e
		}
		code := mmdbRecordCode(kind, value)
		prefixes, wanted := selected[code]
		if !wanted {
			continue
		}
		ip, ok := netip.AddrFromSlice(network.IP)
		bits, total := network.Mask.Size()
		if !ok || bits < 0 {
			return fmt.Errorf("invalid MMDB network")
		}
		if ip.Is4In6() {
			ip = ip.Unmap()
			if total == 128 {
				bits -= 96
			}
		}
		if bits < 0 || bits > ip.BitLen() {
			return fmt.Errorf("invalid MMDB prefix")
		}
		if len(prefixes) >= MaxEntries {
			return fmt.Errorf("matched MMDB prefixes exceed budget")
		}
		selected[code] = append(prefixes, netip.PrefixFrom(ip, bits).Masked())
	}
	return networks.Err()
}

func mmdbRecordCode(kind string, value any) string {
	if kind == "asn" {
		record, _ := value.(map[string]any)
		var number uint64
		switch n := record["autonomous_system_number"].(type) {
		case uint64:
			number = n
		case uint32:
			number = uint64(n)
		case uint16:
			number = uint64(n)
		case uint:
			number = uint64(n)
		case int:
			number = uint64(n)
		}
		if number > 0 && number <= math.MaxUint32 {
			return strconv.FormatUint(number, 10)
		}
		return ""
	}
	// Both GeoIP2 country records and sing-geoip's scalar records work.
	switch record := value.(type) {
	case string:
		return strings.ToUpper(record)
	case map[string]any:
		for _, key := range []string{"country", "registered_country", "represented_country"} {
			country, _ := record[key].(map[string]any)
			if code, _ := country["iso_code"].(string); code != "" {
				return strings.ToUpper(code)
			}
		}
	}
	return ""
}
