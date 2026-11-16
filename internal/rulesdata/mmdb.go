package rulesdata

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/router"
	"github.com/oschwald/maxminddb-golang"
)

func GeodataFormat(kind string, data []byte) string {
	if (kind == "geoip" || kind == "asn") && bytes.Contains(data[max(0, len(data)-128*1024):], []byte("\xab\xcd\xefMaxMind.com")) {
		return "mmdb"
	}
	return "dat"
}

// Decode locked country MMDB assets into the same immutable IP index as DAT.
// Both GeoIP2 country records and sing-geoip's scalar country records work.
func decodeMMDB(code string, data []byte) ([]router.RuleSpec, error) {
	return decodeNetworkDB("geoip", code, data)
}
func decodeASN(code string, data []byte) ([]router.RuleSpec, error) {
	return decodeNetworkDB("asn", code, data)
}
func decodeNetworkDB(kind, code string, data []byte) ([]router.RuleSpec, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" || strings.Contains(code, "@") {
		return nil, fmt.Errorf("MMDB requires one country code")
	}
	var wantedASN uint64
	if kind == "asn" {
		var e error
		wantedASN, e = strconv.ParseUint(strings.TrimPrefix(code, "AS"), 10, 32)
		if e != nil || wantedASN == 0 {
			return nil, fmt.Errorf("invalid ASN; use 1–4294967295")
		}
	}
	db, err := maxminddb.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("invalid MMDB: %w", err)
	}
	defer db.Close()
	if err = db.Verify(); err != nil {
		return nil, fmt.Errorf("corrupt MMDB: %w", err)
	}
	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	var prefixes []string
	count := 0
	for networks.Next() {
		count++
		if count > 8*MaxEntries {
			return nil, fmt.Errorf("MMDB exceeds network budget")
		}
		var value any
		network, e := networks.Network(&value)
		if e != nil {
			return nil, e
		}
		country := ""
		switch record := value.(type) {
		case string:
			country = record
		case map[string]any:
			for _, key := range []string{"country", "registered_country", "represented_country"} {
				if nested, ok := record[key].(map[string]any); ok {
					if s, ok := nested["iso_code"].(string); ok && s != "" {
						country = s
						break
					}
				}
			}
		}
		matches := strings.EqualFold(country, code)
		if kind == "asn" {
			record, ok := value.(map[string]any)
			matches = false
			if ok {
				switch n := record["autonomous_system_number"].(type) {
				case uint64:
					matches = n == wantedASN
				case uint32:
					matches = uint64(n) == wantedASN
				case uint:
					matches = uint64(n) == wantedASN
				case int:
					matches = n > 0 && uint64(n) == wantedASN
				}
			}
		}
		if !matches {
			continue
		}
		ip, ok := netip.AddrFromSlice(network.IP)
		bits, total := network.Mask.Size()
		if !ok || bits < 0 {
			return nil, fmt.Errorf("invalid MMDB network")
		}
		if ip.Is4In6() {
			ip = ip.Unmap()
			if total == 128 {
				bits -= 96
			}
		}
		if bits < 0 || bits > ip.BitLen() {
			return nil, fmt.Errorf("invalid MMDB prefix")
		}
		if len(prefixes) >= MaxEntries {
			return nil, fmt.Errorf("matched MMDB prefixes exceed budget")
		}
		prefixes = append(prefixes, netip.PrefixFrom(ip, bits).Masked().String())
	}
	if err = networks.Err(); err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("selector not present in MMDB")
	}
	return checked([]router.RuleSpec{{Kind: router.KindIPCIDR, Values: prefixes}})
}
