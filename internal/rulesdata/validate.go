package rulesdata

import (
	"fmt"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/oschwald/maxminddb-golang"
	"strings"
)

// ValidateDatabase checks the complete container before pinning an unused asset.
// Individual selectors are fully decoded when referenced by a routing/DNS rule.
func ValidateDatabase(kind, format string, data []byte) error {
	if len(data) == 0 || len(data) > resource.MaxSize {
		return fmt.Errorf("database size outside 128 MiB limit")
	}
	if (kind == "geoip" || kind == "asn") && format == "mmdb" {
		db, err := maxminddb.FromBytes(data)
		if err != nil {
			return fmt.Errorf("invalid MMDB: %w", err)
		}
		defer db.Close()
		if err = db.Verify(); err != nil {
			return fmt.Errorf("corrupt MMDB: %w", err)
		}
		networks := db.Networks(maxminddb.SkipAliasedNetworks)
		if !networks.Next() {
			return fmt.Errorf("empty MMDB")
		}
		var record any
		if _, err = networks.Network(&record); err != nil {
			return err
		}
		if kind == "asn" {
			value, ok := record.(map[string]any)
			if !ok || value["autonomous_system_number"] == nil {
				return fmt.Errorf("MMDB does not contain ASN records")
			}
		} else {
			valid := false
			switch value := record.(type) {
			case string:
				valid = strings.TrimSpace(value) != ""
			case map[string]any:
				for _, key := range []string{"country", "registered_country", "represented_country"} {
					if country, ok := value[key].(map[string]any); ok && country["iso_code"] != nil {
						valid = true
					}
				}
			}
			if !valid {
				return fmt.Errorf("MMDB does not contain country records")
			}
		}
		return nil
	}
	if (kind != "geoip" && kind != "geosite") || format != "dat" {
		return fmt.Errorf("unsupported database kind/format")
	}
	top, err := fields(data)
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range top {
		if entry.n != 1 {
			continue
		}
		record, err := fields(entry.b)
		if err != nil {
			return err
		}
		found := false
		for _, field := range record {
			if field.n == 1 && len(field.b) > 0 {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("database record has no code")
		}
		count++
	}
	if count == 0 {
		return fmt.Errorf("empty database")
	}
	return nil
}
