package rulesdata

import (
	"fmt"
	"strings"

	"github.com/MimoProxy/reka/internal/resource"
	"github.com/oschwald/maxminddb-golang"
	"google.golang.org/protobuf/encoding/protowire"
)

// ValidateDatabase checks the complete container before pinning an unused asset.
// Individual selectors are fully decoded when referenced by a routing/DNS rule.
func ValidateDatabase(kind, format string, data []byte) error {
	if len(data) == 0 || len(data) > resource.MaxSize {
		return fmt.Errorf("database size outside 128 MiB limit")
	}
	if (kind == "geoip" || kind == "asn") && format == "mmdb" {
		db, err := openMMDB(data)
		if err != nil {
			return err
		}
		defer db.Close()
		networks := db.Networks(maxminddb.SkipAliasedNetworks)
		if !networks.Next() {
			return fmt.Errorf("empty MMDB")
		}
		var record any
		if _, err = networks.Network(&record); err != nil {
			return err
		}
		if kind == "asn" {
			value, _ := record.(map[string]any)
			if value["autonomous_system_number"] == nil {
				return fmt.Errorf("MMDB does not contain ASN records")
			}
		} else if strings.TrimSpace(mmdbRecordCode(kind, record)) == "" {
			return fmt.Errorf("MMDB does not contain country records")
		}
		return nil
	}
	if (kind != "geoip" && kind != "geosite" && kind != "asn") || format != "dat" {
		return fmt.Errorf("unsupported database kind/format")
	}
	top, err := fieldsTyped(data, protowire.BytesType)
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range top {
		if entry.n != 1 {
			continue
		}
		record, err := fieldsTyped(entry.b, protowire.BytesType, protowire.BytesType, protowire.VarintType)
		if err != nil {
			return err
		}
		found := false
		for _, field := range record {
			if field.n == 1 && len(field.b) > 0 {
				if kind == "asn" {
					code, err := asnCode(string(field.b))
					if err != nil || code != string(field.b) {
						return fmt.Errorf("ASN DAT requires numeric codes")
					}
				}
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
