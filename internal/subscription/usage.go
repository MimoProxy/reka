package subscription

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/api"
)

// responseUsage parses only the root subscription account declaration. A 304
// may update individual fields; omitted fields retain the prior declaration.
// Ambiguous/invalid known fields become unknown without rejecting valid nodes.
func responseUsage(values []string, previous *api.SubscriptionUsage, notModified bool, now time.Time) *api.SubscriptionUsage {
	if len(values) == 0 {
		if notModified {
			return previous
		}
		return nil
	}
	var out api.SubscriptionUsage
	if notModified && previous != nil {
		out = *previous
	}
	out.ObservedAt = now
	seen, invalid := map[string]bool{}, map[string]bool{}
	if notModified && previous != nil {
		for _, field := range previous.InvalidFields {
			invalid[field] = true
		}
	}
	size := 0
	for _, value := range values {
		size += len(value)
	}
	if size > 8192 {
		return &api.SubscriptionUsage{ObservedAt: now, InvalidFields: []string{"header"}}
	}
	for _, value := range values {
		for _, token := range strings.Split(value, ";") {
			key, raw, found := strings.Cut(token, "=")
			key = strings.ToLower(strings.TrimSpace(key))
			var target **uint64
			switch key {
			case "upload":
				target = &out.Upload
			case "download":
				target = &out.Download
			case "total":
				target = &out.Total
			case "expire":
				target = &out.ExpireUnix
			default:
				continue
			}
			duplicate := seen[key]
			seen[key] = true
			raw = strings.TrimSpace(raw)
			validDecimal := raw != ""
			for _, ch := range raw {
				if ch < '0' || ch > '9' {
					validDecimal = false
					break
				}
			}
			n, err := strconv.ParseUint(raw, 10, 64)
			if duplicate || !found || !validDecimal || err != nil || (key == "expire" && n > 253402300799) {
				*target = nil
				invalid[key] = true
				continue
			}
			*target = &n
			delete(invalid, key)
		}
	}
	out.InvalidFields = nil
	for key := range invalid {
		out.InvalidFields = append(out.InvalidFields, key)
	}
	sort.Strings(out.InvalidFields)
	if len(seen) == 0 {
		if notModified {
			return previous
		}
		return nil
	}
	return &out
}
