package importer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/rulesdata"
)

// ImportBundle binds explicitly supplied geodata to the same resource snapshot
// as providers. It never uses geox-url or implicit global download locations.
func ImportBundle(req Request, payloads, geodata map[string][]byte) Result {
	refs, err := GeodataSelectors(req, payloads)
	if err != nil {
		return invalidBundle(req, err)
	}
	req.resourceNames = map[string]string{}
	for _, ref := range refs {
		kind, code, _ := strings.Cut(ref, ":")
		data, perCode := geodata[ref]
		if !perCode {
			data = geodata[kind]
		}
		if len(data) == 0 {
			return invalidBundle(req, fmt.Errorf("missing explicit %s resource", kind))
		}
		format := rulesdata.GeodataFormat(kind, data)
		if perCode && format != "srs" || !perCode && format == "srs" {
			return invalidBundle(req, fmt.Errorf("%s requires SRS for a per-code resource or DAT/MMDB for a whole database", ref))
		}
		if _, err := rulesdata.Decode(kind, format, code, data); err != nil {
			return invalidBundle(req, err)
		}
		id := StableID(kind, code)
		req.resourceNames[ref] = id
		req.ruleSets = append(req.ruleSets, object{"id": id, "behavior": kind, "format": format, "code": code, "hash": resource.Hash(data)})
	}
	return ImportProviders(req, payloads)
}

// GeodataSelectors returns the locked datasets needed by this conversion.
// It includes references from DNS policy and supplied classical rule sets.
func GeodataSelectors(req Request, payloads map[string][]byte) ([]string, error) {
	format := req.Format
	if format == "" || format == "auto" {
		format = detectFormat(req.Data)
	}
	if req.NodesOnly || format != "clash" {
		return nil, nil
	}
	root, err := checkedDocument([]byte(req.Data))
	if err != nil {
		return nil, err
	}
	refs := map[string]bool{}
	var collect func(router.RuleSpec)
	collect = func(r router.RuleSpec) {
		if r.Kind == router.KindRuleSet && len(r.Values) == 1 && (strings.HasPrefix(r.Values[0], "geoip:") || strings.HasPrefix(r.Values[0], "geosite:") || strings.HasPrefix(r.Values[0], "asn:")) {
			refs[r.Values[0]] = true
		}
		for _, ch := range r.Children {
			collect(ch)
		}
	}
	rules := get(root, "rules")
	if rules != nil {
		for _, n := range rules.Content {
			r, _, e := router.ParseClashRule(text(n))
			if e == nil {
				collect(r)
			}
		}
	}
	if blocks := get(root, "sub-rules"); blocks != nil {
		for i := 1; i < len(blocks.Content); i += 2 {
			for _, n := range blocks.Content[i].Content {
				r, _, e := router.ParseClashRule(text(n))
				if e == nil {
					collect(r)
				}
			}
		}
	}
	if cfg := get(root, "dns"); cfg != nil && text(get(cfg, "enable")) == "true" {
		if policies := get(cfg, "nameserver-policy"); policies != nil {
			for i := 0; i+1 < len(policies.Content); i += 2 {
				key := policies.Content[i].Value
				if strings.HasPrefix(key, "geosite:") {
					refs[strings.ToLower(key)] = true
				}
			}
		}
		if filters := get(cfg, "fake-ip-filter"); filters != nil {
			for _, v := range filters.Content {
				if strings.HasPrefix(text(v), "geosite:") {
					refs[strings.ToLower(text(v))] = true
				}
			}
		}
		if fallback := get(cfg, "fallback"); fallback != nil && len(fallback.Content) > 0 {
			filter := get(cfg, "fallback-filter")
			if sites := get(filter, "geosite"); sites != nil {
				for _, v := range sites.Content {
					refs["geosite:"+strings.ToLower(text(v))] = true
				}
			}
			if get(filter, "geoip") == nil || text(get(filter, "geoip")) == "true" {
				code := strings.ToLower(text(get(filter, "geoip-code")))
				if code == "" {
					code = "cn"
				}
				refs["geoip:"+code] = true
			}
		}
	}
	ps, err := Providers(req)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		if p.Kind == "rule" && p.Behavior == "classical" && p.Format != "srs" {
			specs, e := rulesdata.Decode(p.Behavior, p.Format, "", payloads[p.ID])
			if e != nil {
				return nil, e
			}
			for _, r := range specs {
				collect(r)
			}
		}
	}
	// Sort refs so map iteration never affects source snapshots or fingerprints.
	return sortedNames(refs), nil
}

func sortedNames(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
