package rulesdata

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/router"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

func srsData(t testing.TB, version uint8, rules ...option.HeadlessRule) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := srs.Write(&b, option.PlainRuleSet{Rules: rules}, version); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func srsDefault(rule option.DefaultHeadlessRule) option.HeadlessRule {
	return option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: rule}
}

func srsLogic(mode string, invert bool, rules ...option.HeadlessRule) option.HeadlessRule {
	return option.HeadlessRule{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalHeadlessRule{Mode: mode, Invert: invert, Rules: rules}}
}

func loadRuleSet(t *testing.T, behavior, format string, data []byte) *router.RuleSet {
	t.Helper()
	var builder router.ConditionSetBuilder
	err := Walk(behavior, format, "", data, builder.Add, func(kind router.Kind, value string) error {
		return builder.AddDomain(kind, value)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	set, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func ruleSetRouter(t *testing.T, set *router.RuleSet, noResolve bool) *router.Router {
	t.Helper()
	rules, err := router.CompileRules([]router.RuleSpec{{Kind: router.KindRuleSet, Values: []string{"sites"}, Set: set, Target: "hit", NoResolve: noResolve}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := router.New(rules, router.Options{Outbounds: []string{"hit", "miss"}, Final: "miss"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSRSDomainVersionsMatchText(t *testing.T) {
	text := []byte("exact.test\n+.suffix.test\n.strict.test\ncafé.test\n")
	want := ruleSetRouter(t, loadRuleSet(t, "domain", "text", text), false)
	for version := uint8(C.RuleSetVersion1); version <= C.RuleSetVersionCurrent; version++ {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			data := srsData(t, version, srsDefault(option.DefaultHeadlessRule{
				Domain: []string{"exact.test", "café.test"}, DomainSuffix: []string{"suffix.test", ".strict.test"},
			}))
			got := ruleSetRouter(t, loadRuleSet(t, "domain", "srs", data), false)
			for domain, hit := range map[string]bool{
				"EXACT.test.": true, "café.test": true, "x.exact.test": false, "exact.test.evil": false,
				"suffix.test": true, "x.suffix.test": true, "bad-suffix.test": false, "suffix.test.evil": false,
				"strict.test": false, "a.b.strict.test": true, "bad-strict.test": false, "": false,
			} {
				md := router.Metadata{Domain: router.NormalizeDomain(domain)}
				a, b := got.Route(t.Context(), md, nil).Outbound == "hit", want.Route(t.Context(), md, nil).Outbound == "hit"
				if a != hit || b != hit {
					t.Errorf("%q: SRS=%t text=%t want=%t", domain, a, b, hit)
				}
			}
		})
	}
}

type srsTestEnv string

func (p srsTestEnv) Process(context.Context) (string, bool) { return string(p), p != "" }
func (p srsTestEnv) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
}

func TestSRSClassicalMatchesText(t *testing.T) {
	composite := srsDefault(option.DefaultHeadlessRule{
		Network: []string{"udp"}, Domain: []string{"exact.test"}, DomainKeyword: []string{"allowed"},
		DomainRegex: []string{`^rx[0-9]+\.test$`}, IPCIDR: []string{"192.0.2.0/24", "2001:db8::/32", "::ffff:198.18.8.0/120"},
		SourceIPCIDR: []string{"198.51.100.0/24", "2001:db8:1::/48", "::ffff:10.80.0.0/112"}, Port: []uint16{53},
		PortRange: []string{"80:90", "60000:"}, SourcePort: []uint16{5353}, SourcePortRange: []string{":20"},
	})
	process := srsLogic(C.LogicalTypeOr, false,
		srsDefault(option.DefaultHeadlessRule{ProcessName: []string{"browser"}}),
		srsDefault(option.DefaultHeadlessRule{ProcessPath: []string{`/opt/apps/client`}}),
		srsDefault(option.DefaultHeadlessRule{ProcessPathRegex: []string{`^/opt/tools/worker[0-9]+$`}}),
	)
	logic := srsLogic(C.LogicalTypeAnd, false, srsDefault(option.DefaultHeadlessRule{DomainSuffix: []string{"logic.test"}}),
		srsLogic(C.LogicalTypeOr, true,
			srsDefault(option.DefaultHeadlessRule{Network: []string{"tcp"}}),
			srsDefault(option.DefaultHeadlessRule{Port: []uint16{443}}),
		),
		srsDefault(option.DefaultHeadlessRule{SourcePort: []uint16{100}, Invert: true}),
	)
	source := `AND,((NETWORK,UDP),(OR,((DOMAIN,exact.test),(DOMAIN-KEYWORD,allowed),(DOMAIN-REGEX,^rx[0-9]+\.test$),(IP-CIDR,192.0.2.0/24),(IP-CIDR6,2001:db8::/32),(IP-CIDR6,::ffff:198.18.8.0/120))),(OR,((SRC-IP-CIDR,198.51.100.0/24),(SRC-IP-CIDR,2001:db8:1::/48),(SRC-IP-CIDR,::ffff:10.80.0.0/112))),(OR,((DST-PORT,53),(DST-PORT,80-90),(DST-PORT,60000-65535))),(OR,((SRC-PORT,5353),(SRC-PORT,0-20))))
PROCESS-NAME,browser
PROCESS-PATH,/opt/apps/client
PROCESS-PATH-REGEX,^/opt/tools/worker[0-9]+$
AND,((DOMAIN-SUFFIX,logic.test),(NOT,(OR,((NETWORK,TCP),(DST-PORT,443)))),(NOT,(SRC-PORT,100)))
`
	decoded := loadRuleSet(t, "classical", "srs", srsData(t, C.RuleSetVersionCurrent, composite, process, logic))
	if !decoded.NeedsProcess() || !decoded.MatchesDomain() {
		t.Fatal("missing SRS rule metadata")
	}
	ref := loadRuleSet(t, "classical", "text", []byte(source))
	got, want := ruleSetRouter(t, decoded, true), ruleSetRouter(t, ref, true)
	for _, tc := range []struct {
		name, domain, addr, source, network, process string
		port                                         uint16
		hit                                          bool
	}{
		{name: "exact and scalar ports", domain: "exact.test", source: "198.51.100.1:5353", network: "udp", port: 53, hit: true},
		{name: "keyword and ranges", domain: "allowed.test", source: "198.51.100.2:14", network: "udp", port: 87, hit: true},
		{name: "regex and open ranges", domain: "rx23.test", source: "[2001:db8:1::1]:20", network: "udp", port: 64000, hit: true},
		{name: "destination alternative", domain: "other.test", addr: "192.0.2.10", source: "198.51.100.3:5353", network: "udp", port: 53, hit: true},
		{name: "IPv6 destination alternative", addr: "2001:db8::20", source: "198.51.100.3:5353", network: "udp", port: 53, hit: true},
		{name: "mapped prefixes", addr: "198.18.8.5", source: "10.80.0.3:5353", network: "udp", port: 53, hit: true},
		{name: "no resolve", domain: "other.test", source: "198.51.100.3:5353", network: "udp", port: 53},
		{name: "source outside range", domain: "exact.test", source: "203.0.113.1:5353", network: "udp", port: 53},
		{name: "source port outside range", domain: "exact.test", source: "198.51.100.2:21", network: "udp", port: 53},
		{name: "port outside range", domain: "exact.test", source: "198.51.100.2:5353", network: "udp", port: 91},
		{name: "network mismatch", domain: "exact.test", source: "198.51.100.2:5353", network: "tcp", port: 53},
		{name: "process name", process: "/some/path/browser", hit: true},
		{name: "process path", process: "/opt/apps/client", hit: true},
		{name: "process regex", process: "/opt/tools/worker27", hit: true},
		{name: "other process", process: "/opt/work/worker27"},
		{name: "nested logic", domain: "a.logic.test", source: "198.51.100.1:101", network: "udp", port: 53, hit: true},
		{name: "inverted default", domain: "a.logic.test", source: "198.51.100.1:100", network: "udp", port: 53},
		{name: "inverted logical network", domain: "a.logic.test", network: "tcp", port: 53},
		{name: "inverted logical port", domain: "a.logic.test", network: "udp", port: 443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			md := router.Metadata{Domain: tc.domain, Network: tc.network, Port: tc.port}
			if tc.source != "" {
				md.Source = netip.MustParseAddrPort(tc.source)
			}
			if tc.addr != "" {
				md.Addr = netip.MustParseAddr(tc.addr)
			}
			for name, r := range map[string]*router.Router{"SRS": got, "text": want} {
				if hit := r.Route(t.Context(), md, srsTestEnv(tc.process)).Outbound == "hit"; hit != tc.hit {
					t.Errorf("%s match = %t, want %t", name, hit, tc.hit)
				}
			}
		})
	}
	got, want = ruleSetRouter(t, decoded, false), ruleSetRouter(t, ref, false)
	md := router.Metadata{Domain: "other.test", Source: netip.MustParseAddrPort("198.51.100.3:5353"), Network: "udp", Port: 53}
	if got.Route(t.Context(), md, srsTestEnv("")).Outbound != "hit" || want.Route(t.Context(), md, srsTestEnv("")).Outbound != "hit" {
		t.Fatal("both IP rule sets should match a resolved address")
	}
}

func TestSRSRejectsUnsupportedConditions(t *testing.T) {
	prefix := badoption.Prefixable(netip.MustParsePrefix("192.0.2.0/24"))
	interfaceType := option.InterfaceType(C.InterfaceTypeWIFI)
	var byType badjson.TypedMap[option.InterfaceType, badoption.Listable[*badoption.Prefixable]]
	byType.Put(interfaceType, []*badoption.Prefixable{&prefix})
	for key, rule := range map[string]option.DefaultHeadlessRule{
		"query_type":                {QueryType: []option.DNSQueryType{1}},
		"package_name":              {PackageName: []string{"com.example.app"}},
		"package_name_regex":        {PackageNameRegex: []string{`^com\.example\.`}},
		"wifi_ssid":                 {WIFISSID: []string{"network"}},
		"wifi_bssid":                {WIFIBSSID: []string{"02:00:00:00:00:01"}},
		"network_type":              {NetworkType: []option.InterfaceType{interfaceType}},
		"network_is_expensive":      {NetworkIsExpensive: true},
		"network_is_constrained":    {NetworkIsConstrained: true},
		"network_interface_address": {NetworkInterfaceAddress: &byType},
		"default_interface_address": {DefaultInterfaceAddress: []*badoption.Prefixable{&prefix}},
		"adguard_domain":            {AdGuardDomain: []string{"||ads.example^"}},
	} {
		t.Run(key, func(t *testing.T) {
			rule.Domain = []string{"allowed.test"}
			data := srsData(t, C.RuleSetVersionCurrent, srsLogic(C.LogicalTypeAnd, false, srsDefault(rule)))
			if _, err := Decode("classical", "srs", "", data); err == nil || !strings.Contains(err.Error(), "unsupported SRS condition "+key) {
				t.Fatalf("expected a diagnostic for %s, got %v", key, err)
			}
		})
	}
}

func srsWireData(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write(srs.MagicBytes[:])
	b.WriteByte(C.RuleSetVersionCurrent)
	z := zlib.NewWriter(&b)
	if _, err := z.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestSRSRejectsMalformedResources(t *testing.T) {
	data := srsData(t, C.RuleSetVersionCurrent, srsDefault(option.DefaultHeadlessRule{Domain: []string{"exact.test"}}))
	magic, version, checksum := bytes.Clone(data), bytes.Clone(data), bytes.Clone(data)
	magic[0] ^= 1
	version[3] = C.RuleSetVersionCurrent + 1
	checksum[len(checksum)-1] ^= 1
	for _, tc := range []struct {
		name, message string
		data          []byte
	}{
		{"magic", "magic", magic},
		{"version", "unsupported SRS version", version},
		{"checksum", "checksum", checksum},
		{"trailing bytes", "trailing", append(bytes.Clone(data), 0)},
		{"empty", "empty SRS", srsData(t, C.RuleSetVersionCurrent)},
		{"too many rules", "too many SRS entries", srsWireData(t, binary.AppendUvarint(nil, MaxEntries+1))},
		{"too many values", "too many SRS entries", srsWireData(t, binary.AppendUvarint([]byte{1, 0, srsNetwork}, MaxEntries+1))},
		{"expanded size", "expanded size limit", srsWireData(t, binary.AppendUvarint([]byte{1, 0, srsNetwork, 1}, MaxExpanded+1))},
		{"malformed matcher", "invalid SRS domain matcher", srsWireData(t, []byte{1, 0, srsDomain, 0x80})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode("classical", "srs", "", tc.data); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("expected %q, got %v", tc.message, err)
			}
		})
	}
	for n := range len(data) {
		if _, err := Decode("domain", "srs", "", data[:n]); err == nil {
			t.Fatalf("accepted truncated SRS at byte %d", n)
		}
	}
	var visited bool
	err := WalkWithBudget("domain", "srs", "", data, func(router.RuleSpec) error { visited = true; return nil }, nil, nil, func(n int) error {
		if n != 2 {
			t.Fatalf("expected one rule and one value, got %d entries", n)
		}
		return errSRSEntries
	})
	if err != errSRSEntries || visited {
		t.Fatalf("expected the shared entry budget to stop decoding, got %v", err)
	}
}

func TestSRSLoadingAllocatesLessThanText(t *testing.T) {
	domains := make([]string, 100_000)
	for i := range domains {
		domains[i] = fmt.Sprintf("region%06d.content.edge.example", i)
	}
	data := srsData(t, C.RuleSetVersionCurrent, srsDefault(option.DefaultHeadlessRule{Domain: domains}))
	text := []byte(strings.Join(domains, "\n"))
	load := func(format string, raw []byte) (*router.RuleSet, uint64) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		set := loadRuleSet(t, "domain", format, raw)
		runtime.ReadMemStats(&after)
		return set, after.TotalAlloc - before.TotalAlloc
	}
	compactSet, compactAlloc := load("srs", data)
	textSet, textAlloc := load("text", text)
	compactRetained, textRetained := compactSet.EstimateMemory().Bytes, textSet.EstimateMemory().Bytes
	t.Logf("100,000 domains: SRS/text file bytes %d/%d, allocated %d/%d, estimated retained %d/%d", len(data), len(text), compactAlloc, textAlloc, compactRetained, textRetained)
	if compactAlloc >= textAlloc/3 || compactRetained >= textRetained/3 || compactRetained < uint64(len(data)) {
		t.Fatal("SRS allocations or retained size did not meet expectations")
	}
	for _, set := range []*router.RuleSet{compactSet, textSet} {
		r := ruleSetRouter(t, set, false)
		for _, i := range []int{0, len(domains) / 2, len(domains) - 1} {
			if r.Route(t.Context(), router.Metadata{Domain: domains[i]}, nil).Outbound != "hit" {
				t.Fatal("missing loaded domain", domains[i])
			}
		}
	}
}
