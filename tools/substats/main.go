// Command substats counts which Clash subscription fields real
// subscriptions use, to decide the import scope. It reads Clash YAML files
// and prints aggregate counts only: field names, and values of an allowlist
// of non-identifying enum fields. Servers, credentials, names, URLs and
// paths are never printed.
//
// With -sanitize DIR it also writes a copy of each input with every
// identifying value replaced, for use as a test corpus.
//
//	go run ./tools/substats [-sanitize DIR] FILE...
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

func main() {
	sanitizeDir := flag.String("sanitize", "", "write sanitized copies of the inputs into this directory")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: substats [-sanitize DIR] FILE...")
		os.Exit(2)
	}
	st := newStats()
	for i, path := range flag.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			fatal(err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			fmt.Fprintf(os.Stderr, "file %d: not YAML (%v); skipped\n", i+1, err)
			continue
		}
		root := docRoot(&doc)
		if root == nil || root.Kind != yaml.MappingNode {
			fmt.Fprintf(os.Stderr, "file %d: not a Clash mapping; skipped\n", i+1)
			continue
		}
		st.add(root)
		if *sanitizeDir != "" {
			if err := writeSanitized(*sanitizeDir, i+1, &doc); err != nil {
				fatal(err)
			}
		}
	}
	st.print(os.Stdout)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func docRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	return nil
}

// mapGet returns the value for key in a mapping node.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// counter counts occurrences and, separately, how many files had each key.
type counter struct {
	n     map[string]int
	files map[string]int
	seen  map[string]bool
}

func newCounter() *counter {
	return &counter{n: map[string]int{}, files: map[string]int{}, seen: map[string]bool{}}
}

func (c *counter) inc(key string) {
	c.n[key]++
	if !c.seen[key] {
		c.seen[key] = true
		c.files[key]++
	}
}

func (c *counter) endFile() { c.seen = map[string]bool{} }

type stats struct {
	files int
	top   *counter

	proxies       int
	proxyType     *counter
	proxyField    map[string]*counter // by type
	proxyEnum     *counter            // "type.field=value"
	groups        int
	groupType     *counter
	groupField    *counter
	groupEnum     *counter
	rules         int
	ruleType      *counter
	ruleParam     *counter
	ruleGeo       *counter
	ruleLogical   *counter
	dnsField      *counter
	dnsEnum       *counter
	dnsServer     *counter // scheme by field
	dnsPolicyKey  *counter
	providerField *counter
	providerEnum  *counter
	perFile       []fileSummary
}

type fileSummary struct {
	proxies, groups, rules, proxyProviders, ruleProviders int
	hasDNS                                                bool
}

func newStats() *stats {
	return &stats{
		top: newCounter(), proxyType: newCounter(), proxyField: map[string]*counter{},
		proxyEnum: newCounter(), groupType: newCounter(), groupField: newCounter(), groupEnum: newCounter(),
		ruleType: newCounter(), ruleParam: newCounter(), ruleGeo: newCounter(), ruleLogical: newCounter(),
		dnsField: newCounter(), dnsEnum: newCounter(), dnsServer: newCounter(), dnsPolicyKey: newCounter(),
		providerField: newCounter(), providerEnum: newCounter(),
	}
}

func (s *stats) all() []*counter {
	cs := []*counter{s.top, s.proxyType, s.proxyEnum, s.groupType, s.groupField, s.groupEnum, s.ruleType,
		s.ruleParam, s.ruleGeo, s.ruleLogical, s.dnsField, s.dnsEnum, s.dnsServer, s.dnsPolicyKey,
		s.providerField, s.providerEnum}
	for _, c := range s.proxyField {
		cs = append(cs, c)
	}
	return cs
}

// Values of these proxy fields are protocol options, not identifiers, so
// their distribution is printed. Everything else is counted by name only.
var proxyEnumFields = map[string]bool{
	"network": true, "cipher": true, "flow": true, "tls": true, "udp": true,
	"client-fingerprint": true, "skip-cert-verify": true, "packet-encoding": true,
	"plugin": true, "obfs": true, "protocol": true, "xudp": true, "udp-over-tcp": true,
	"ip-version": true, "encryption": true, "tfo": true, "mptcp": true, "alpn": true,
	"version": true, "congestion-controller": true, "udp-relay-mode": true,
	"reality-opts.support-x25519mlkem768": true, "smux.enabled": true, "smux.protocol": true,
	"plugin-opts.mode": true, "plugin-opts.tls": true, "plugin-opts.mux": true,
	"ws-opts.v2ray-http-upgrade": true, "grpc-opts.grpc-service-name": false,
	"alterId": true, "authenticated-length": true, "global-padding": true,
	"up": false, "down": false, "fast-open": true, "reduce-rtt": true,
	"heartbeat-interval": false, "disable-sni": true, "obfs-password": false,
}

var groupEnumFields = map[string]bool{
	"type": true, "strategy": true, "lazy": true, "include-all": true, "include-all-proxies": true,
	"include-all-providers": true, "disable-udp": true, "hidden": true, "expected-status": true,
	"tolerance": true, "interval": true, "timeout": true, "max-failed-times": true,
}

var dnsEnumFields = map[string]bool{
	"enable": true, "ipv6": true, "enhanced-mode": true, "use-hosts": true, "use-system-hosts": true,
	"respect-rules": true, "prefer-h3": true, "cache-algorithm": true, "fake-ip-filter-mode": true,
	"fallback-filter.geoip": true, "fallback-filter.geoip-code": true, "direct-nameserver-follow-policy": true,
}

var providerEnumFields = map[string]bool{
	"type": true, "behavior": true, "format": true, "interval": true,
	"health-check.enable": true, "health-check.lazy": true, "health-check.interval": true,
}

func (s *stats) add(root *yaml.Node) {
	s.files++
	var fs fileSummary
	for i := 0; i+1 < len(root.Content); i += 2 {
		s.top.inc(root.Content[i].Value)
	}
	if p := mapGet(root, "proxies"); p != nil && p.Kind == yaml.SequenceNode {
		for _, px := range p.Content {
			s.addProxy(px)
			fs.proxies++
		}
	}
	if g := mapGet(root, "proxy-groups"); g != nil && g.Kind == yaml.SequenceNode {
		for _, grp := range g.Content {
			s.addGroup(grp)
			fs.groups++
		}
	}
	if r := mapGet(root, "rules"); r != nil && r.Kind == yaml.SequenceNode {
		for _, rule := range r.Content {
			s.addRule(rule.Value)
			fs.rules++
		}
	}
	if d := mapGet(root, "dns"); d != nil && d.Kind == yaml.MappingNode {
		fs.hasDNS = true
		s.addDNS(d)
	}
	for _, kind := range []string{"proxy-providers", "rule-providers"} {
		if pp := mapGet(root, kind); pp != nil && pp.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(pp.Content); i += 2 {
				s.addProvider(kind, pp.Content[i+1])
				if kind == "proxy-providers" {
					fs.proxyProviders++
				} else {
					fs.ruleProviders++
				}
			}
		}
	}
	s.perFile = append(s.perFile, fs)
	for _, c := range s.all() {
		c.endFile()
	}
}

// flatten visits every leaf under m with dotted paths; sequences of
// scalars end the path with "[]".
func flatten(prefix string, n *yaml.Node, visit func(path string, v *yaml.Node)) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			p := n.Content[i].Value
			if prefix != "" {
				p = prefix + "." + p
			}
			flatten(p, n.Content[i+1], visit)
		}
	case yaml.SequenceNode:
		if len(n.Content) == 0 {
			visit(prefix+"[]", n)
			return
		}
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				visit(prefix+"[]", c)
			} else {
				flatten(prefix+"[]", c, visit)
			}
		}
	default:
		visit(prefix, n)
	}
}

// isHeaderKey folds user-chosen map keys (HTTP headers) into one path.
func normalizePath(path string) string {
	for _, h := range []string{"ws-opts.headers.", "http-opts.headers.", "h2-opts.headers."} {
		if strings.HasPrefix(path, h) {
			return h + "<header>"
		}
	}
	return path
}

func (s *stats) addProxy(px *yaml.Node) {
	s.proxies++
	typ := "?"
	if t := mapGet(px, "type"); t != nil {
		typ = t.Value
	}
	s.proxyType.inc(typ)
	fc := s.proxyField[typ]
	if fc == nil {
		fc = newCounter()
		s.proxyField[typ] = fc
	}
	seen := map[string]bool{}
	flatten("", px, func(path string, v *yaml.Node) {
		path = normalizePath(path)
		if !seen[path] {
			seen[path] = true
			fc.inc(path)
		}
		key := strings.TrimSuffix(path, "[]")
		if proxyEnumFields[key] {
			s.proxyEnum.inc(typ + "." + key + "=" + v.Value)
		}
	})
}

func (s *stats) addGroup(g *yaml.Node) {
	s.groups++
	typ := "?"
	if t := mapGet(g, "type"); t != nil {
		typ = t.Value
	}
	s.groupType.inc(typ)
	seen := map[string]bool{}
	flatten("", g, func(path string, v *yaml.Node) {
		if !seen[path] {
			seen[path] = true
			s.groupField.inc(path)
		}
		if groupEnumFields[path] {
			s.groupEnum.inc(path + "=" + v.Value)
		}
	})
	if u := mapGet(g, "url"); u != nil {
		s.groupEnum.inc("url-host=" + urlHost(u.Value))
	}
}

// urlHost keeps only the host of health-check URLs, which are public
// probe endpoints (gstatic, cp.cloudflare.com and the like).
func urlHost(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, "/?"); i >= 0 {
		u = u[:i]
	}
	return u
}

// splitRule splits a Clash rule on top-level commas (logical rules nest
// parenthesised sub-rules).
func splitRule(r string) []string {
	var parts []string
	depth, start := 0, 0
	for i, c := range r {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(r[start:i]))
				start = i + 1
			}
		}
	}
	return append(parts, strings.TrimSpace(r[start:]))
}

var knownRuleParams = map[string]bool{"no-resolve": true, "src": true}

func (s *stats) addRule(rule string) {
	s.rules++
	parts := splitRule(rule)
	typ := strings.ToUpper(parts[0])
	s.ruleType.inc(typ)
	switch typ {
	case "AND", "OR", "NOT":
		s.addLogical(logicalArg(parts))
	case "GEOSITE", "GEOIP", "SRC-GEOIP":
		if len(parts) > 1 {
			s.ruleGeo.inc(typ + ":" + strings.ToLower(parts[1]))
		}
	}
	if !isLogical(typ) && typ != "MATCH" && typ != "FINAL" && len(parts) > 3 {
		for _, p := range parts[3:] {
			if knownRuleParams[p] {
				s.ruleParam.inc(typ + "," + p)
			} else {
				s.ruleParam.inc(typ + ",<other>")
			}
		}
	}
}

func (s *stats) addLogical(arg string) {
	for _, item := range logicalItems(arg) {
		typ, rest := subRule(item)
		s.ruleLogical.inc("sub:" + typ)
		if isLogical(typ) {
			s.addLogical(rest)
			continue
		}
		switch typ {
		case "GEOSITE", "GEOIP", "SRC-GEOIP":
			s.ruleGeo.inc(typ + ":" + strings.ToLower(strings.TrimSpace(rest)))
		}
	}
}

// dnsScheme classifies a nameserver without its address.
func dnsScheme(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "#"); i >= 0 {
		v = v[:i] + "#<param>"
	}
	switch {
	case strings.Contains(v, "://"):
		return v[:strings.Index(v, "://")] + "://" + hostKind(v[strings.Index(v, "://")+3:]) + tail(v)
	case v == "system" || v == "dhcp" || strings.HasPrefix(v, "dhcp"):
		return v
	default:
		return "udp(bare)://" + hostKind(v) + tail(v)
	}
}

func tail(v string) string {
	if strings.Contains(v, "#<param>") {
		return "#<param>"
	}
	return ""
}

func hostKind(h string) string {
	if i := strings.IndexAny(h, "/#"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimPrefix(h, "[")
	if strings.Count(h, ":") >= 2 {
		return "ipv6"
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	for _, c := range h {
		if (c < '0' || c > '9') && c != '.' {
			return "domain"
		}
	}
	return "ipv4"
}

func (s *stats) addDNS(d *yaml.Node) {
	flatten("", d, func(path string, v *yaml.Node) {
		key := strings.TrimSuffix(path, "[]")
		if strings.HasPrefix(key, "nameserver-policy.") {
			s.dnsField.inc("nameserver-policy.<key>")
			return
		}
		if strings.HasPrefix(key, "hosts.") {
			s.dnsField.inc("hosts.<key>")
			return
		}
		s.dnsField.inc(path)
		if dnsEnumFields[key] {
			s.dnsEnum.inc(key + "=" + v.Value)
		}
		switch key {
		case "nameserver", "fallback", "default-nameserver", "proxy-server-nameserver", "direct-nameserver":
			s.dnsServer.inc(key + ": " + dnsScheme(v.Value))
		}
	})
	if np := mapGet(d, "nameserver-policy"); np != nil && np.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(np.Content); i += 2 {
			k := np.Content[i].Value
			kind := "domain"
			switch {
			case strings.HasPrefix(k, "geosite:"):
				kind = "geosite:<code>"
			case strings.HasPrefix(k, "rule-set:"):
				kind = "rule-set:<name>"
			case strings.HasPrefix(k, "+."):
				kind = "+.<domain>"
			case strings.HasPrefix(k, "*."):
				kind = "*.<domain>"
			case strings.Contains(k, ","):
				kind = "list"
			}
			s.dnsPolicyKey.inc(kind)
		}
	}
	if f := mapGet(d, "fake-ip-filter"); f != nil {
		s.dnsEnum.inc(fmt.Sprintf("fake-ip-filter entries=%s", bucket(len(f.Content))))
	}
}

func bucket(n int) string {
	switch {
	case n == 0:
		return "0"
	case n <= 10:
		return "1-10"
	case n <= 50:
		return "11-50"
	default:
		return ">50"
	}
}

func (s *stats) addProvider(kind string, p *yaml.Node) {
	seen := map[string]bool{}
	flatten("", p, func(path string, v *yaml.Node) {
		if !seen[path] {
			seen[path] = true
			s.providerField.inc(kind + ": " + path)
		}
		if providerEnumFields[path] {
			s.providerEnum.inc(kind + ": " + path + "=" + v.Value)
		}
	})
}

// --- output ---

func (s *stats) print(w io.Writer) {
	fmt.Fprintf(w, "# Subscription field frequency\n\n%d files, %d proxies, %d proxy groups, %d rules.\n\n", s.files, s.proxies, s.groups, s.rules)
	fmt.Fprintln(w, "| file | proxies | groups | rules | proxy-providers | rule-providers | dns |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- |")
	for i, f := range s.perFile {
		fmt.Fprintf(w, "| %d | %d | %d | %d | %d | %d | %v |\n", i+1, f.proxies, f.groups, f.rules, f.proxyProviders, f.ruleProviders, f.hasDNS)
	}
	section(w, "Top-level keys", s.top, "key")
	section(w, "Proxy types", s.proxyType, "type")
	types := sortedKeys(s.proxyField)
	for _, t := range types {
		section(w, "Proxy fields: "+t, s.proxyField[t], "field")
	}
	section(w, "Proxy option values", s.proxyEnum, "type.field=value")
	section(w, "Proxy group types", s.groupType, "type")
	section(w, "Proxy group fields", s.groupField, "field")
	section(w, "Proxy group option values", s.groupEnum, "field=value")
	section(w, "Rule types", s.ruleType, "type")
	section(w, "Rule parameters", s.ruleParam, "type,param")
	section(w, "Sub-rules inside AND/OR/NOT", s.ruleLogical, "sub-rule type")
	section(w, "GEOSITE/GEOIP codes", s.ruleGeo, "code")
	section(w, "DNS fields", s.dnsField, "field")
	section(w, "DNS option values", s.dnsEnum, "field=value")
	section(w, "DNS servers (scheme and address kind only)", s.dnsServer, "field: scheme")
	section(w, "nameserver-policy key kinds", s.dnsPolicyKey, "kind")
	section(w, "Provider fields", s.providerField, "kind: field")
	section(w, "Provider option values", s.providerEnum, "kind: field=value")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func section(w io.Writer, title string, c *counter, label string) {
	if len(c.n) == 0 {
		return
	}
	keys := sortedKeys(c.n)
	sort.SliceStable(keys, func(i, j int) bool { return c.n[keys[i]] > c.n[keys[j]] })
	fmt.Fprintf(w, "\n## %s\n\n| %s | count | files |\n| --- | --- | --- |\n", title, label)
	for _, k := range keys {
		fmt.Fprintf(w, "| `%s` | %d | %d |\n", strings.ReplaceAll(k, "|", "\\|"), c.n[k], c.files[k])
	}
}

func writeSanitized(dir string, index int, doc *yaml.Node) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sanitize(doc)
	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, fmt.Sprintf("subscription-%02d.yaml", index)), out, 0o600)
}
