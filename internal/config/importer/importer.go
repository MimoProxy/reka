// Package importer converts external subscription content to an isolated native
// source snapshot. It never downloads resources, writes files or activates it.
package importer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

const ReferenceVersion = "v1.19.34"

type Request struct {
	displayNames  map[string]string
	ruleSets      []object
	resourceNames map[string]string
	SourceID      string `json:"source_id"`
	Format        string `json:"format,omitempty"`
	Data          string `json:"data"`
	NodesOnly     bool   `json:"nodes_only,omitempty"`
	AllowPartial  bool   `json:"allow_partial,omitempty"`
}
type Count struct {
	Total       int `json:"total"`
	Imported    int `json:"imported"`
	Unavailable int `json:"unavailable"`
}
type Binding struct {
	Provider  string `json:"provider,omitempty"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	ID        string `json:"id"`
	Available bool   `json:"available"`
}
type Report struct {
	SourceID    string            `json:"source_id"`
	Format      string            `json:"format"`
	Partial     bool              `json:"partial"`
	CanApply    bool              `json:"can_apply"`
	Nodes       Count             `json:"nodes"`
	Groups      Count             `json:"groups"`
	Rules       Count             `json:"rules"`
	Ignored     []string          `json:"ignored,omitempty"`
	Bindings    []Binding         `json:"bindings,omitempty"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
}
type Result struct {
	Report Report
	// Source is a single normalized source object, containing credentials.
	// Only pass it to ConfigService or Preview; never log or serialize it.
	Source json.RawMessage `json:"-"`
}
type Preview struct {
	Report  Report `json:"report"`
	Sources string `json:"sources"`
	Masked  int    `json:"masked,omitempty"`
}

func (r Result) Preview(reveal bool) Preview {
	p := Preview{Report: r.Report}
	if len(r.Source) == 0 {
		return p
	}
	node, err := model.JSONToNode(append(append([]byte(`{"schema-version":1,"sources":[`), r.Source...), []byte(`]}`)...))
	if err != nil {
		return p
	}
	doc, ds := model.LoadDoc(model.DocSources, model.Format(node))
	if ds.HasErrors() {
		p.Report.CanApply = false
		p.Report.Diagnostics = append(p.Report.Diagnostics, ds...)
		return p
	}
	if !reveal {
		p.Masked = doc.MaskSecrets()
	}
	p.Sources = string(doc.Bytes())
	return p
}

// StableID follows exact original names, independent of order, addresses and
// credentials. Renaming creates a new identity; no fuzzy matching is attempted.
func StableID(kind, name string) string {
	sum := sha256.Sum256([]byte(name))
	return kind + "-" + hex.EncodeToString(sum[:12])
}

var sourceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type object = map[string]any

type converter struct {
	dns        object
	req        Request
	report     Report
	fatal      bool
	names      map[string]string
	available  map[string]bool
	nodes      []object
	groups     []object
	rules      []object
	subRules   []object
	blockNames map[string]string
}

func (c *converter) diag(n *yaml.Node, path, code, message string, fatal bool) {
	severity := model.SeverityWarning
	if fatal {
		severity = model.SeverityError
		c.fatal = true
	}
	d := model.Diagnostic{Severity: severity, Code: code, Document: c.report.Format, Path: path, Message: message}
	if n != nil {
		d.Line, d.Column = n.Line, n.Column
	}
	c.report.Diagnostics = append(c.report.Diagnostics, d)
}
func (c *converter) unsupported(n *yaml.Node, path, code, message string) {
	c.report.Partial = true
	c.diag(n, path, code, message, false)
}
func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}
func get(n *yaml.Node, key string) *yaml.Node {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return deref(n.Content[i+1])
		}
	}
	return nil
}
func text(n *yaml.Node) string {
	n = deref(n)
	if n == nil {
		return ""
	}
	return n.Value
}
func empty(n *yaml.Node) bool {
	n = deref(n)
	return n == nil || n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

// Import returns a report even when conversion is blocked, so callers can
// review every unavailable item without mistaking an empty result for success.
func importDirect(req Request) Result {
	c := &converter{req: req, names: map[string]string{}, available: map[string]bool{}}
	format := req.Format
	if format == "" || format == "auto" {
		format = detectFormat(req.Data)
	}
	c.report = Report{SourceID: req.SourceID, Format: format}
	if !sourceID.MatchString(req.SourceID) {
		c.diag(nil, "/source_id", "import.source-id", "source_id must be a native stable ID", true)
		return c.finish()
	}
	if len(req.Data) > model.MaxDocumentSize {
		c.diag(nil, "/", "import.size", "input exceeds the document size limit", true)
		return c.finish()
	}
	switch format {
	case "clash":
		c.clash([]byte(req.Data))
	case "links":
		c.links(req.Data)
	default:
		c.diag(nil, "/format", "import.format", "format must be auto, clash or links", true)
	}
	return c.finish()
}
func (c *converter) finish() Result {
	c.report.Nodes.Imported = len(c.nodes)
	c.report.Nodes.Unavailable = c.report.Nodes.Total - len(c.nodes)
	c.report.Groups.Imported = len(c.groups)
	c.report.Groups.Unavailable = c.report.Groups.Total - len(c.groups)
	c.report.Rules.Imported = len(c.rules)
	c.report.Rules.Unavailable = c.report.Rules.Total - len(c.rules)
	useful := len(c.nodes)+len(c.groups)+len(c.rules) > 0 || c.dns != nil
	if !useful && !c.fatal {
		c.diag(nil, "/", "import.empty", "no supported resources were imported", true)
	}
	c.report.CanApply = !c.fatal && useful && (!c.report.Partial || c.req.AllowPartial)
	if c.report.Partial && !c.req.AllowPartial && !c.fatal {
		c.diag(nil, "/", "import.partial", "conversion is incomplete; select nodes_only or explicitly allow_partial after reviewing the report", false)
	}
	var source json.RawMessage
	if !c.fatal {
		b, _ := json.Marshal(object{"id": c.req.SourceID, "outbounds": c.nodes, "groups": c.groups, "rules": c.rules, "rule-sets": c.req.ruleSets, "sub-rules": c.subRules, "dns": c.dns})
		if len(b) > model.MaxDocumentSize {
			c.diag(nil, "/", "import.size", "normalized source exceeds the document size limit", true)
			c.report.CanApply = false
		} else {
			source = b
		}
	}
	return Result{Report: c.report, Source: source}
}

// validateTree bounds unknown fields too; an ignored section cannot hide an
// alias bomb. Duplicate mapping keys and YAML merge keys are rejected.
func (c *converter) validateTree(root *yaml.Node) bool {
	budget := 2_000_000
	expandedBytes := 0
	var walk func(*yaml.Node, string, int) bool
	walk = func(n *yaml.Node, path string, depth int) bool {
		budget--
		expandedBytes += len(n.Value) + 16
		if budget < 0 || depth > 32 || expandedBytes > model.MaxDocumentSize {
			c.diag(n, path, "import.yaml-limit", "YAML depth or alias expansion limit exceeded", true)
			return false
		}
		if n.Kind == yaml.AliasNode {
			return walk(n.Alias, path, depth+1)
		}
		switch n.Kind {
		case yaml.MappingNode:
			seen := map[string]bool{}
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i]
				p := model.JoinPath(path, k.Value)
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
					c.diag(k, p, "import.yaml-key", "mapping keys must be strings; merge keys are unsupported", true)
					return false
				}
				if seen[k.Value] {
					c.diag(k, p, "import.duplicate-key", "duplicate mapping key", true)
					return false
				}
				seen[k.Value] = true
				if !walk(n.Content[i+1], p, depth+1) {
					return false
				}
			}
		case yaml.SequenceNode:
			for i, v := range n.Content {
				if !walk(v, fmt.Sprintf("%s/#%d", path, i), depth+1) {
					return false
				}
			}
		}
		return true
	}
	return walk(root, "", 0)
}
func (c *converter) items(root *yaml.Node, key string) []*yaml.Node {
	n := get(root, key)
	if empty(n) {
		return nil
	}
	if n.Kind != yaml.SequenceNode {
		c.diag(n, "/"+key, "import.type", "expected a list", true)
		return nil
	}
	return n.Content
}
func (c *converter) register(n *yaml.Node, kind, path string) bool {
	name := text(get(n, "name"))
	if deref(n).Kind != yaml.MappingNode || strings.TrimSpace(name) == "" {
		c.diag(n, path, "import.name", "a resource needs a name", true)
		return false
	}
	if _, ok := c.names[name]; ok || name == "DIRECT" || name == "REJECT" || name == "COMPATIBLE" || name == "PASS" || name == "REJECT-DROP" {
		c.diag(get(n, "name"), path+"/name", "import.duplicate-name", "duplicate or reserved resource name", true)
		return false
	}
	c.names[name] = StableID(kind, name)
	return true
}
func (c *converter) clash(data []byte) {
	root, ds := model.ParseNode("clash", data)
	if ds.HasErrors() {
		c.report.Diagnostics = append(c.report.Diagnostics, ds...)
		c.fatal = true
		return
	}
	if root == nil {
		c.diag(nil, "/", "import.empty", "empty Clash document", true)
		return
	}
	if !c.validateTree(root) {
		return
	}
	proxies := c.items(root, "proxies")
	var groups, rules []*yaml.Node
	if !c.req.NodesOnly {
		groups = c.items(root, "proxy-groups")
		rules = c.items(root, "rules")
	}
	if !c.req.NodesOnly {
		groups = ensureGlobalGroup(root, proxies, groups)
	}
	c.report.Nodes.Total = len(proxies)
	c.report.Groups.Total = len(groups)
	c.report.Rules.Total = len(rules)
	for i, p := range proxies {
		c.register(p, "p", fmt.Sprintf("/proxies/#%d", i))
	}
	for i, g := range groups {
		c.register(g, "g", fmt.Sprintf("/proxy-groups/#%d", i))
	}
	if c.fatal {
		return
	}
	for i, p := range proxies {
		c.convertProxy(p, fmt.Sprintf("/proxies/#%d", i))
	}
	if !c.req.NodesOnly {
		c.convertGroups(groups)
		c.convertRuleBlocks(root, rules)
		c.convertDNS(root)
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i].Value, deref(root.Content[i+1])
		path := model.JoinPath("", key)
		switch key {
		case "proxies":
		case "proxy-groups", "rules", "sub-rules":
			if c.req.NodesOnly {
				c.report.Ignored = append(c.report.Ignored, path)
			}
		case "dns":
			if c.req.NodesOnly {
				c.report.Ignored = append(c.report.Ignored, path)
			}
		case "hosts":
			if c.req.NodesOnly || c.dns == nil {
				c.report.Ignored = append(c.report.Ignored, path)
			}
		case "proxy-providers", "rule-providers":
			if c.req.NodesOnly {
				c.report.Ignored = append(c.report.Ignored, path)
			} else if !empty(val) && !(val.Kind == yaml.MappingNode && len(val.Content) == 0) {
				c.reportSection(val, path)
			}
		default:
			c.report.Ignored = append(c.report.Ignored, path)
			c.diag(val, path, "import.ignored-top-level", "top-level setting belongs outside the subscription source and was ignored", false)
		}
	}
}
func (c *converter) reportSection(n *yaml.Node, path string) {
	if n.Kind != yaml.MappingNode {
		c.unsupported(n, path, "import.unsupported-section", "section is not supported in this stage")
		return
	}
	if path == "/dns" && text(get(n, "enable")) == "false" {
		c.report.Ignored = append(c.report.Ignored, path)
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		p := model.JoinPath(path, n.Content[i].Value)
		c.unsupported(n.Content[i+1], p, "import.unsupported-field", "field is not supported and was not imported")
	}
}
