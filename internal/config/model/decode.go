package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Parse limits. Configuration documents are small; these only stop
// pathological input.
const (
	MaxDocumentSize = 16 << 20
	maxDepth        = 32
	// maxNodeVisits bounds the work done decoding, counting every node
	// reached through an alias again. It stops "billion laughs" input.
	maxNodeVisits = 2_000_000
)

var lineRE = regexp.MustCompile(`line (\d+)`)

// ParseNode parses one YAML document and returns its root node (a mapping,
// or nil for an empty document). Multiple documents are an error.
func ParseNode(doc string, data []byte) (*yaml.Node, Diagnostics) {
	if len(data) > MaxDocumentSize {
		return nil, Diagnostics{{Severity: SeverityError, Code: "yaml.size", Document: doc,
			Message: fmt.Sprintf("document is larger than %d bytes", MaxDocumentSize)}}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, Diagnostics{syntaxDiag(doc, err)}
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, Diagnostics{{Severity: SeverityError, Code: "yaml.documents", Document: doc,
			Line: extra.Line, Column: extra.Column, Message: "only one YAML document is allowed"}}
	} else if !errors.Is(err, io.EOF) {
		return nil, Diagnostics{syntaxDiag(doc, err)}
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, nil
	}
	n := root.Content[0]
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return nil, nil
	}
	if n.Kind != yaml.MappingNode {
		return nil, Diagnostics{{Severity: SeverityError, Code: "yaml.type", Document: doc,
			Line: n.Line, Column: n.Column, Path: "/", Message: "the document must be a mapping"}}
	}
	return n, nil
}

func syntaxDiag(doc string, err error) Diagnostic {
	d := Diagnostic{Severity: SeverityError, Code: "yaml.syntax", Document: doc,
		Message: strings.TrimPrefix(err.Error(), "yaml: ")}
	if m := lineRE.FindStringSubmatch(err.Error()); m != nil {
		d.Line, _ = strconv.Atoi(m[1])
	}
	return d
}

// ParseProfile parses and decodes a profile document.
func ParseProfile(data []byte) (*Profile, Positions, Diagnostics) {
	p := &Profile{}
	pos, diags := decodeDocument(DocProfile, data, p, true)
	return p, pos, diags
}

// ParseLocal parses and decodes local settings. An empty document is valid.
func ParseLocal(data []byte) (*LocalSettings, Positions, Diagnostics) {
	l := &LocalSettings{}
	pos, diags := decodeDocument(DocLocal, data, l, false)
	if l.SchemaVersion == 0 {
		l.SchemaVersion = SchemaVersion
	}
	return l, pos, diags
}

func ParseSources(data []byte) (*Sources, Positions, Diagnostics) {
	s := &Sources{}
	p, d := decodeDocument(DocSources, data, s, false)
	return s, p, d
}

func ParseOverlay(data []byte) (*Overlay, Positions, Diagnostics) {
	o := &Overlay{}
	p, d := decodeDocument(DocOverlay, data, o, false)
	return o, p, d
}

func decodeDocument(doc string, data []byte, out any, requireVersion bool) (Positions, Diagnostics) {
	root, diags := ParseNode(doc, data)
	if diags.HasErrors() {
		return nil, diags
	}
	pos := Positions{}
	if root == nil {
		if requireVersion {
			return pos, Diagnostics{{Severity: SeverityError, Code: "schema.version", Document: doc,
				Message: "empty document; schema-version is required"}}
		}
		return pos, nil
	}
	return DecodeNode(doc, root, out)
}

// DecodeNode decodes a mapping node into out (a pointer to a document
// struct), strictly: unknown fields, duplicate keys, wrong types, excessive
// nesting and alias expansion are errors. It returns the position of every
// decoded value.
func DecodeNode(doc string, root *yaml.Node, out any) (Positions, Diagnostics) {
	d := &decoder{doc: doc, pos: Positions{}, budget: maxNodeVisits}
	d.decode(root, "", reflect.ValueOf(out).Elem(), 0)
	if d.budgetHit {
		d.errorf(root, "", "yaml.alias", "alias expansion exceeds %d nodes", maxNodeVisits)
	}
	v := reflect.ValueOf(out).Elem().FieldByName("SchemaVersion")
	if v.IsValid() && !d.diags.HasErrors() {
		switch ver := int(v.Int()); {
		case ver == 0 && doc == DocProfile:
			d.diags = append(d.diags, Diagnostic{Severity: SeverityError, Code: "schema.version", Document: doc,
				Path: "/schema-version", Line: root.Line, Column: root.Column, Message: "schema-version is required"})
		case ver != 0 && ver != SchemaVersion:
			p := d.pos["/schema-version"]
			d.diags = append(d.diags, Diagnostic{Severity: SeverityError, Code: "schema.version", Document: doc,
				Path: "/schema-version", Line: p.Line, Column: p.Column,
				Message: fmt.Sprintf("schema-version %d is not supported; this build reads version %d", ver, SchemaVersion)})
		}
	}
	return d.pos, d.diags
}

type decoder struct {
	doc       string
	diags     Diagnostics
	pos       Positions
	budget    int
	budgetHit bool
	depthHit  bool
}

func (d *decoder) errorf(n *yaml.Node, path, code, format string, args ...any) {
	diag := Diagnostic{Severity: SeverityError, Code: code, Document: d.doc, Path: path, Message: fmt.Sprintf(format, args...)}
	if n != nil {
		diag.Line, diag.Column = n.Line, n.Column
	}
	if diag.Path == "" {
		diag.Path = "/"
	}
	d.diags = append(d.diags, diag)
}

// unmarshaler lets a type decode itself from a node.
type unmarshaler interface {
	decodeYAML(d *decoder, n *yaml.Node, path string)
}

func kindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!null":
			return "null"
		case "!!bool":
			return "a boolean"
		case "!!int", "!!float":
			return "a number"
		}
		return "a string"
	}
	return "an unsupported node"
}

func (d *decoder) visit(n *yaml.Node, path string, depth int) (*yaml.Node, bool) {
	if d.budgetHit || d.depthHit {
		return nil, false
	}
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	d.budget--
	if d.budget < 0 {
		d.budgetHit = true
		return nil, false
	}
	if depth > maxDepth {
		d.depthHit = true
		d.errorf(n, path, "yaml.depth", "nesting deeper than %d levels", maxDepth)
		return nil, false
	}
	d.pos[orRoot(path)] = Pos{n.Line, n.Column}
	return n, true
}

func orRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func (d *decoder) decode(n *yaml.Node, path string, v reflect.Value, depth int) {
	n, ok := d.visit(n, path, depth)
	if !ok {
		return
	}
	if v.Type() == reflect.TypeFor[json.RawMessage]() {
		value := d.jsonValue(n, path, depth)
		b, err := json.Marshal(value)
		if err != nil {
			d.errorf(n, path, "yaml.value", "value cannot be represented as JSON")
		}
		v.SetBytes(b)
		return
	}
	if u, ok := v.Addr().Interface().(unmarshaler); ok {
		u.decodeYAML(d, n, path)
		return
	}
	isNull := n.Kind == yaml.ScalarNode && n.Tag == "!!null"
	switch v.Kind() {
	case reflect.Pointer:
		if isNull {
			return
		}
		p := reflect.New(v.Type().Elem())
		d.decode(n, path, p.Elem(), depth)
		v.Set(p)
	case reflect.String:
		if n.Kind != yaml.ScalarNode || isNull {
			d.errorf(n, path, "yaml.type", "expected a string, got %s", kindName(n))
			return
		}
		v.SetString(n.Value)
	case reflect.Bool:
		if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
			d.errorf(n, path, "yaml.type", "expected true or false, got %s", kindName(n))
			return
		}
		b, _ := strconv.ParseBool(n.Value)
		v.SetBool(b)
	case reflect.Int:
		if n.Kind != yaml.ScalarNode || n.Tag != "!!int" {
			d.errorf(n, path, "yaml.type", "expected an integer, got %s", kindName(n))
			return
		}
		i, err := strconv.ParseInt(n.Value, 0, 64)
		if err != nil {
			d.errorf(n, path, "yaml.type", "integer out of range")
			return
		}
		v.SetInt(i)
	case reflect.Slice:
		if isNull {
			return
		}
		if n.Kind != yaml.SequenceNode {
			d.errorf(n, path, "yaml.type", "expected a list, got %s", kindName(n))
			return
		}
		s := reflect.MakeSlice(v.Type(), len(n.Content), len(n.Content))
		for i, item := range n.Content {
			d.decode(item, JoinPath(path, ElementSegment(item, i)), s.Index(i), depth+1)
		}
		v.Set(s)
	case reflect.Struct:
		if isNull {
			return
		}
		if n.Kind != yaml.MappingNode {
			d.errorf(n, path, "yaml.type", "expected a mapping, got %s", kindName(n))
			return
		}
		fields := structFields(v.Type())
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, val := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode {
				d.errorf(k, path, "yaml.key", "keys must be strings")
				continue
			}
			kp := JoinPath(path, k.Value)
			if seen[k.Value] {
				d.errorf(k, kp, "yaml.duplicate", "duplicate key %q", k.Value)
				continue
			}
			seen[k.Value] = true
			idx, ok := fields[k.Value]
			if !ok {
				d.errorf(k, kp, "schema.unknown-field", "unknown field %q", k.Value)
				continue
			}
			d.decode(val, kp, v.Field(idx), depth+1)
		}
	default:
		panic("model: unsupported field kind " + v.Kind().String())
	}
}

// jsonValue validates arbitrary patch values with the same depth, alias and
// duplicate-key limits as the typed documents.
func (d *decoder) jsonValue(n *yaml.Node, path string, depth int) any {
	n, ok := d.visit(n, path, depth)
	if !ok {
		return nil
	}
	switch n.Kind {
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				d.errorf(k, path, "yaml.key", "patch object keys must be strings")
				continue
			}
			p := JoinPath(path, k.Value)
			if _, exists := out[k.Value]; exists {
				d.errorf(k, p, "yaml.duplicate", "duplicate key %q", k.Value)
			}
			out[k.Value] = d.jsonValue(n.Content[i+1], p, depth+1)
		}
		return out
	case yaml.SequenceNode:
		out := make([]any, len(n.Content))
		for i, v := range n.Content {
			out[i] = d.jsonValue(v, JoinPath(path, ElementSegment(v, i)), depth+1)
		}
		return out
	case yaml.ScalarNode:
		var out any
		if err := n.Decode(&out); err != nil {
			d.errorf(n, path, "yaml.value", "invalid patch value")
			return nil
		}
		// Restrict tags to JSON-compatible scalars (timestamps remain strings).
		switch n.Tag {
		case "!!str", "!!timestamp":
			return n.Value
		case "!!null", "!!bool", "!!int", "!!float":
			return out
		}
	}
	d.errorf(n, path, "yaml.value", "unsupported patch value")
	return nil
}

// ElementSegment is the path segment for a list element: its id when it
// has a scalar one, otherwise "#index".
func ElementSegment(n *yaml.Node, index int) string {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if id := mappingID(n); id != "" {
		return id
	}
	return "#" + strconv.Itoa(index)
}

func mappingID(n *yaml.Node) string {
	if n.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "id" && n.Content[i+1].Kind == yaml.ScalarNode {
			id := n.Content[i+1].Value
			if id != "" && !strings.HasPrefix(id, "#") {
				return id
			}
		}
	}
	return ""
}

func structFields(t reflect.Type) map[string]int {
	m := make(map[string]int, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		m[tag] = i
	}
	return m
}

// MatchKeys are the rule condition keys, in documentation order.
var MatchKeys = []string{
	"domain", "domain-suffix", "domain-keyword", "domain-regex", "domain-pattern",
	"ip-cidr", "src-ip-cidr", "dst-port", "src-port", "network", "process-name", "process-name-regex", "rule-set", "geoip", "and", "or", "not", "all",
}

func isMatchKey(k string) bool {
	for _, m := range MatchKeys {
		if m == k {
			return true
		}
	}
	return false
}

func (m *Match) decodeYAML(d *decoder, n *yaml.Node, path string) {
	if n.Kind != yaml.MappingNode {
		d.errorf(n, path, "yaml.type", "expected a mapping, got %s", kindName(n))
		return
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		for val.Kind == yaml.AliasNode {
			val = val.Alias
		}
		kp := JoinPath(path, k.Value)
		if k.Kind != yaml.ScalarNode {
			d.errorf(k, path, "yaml.key", "keys must be strings")
			continue
		}
		if seen[k.Value] {
			d.errorf(k, kp, "yaml.duplicate", "duplicate key %q", k.Value)
			continue
		}
		seen[k.Value] = true
		d.pos[kp] = Pos{val.Line, val.Column}
		switch {
		case k.Value == "no-resolve":
			if val.Kind != yaml.ScalarNode || val.Tag != "!!bool" {
				d.errorf(val, kp, "yaml.type", "expected true or false, got %s", kindName(val))
				continue
			}
			m.NoResolve = val.Value == "true"
		case k.Value == "and" || k.Value == "or" || k.Value == "not":
			d.setKind(m, k, kp, k.Value)
			d.decode(val, kp, reflect.ValueOf(&m.Children).Elem(), strings.Count(kp, "/"))
		case k.Value == "all":
			if val.Kind != yaml.ScalarNode || val.Tag != "!!bool" || val.Value != "true" {
				d.errorf(val, kp, "yaml.type", "all must be true")
				continue
			}
			d.setKind(m, k, kp, "all")
		case isMatchKey(k.Value):
			d.setKind(m, k, kp, k.Value)
			switch val.Kind {
			case yaml.ScalarNode:
				if val.Tag == "!!null" || val.Tag == "!!bool" {
					d.errorf(val, kp, "yaml.type", "expected a value or a list of values, got %s", kindName(val))
					continue
				}
				m.Values = []string{val.Value}
			case yaml.SequenceNode:
				for j, item := range val.Content {
					for item.Kind == yaml.AliasNode {
						item = item.Alias
					}
					if item.Kind != yaml.ScalarNode || item.Tag == "!!null" || item.Tag == "!!bool" {
						d.errorf(item, JoinPath(kp, "#"+strconv.Itoa(j)), "yaml.type", "expected a value, got %s", kindName(item))
						continue
					}
					m.Values = append(m.Values, item.Value)
				}
				if len(val.Content) == 0 {
					d.errorf(val, kp, "schema.empty", "the list of values is empty")
				}
			default:
				d.errorf(val, kp, "yaml.type", "expected a value or a list of values, got %s", kindName(val))
			}
		default:
			d.errorf(k, kp, "schema.unknown-field", "unknown match condition %q", k.Value)
		}
	}
	if m.Kind == "" && !d.diags.HasErrors() {
		d.errorf(n, path, "schema.match", "a match needs one condition (%s)", strings.Join(MatchKeys, ", "))
	}
}

func (d *decoder) setKind(m *Match, k *yaml.Node, path, kind string) {
	if m.Kind != "" {
		d.errorf(k, path, "schema.match", "a match takes one condition; %q is already set (combine conditions with separate rules)", m.Kind)
		return
	}
	m.Kind = kind
}
