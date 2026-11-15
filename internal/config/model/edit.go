package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Doc is a configuration document kept as a YAML node tree, so edits keep
// the user's comments.
type Doc struct {
	name string
	root *yaml.Node // DocumentNode
}

// LoadDoc parses data for structural editing. An empty document becomes
// an empty mapping.
func LoadDoc(name string, data []byte) (*Doc, Diagnostics) {
	if _, diags := ParseNode(name, data); diags.HasErrors() {
		return nil, diags
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, Diagnostics{syntaxDiag(name, err)}
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 ||
		(root.Content[0].Kind == yaml.ScalarNode && root.Content[0].Tag == "!!null") {
		root = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	return &Doc{name: name, root: &root}, nil
}

// Mapping returns the root mapping node.
func (d *Doc) Mapping() *yaml.Node { return d.root.Content[0] }

// Bytes renders the document in canonical form (see Format).
func (d *Doc) Bytes() []byte { return Format(d.root) }

// Format renders a YAML node tree in Reka's canonical form: two-space
// indentation, one blank line between top-level entries (before their
// head comments), one space before line comments. Formatting canonical
// output again does not change it.
func Format(n *yaml.Node) []byte {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		// Encoding a tree that came from the parser or from JSON values
		// cannot fail; treat it as a bug.
		panic("model: encode: " + err.Error())
	}
	enc.Close()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	out := make([]string, 0, len(lines)+16)
	for _, line := range lines {
		if line == "" {
			if len(out) > 0 && out[len(out)-1] != "" {
				out = append(out, "")
			}
			continue
		}
		if isTopLevelEntry(line) && len(out) > 0 {
			j := len(out)
			for j > 0 && strings.HasPrefix(out[j-1], "#") {
				j--
			}
			if j > 0 && out[j-1] != "" {
				out = append(out[:j], append([]string{""}, out[j:]...)...)
			}
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

func isTopLevelEntry(line string) bool {
	switch line[0] {
	case ' ', '\t', '#', '-', '.':
		return false
	}
	return true
}

// Op is one structural edit. Paths use stable IDs, as in diagnostics.
type Op struct {
	// Op is "set", "remove" or "insert".
	Op   string `json:"op" yaml:"op"`
	Path string `json:"path" yaml:"path"`
	// Value is a JSON value; object key order is kept.
	Value json.RawMessage `json:"value,omitempty" yaml:"value"`
	// Before or After place an inserted list element next to the element
	// with that ID (or "#index"). With neither, it is appended.
	Before string `json:"before,omitempty" yaml:"before"`
	After  string `json:"after,omitempty" yaml:"after"`
}

// ErrPath reports a path that does not resolve.
var ErrPath = errors.New("path not found")

// Apply performs ops in order. On error the document may be partly
// edited; callers apply to a copy.
func (d *Doc) Apply(ops ...Op) error {
	for i, op := range ops {
		if err := d.apply(op); err != nil {
			return fmt.Errorf("op %d (%s %s): %w", i, op.Op, op.Path, err)
		}
	}
	return nil
}

func (d *Doc) apply(op Op) error {
	segs, err := SplitPath(op.Path)
	if err != nil {
		return err
	}
	if len(segs) == 0 {
		return errors.New("cannot edit the document root; commit a whole document instead")
	}
	var value *yaml.Node
	if op.Op == "set" || op.Op == "insert" {
		if len(op.Value) == 0 {
			return errors.New("missing value")
		}
		if value, err = JSONToNode(op.Value); err != nil {
			return err
		}
	}
	create := op.Op != "remove"
	parent, err := walk(d.Mapping(), segs[:len(segs)-1], create)
	if err != nil {
		return err
	}
	last := segs[len(segs)-1]
	switch op.Op {
	case "set":
		return setChild(parent, last, value)
	case "remove":
		return removeChild(parent, last)
	case "insert":
		seq, err := child(parent, last, true, yaml.SequenceNode)
		if err != nil {
			return err
		}
		if seq.Kind != yaml.SequenceNode {
			return fmt.Errorf("%s is not a list", op.Path)
		}
		if id := mappingID(value); id != "" {
			if i := findElement(seq, id); i >= 0 {
				return fmt.Errorf("an element with id %q already exists", id)
			}
		}
		at := len(seq.Content)
		switch {
		case op.Before != "":
			if at = findElement(seq, op.Before); at < 0 {
				return fmt.Errorf("before %q: %w", op.Before, ErrPath)
			}
		case op.After != "":
			if at = findElement(seq, op.After); at < 0 {
				return fmt.Errorf("after %q: %w", op.After, ErrPath)
			}
			at++
		}
		seq.Content = append(seq.Content[:at], append([]*yaml.Node{value}, seq.Content[at:]...)...)
		return nil
	}
	return fmt.Errorf("unknown op %q", op.Op)
}

// Get returns the node at path, or nil.
func (d *Doc) Get(path string) *yaml.Node {
	segs, err := SplitPath(path)
	if err != nil {
		return nil
	}
	n, err := walk(d.Mapping(), segs, false)
	if err != nil {
		return nil
	}
	return n
}

func walk(n *yaml.Node, segs []string, create bool) (*yaml.Node, error) {
	for _, s := range segs {
		next, err := child(n, s, create, yaml.MappingNode)
		if err != nil {
			return nil, err
		}
		n = next
	}
	return n, nil
}

// child finds seg under n. When create is set, a missing mapping key is
// added with an empty node of kind.
func child(n *yaml.Node, seg string, create bool, kind yaml.Kind) (*yaml.Node, error) {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == seg {
				return n.Content[i+1], nil
			}
		}
		if !create {
			return nil, fmt.Errorf("%q: %w", seg, ErrPath)
		}
		v := &yaml.Node{Kind: kind}
		if kind == yaml.MappingNode {
			v.Tag = "!!map"
		} else {
			v.Tag = "!!seq"
		}
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: seg}, v)
		return v, nil
	case yaml.SequenceNode:
		if i := findElement(n, seg); i >= 0 {
			return n.Content[i], nil
		}
		return nil, fmt.Errorf("list element %q: %w", seg, ErrPath)
	case yaml.ScalarNode:
		if create && n.Tag == "!!null" {
			n.Kind, n.Tag, n.Value = yaml.MappingNode, "!!map", ""
			return child(n, seg, create, kind)
		}
	}
	return nil, fmt.Errorf("%q: parent is not a mapping or list: %w", seg, ErrPath)
}

// findElement finds a list element by id or "#index".
func findElement(seq *yaml.Node, seg string) int {
	if strings.HasPrefix(seg, "#") {
		i, err := strconv.Atoi(seg[1:])
		if err != nil || i < 0 || i >= len(seq.Content) {
			return -1
		}
		return i
	}
	for i, item := range seq.Content {
		if mappingID(item) == seg {
			return i
		}
	}
	return -1
}

func keepComments(old, value *yaml.Node) {
	if value.HeadComment == "" {
		value.HeadComment = old.HeadComment
	}
	if value.LineComment == "" {
		value.LineComment = old.LineComment
	}
	if value.FootComment == "" {
		value.FootComment = old.FootComment
	}
}

func setChild(parent *yaml.Node, seg string, value *yaml.Node) error {
	switch parent.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(parent.Content); i += 2 {
			if parent.Content[i].Value == seg {
				keepComments(parent.Content[i+1], value)
				parent.Content[i+1] = value
				return nil
			}
		}
		parent.Content = append(parent.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: seg}, value)
		return nil
	case yaml.SequenceNode:
		i := findElement(parent, seg)
		if i < 0 {
			return fmt.Errorf("list element %q: %w", seg, ErrPath)
		}
		keepComments(parent.Content[i], value)
		parent.Content[i] = value
		return nil
	}
	return fmt.Errorf("%q: parent is not a mapping or list: %w", seg, ErrPath)
}

func removeChild(parent *yaml.Node, seg string) error {
	switch parent.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(parent.Content); i += 2 {
			if parent.Content[i].Value == seg {
				parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
				return nil
			}
		}
	case yaml.SequenceNode:
		if i := findElement(parent, seg); i >= 0 {
			parent.Content = append(parent.Content[:i], parent.Content[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%q: %w", seg, ErrPath)
}

// JSONToNode converts a JSON value to a YAML node, keeping object key
// order.
func JSONToNode(raw []byte) (*yaml.Node, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	n, err := jsonNode(dec)
	if err != nil {
		return nil, fmt.Errorf("value: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("value: trailing data")
	}
	return n, nil
}

func jsonNode(dec *json.Decoder) (*yaml.Node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, _ := kt.(string)
				v, err := jsonNode(dec)
				if err != nil {
					return nil, err
				}
				n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
			}
			_, err := dec.Token()
			return n, err
		case '[':
			n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for dec.More() {
				v, err := jsonNode(dec)
				if err != nil {
					return nil, err
				}
				n.Content = append(n.Content, v)
			}
			_, err := dec.Token()
			return n, err
		}
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t}, nil
	case json.Number:
		tag := "!!int"
		if _, err := strconv.ParseInt(string(t), 10, 64); err != nil {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: string(t)}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(t)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	}
	return nil, fmt.Errorf("unexpected token %v", tok)
}

// NodeToJSON converts a YAML node to a JSON value, for diffs and API
// responses.
func NodeToJSON(n *yaml.Node) any {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil
		}
		return NodeToJSON(n.Content[0])
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = NodeToJSON(n.Content[i+1])
		}
		return m
	case yaml.SequenceNode:
		s := make([]any, len(n.Content))
		for i, c := range n.Content {
			s[i] = NodeToJSON(c)
		}
		return s
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!null":
			return nil
		case "!!bool":
			b, _ := strconv.ParseBool(n.Value)
			return b
		case "!!int":
			if i, err := strconv.ParseInt(n.Value, 0, 64); err == nil {
				return i
			}
		case "!!float":
			if f, err := strconv.ParseFloat(n.Value, 64); err == nil {
				return f
			}
		}
		return n.Value
	}
	return nil
}

// Flatten lists every scalar leaf of a document by stable path, for field
// diffs. Lists of scalars are leaves as a whole.
func Flatten(n *yaml.Node) map[string]any {
	out := map[string]any{}
	flatten(n, "", out)
	return out
}

func flatten(n *yaml.Node, path string, out map[string]any) {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) > 0 {
			flatten(n.Content[0], path, out)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			flatten(n.Content[i+1], JoinPath(path, n.Content[i].Value), out)
		}
	case yaml.SequenceNode:
		scalars := true
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode {
				scalars = false
			}
		}
		if scalars {
			out[orRoot(path)] = NodeToJSON(n)
			return
		}
		for i, c := range n.Content {
			flatten(c, JoinPath(path, ElementSegment(c, i)), out)
		}
	default:
		out[orRoot(path)] = NodeToJSON(n)
	}
}
