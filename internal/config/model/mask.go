package model

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Mask replaces credentials written inline when a document is read back
// through the API. Sending Mask back in the same field keeps the stored
// value.
const Mask = "********"

// SecretPrefix marks a value held in the SecretStore, for example
// "secret://outbounds/my-vps/uuid". References are not masked.
const SecretPrefix = "secret://"

// sensitiveFields are outbound fields that hold credentials.
var sensitiveFields = map[string]bool{"password": true, "uuid": true}

// IsSensitive reports whether path names a credential field.
func IsSensitive(path string) bool {
	segs, err := SplitPath(path)
	return err == nil && len(segs) == 3 && segs[0] == "outbounds" && sensitiveFields[segs[2]]
}

// sensitiveNodes calls fn for each inline credential scalar in a profile.
func sensitiveNodes(root *yaml.Node, fn func(path string, n *yaml.Node)) {
	outbounds, err := child(root, "outbounds", false, 0)
	if err != nil || outbounds.Kind != yaml.SequenceNode {
		return
	}
	for i, ob := range outbounds.Content {
		if ob.Kind != yaml.MappingNode {
			continue
		}
		seg := ElementSegment(ob, i)
		for j := 0; j+1 < len(ob.Content); j += 2 {
			k, v := ob.Content[j], ob.Content[j+1]
			if sensitiveFields[k.Value] && v.Kind == yaml.ScalarNode && !strings.HasPrefix(v.Value, SecretPrefix) {
				fn(JoinPath("", "outbounds", seg, k.Value), v)
			}
		}
	}
}

// MaskSecrets replaces inline credentials in a profile with Mask and
// reports how many were replaced.
func (d *Doc) MaskSecrets() int {
	n := 0
	sensitiveNodes(d.Mapping(), func(_ string, v *yaml.Node) {
		if v.Value != "" && v.Value != Mask {
			v.Value, v.Tag, v.Style = Mask, "!!str", 0
			n++
		}
	})
	return n
}

// UnmaskSecrets puts back, from base, every credential the client sent as
// Mask. It fails if base has no value at that path.
func (d *Doc) UnmaskSecrets(base *Doc) error {
	var err error
	sensitiveNodes(d.Mapping(), func(path string, v *yaml.Node) {
		if v.Value != Mask || err != nil {
			return
		}
		var old *yaml.Node
		if base != nil {
			old = base.Get(path)
		}
		if old == nil || old.Kind != yaml.ScalarNode || old.Value == Mask {
			err = fmt.Errorf("%s: masked value has no stored value to keep", path)
			return
		}
		v.Value, v.Tag, v.Style = old.Value, old.Tag, old.Style
	})
	return err
}
