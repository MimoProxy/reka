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
var sensitiveFields = map[string]bool{"password": true, "uuid": true, "username": true}

// IsSensitive reports whether path names a credential field.
func IsSensitive(path string) bool {
	segs, err := SplitPath(path)
	return err == nil && len(segs) == 3 && segs[0] == "outbounds" && sensitiveFields[segs[2]]
}

func unalias(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// sensitiveNodes calls fn for each inline credential scalar in a profile.
func sensitiveNodes(root *yaml.Node, fn func(path string, n *yaml.Node)) {
	var nested func(*yaml.Node, string)
	nested = func(n *yaml.Node, prefix string) {
		n = unalias(n)
		if n == nil {
			return
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i].Value, unalias(n.Content[i+1])
				path := JoinPath(prefix, k)
				if (k == "password" || k == "user-key" || k == "value") && v.Kind == yaml.ScalarNode && !strings.HasPrefix(v.Value, SecretPrefix) {
					fn(path, v)
				} else {
					nested(v, path)
				}
			}
		} else if n.Kind == yaml.SequenceNode {
			for i, v := range n.Content {
				nested(v, JoinPath(prefix, ElementSegment(v, i)))
			}
		}
	}
	var dnsSecrets func(*yaml.Node, string)
	dnsSecrets = func(n *yaml.Node, prefix string) {
		n = unalias(n)
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode {
			if (strings.ContainsAny(n.Value, "?@") || n.Value == Mask) && !strings.HasPrefix(n.Value, SecretPrefix) {
				fn(prefix, n)
			}
		} else if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				dnsSecrets(n.Content[i+1], JoinPath(prefix, n.Content[i].Value))
			}
		} else if n.Kind == yaml.SequenceNode {
			for i, v := range n.Content {
				dnsSecrets(v, JoinPath(prefix, ElementSegment(v, i)))
			}
		}
	}
	var outbound func(*yaml.Node, string)
	outbound = func(ob *yaml.Node, prefix string) {
		ob = unalias(ob)
		if ob.Kind != yaml.MappingNode {
			return
		}
		for _, key := range []string{"protocol", "transport"} {
			if v, e := child(ob, key, false, 0); e == nil {
				nested(v, JoinPath(prefix, key))
			}
		}
		for j := 0; j+1 < len(ob.Content); j += 2 {
			k, v := ob.Content[j], unalias(ob.Content[j+1])
			if sensitiveFields[k.Value] && v.Kind == yaml.ScalarNode && !strings.HasPrefix(v.Value, SecretPrefix) {
				fn(JoinPath(prefix, k.Value), v)
			}
		}
	}
	list := func(n *yaml.Node, prefix string) {
		n = unalias(n)
		if n == nil || n.Kind != yaml.SequenceNode {
			return
		}
		for i, ob := range n.Content {
			outbound(ob, JoinPath(prefix, ElementSegment(ob, i)))
		}
	}
	if v, e := child(root, "dns", false, 0); e == nil {
		dnsSecrets(v, "/dns")
	}
	var groupSecrets func(*yaml.Node, string)
	groupSecrets = func(n *yaml.Node, prefix string) {
		n = unalias(n)
		if n == nil {
			return
		}
		if n.Kind == yaml.SequenceNode {
			for i, g := range n.Content {
				groupSecrets(g, JoinPath(prefix, ElementSegment(g, i)))
			}
		} else if u, e := child(n, "url", false, 0); e == nil {
			dnsSecrets(u, JoinPath(prefix, "url"))
		}
	}
	if groups, e := child(root, "groups", false, 0); e == nil {
		groupSecrets(groups, "/groups")
	}
	obs, _ := child(root, "outbounds", false, 0)
	list(obs, "/outbounds")
	if sources, err := child(root, "sources", false, 0); err == nil && unalias(sources).Kind == yaml.SequenceNode {
		sources = unalias(sources)
		for i, src := range sources.Content {
			prefix := JoinPath("/sources", ElementSegment(src, i), "subscription")
			if subscription, e := child(src, "subscription", false, 0); e == nil && unalias(subscription).Kind == yaml.MappingNode {
				if u, e := child(subscription, "url", false, 0); e == nil {
					u = unalias(u)
					if u.Kind == yaml.ScalarNode && !strings.HasPrefix(u.Value, SecretPrefix) {
						fn(prefix+"/url", u)
					}
				}
				if assets, e := child(subscription, "geodata", false, 0); e == nil && unalias(assets).Kind == yaml.SequenceNode {
					for j, asset := range unalias(assets).Content {
						if u, e := child(asset, "url", false, 0); e == nil {
							u = unalias(u)
							if u.Kind == yaml.ScalarNode && u.Value != "" && !strings.HasPrefix(u.Value, SecretPrefix) {
								fn(JoinPath(prefix, "geodata", ElementSegment(asset, j), "url"), u)
							}
						}
					}
				}
				if headers, e := child(subscription, "headers", false, 0); e == nil && unalias(headers).Kind == yaml.SequenceNode {
					for j, header := range unalias(headers).Content {
						if v, e := child(header, "value", false, 0); e == nil {
							v = unalias(v)
							if v.Kind == yaml.ScalarNode && !strings.HasPrefix(v.Value, SecretPrefix) {
								fn(JoinPath(prefix, "headers", ElementSegment(header, j), "value"), v)
							}
						}
					}
				}
			}
			if v, e := child(src, "dns", false, 0); e == nil {
				dnsSecrets(v, JoinPath("/sources", ElementSegment(src, i), "dns"))
			}
			if v, e := child(src, "groups", false, 0); e == nil {
				groupSecrets(v, JoinPath("/sources", ElementSegment(src, i), "groups"))
			}
			obs, _ := child(src, "outbounds", false, 0)
			list(obs, JoinPath("/sources", ElementSegment(src, i), "outbounds"))
		}
	}
	if patches, err := child(root, "patches", false, 0); err == nil && unalias(patches).Kind == yaml.SequenceNode {
		patches = unalias(patches)
		for i, patch := range patches.Content {
			path, e := child(patch, "path", false, 0)
			if e != nil {
				continue
			}
			value, e := child(patch, "value", false, 0)
			if e != nil {
				continue
			}
			path, value = unalias(path), unalias(value)
			if strings.Contains(path.Value, "/protocol") || strings.Contains(path.Value, "/transport") {
				prefix := JoinPath("/patches", ElementSegment(patch, i), "value")
				if value.Kind == yaml.ScalarNode && (strings.HasSuffix(path.Value, "/password") || strings.HasSuffix(path.Value, "/user-key") || strings.HasSuffix(path.Value, "/value")) {
					if !strings.HasPrefix(value.Value, SecretPrefix) {
						fn(prefix, value)
					}
				} else {
					nested(value, prefix)
				}
			}
			if path.Value == "/dns" || strings.HasPrefix(path.Value, "/dns/") {
				dnsSecrets(value, JoinPath("/patches", ElementSegment(patch, i), "value"))
			}
			if strings.HasPrefix(path.Value, "/groups") {
				prefix := JoinPath("/patches", ElementSegment(patch, i), "value")
				if strings.HasSuffix(path.Value, "/url") {
					dnsSecrets(value, prefix)
				} else {
					groupSecrets(value, prefix)
				}
			}

			segs, e := SplitPath(path.Value)
			if e != nil || len(segs) == 0 || segs[0] != "outbounds" {
				continue
			}
			prefix := JoinPath("/patches", ElementSegment(patch, i), "value")
			switch len(segs) {
			case 1:
				if value.Kind == yaml.SequenceNode {
					list(value, prefix)
				} else {
					outbound(value, prefix)
				}
			case 2:
				outbound(value, prefix)
			case 3:
				if sensitiveFields[segs[2]] && value.Kind == yaml.ScalarNode && !strings.HasPrefix(value.Value, SecretPrefix) {
					fn(prefix, value)
				}
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
			old = unalias(base.Get(path))
			if d.name == DocSources {
				parts, _ := SplitPath(path)
				if len(parts) == 6 && parts[0] == "sources" && parts[2] == "subscription" && parts[3] == "headers" {
					prefix := JoinPath("", parts[:5]...)
					a, b := unalias(d.Get(prefix+"/name")), unalias(base.Get(prefix+"/name"))
					if a == nil || b == nil || !strings.EqualFold(a.Value, b.Value) {
						err = fmt.Errorf("%s: masked header changed identity; supply its value again", path)
						return
					}
				}
			}
			// Overlay values are addressed by operation position. A masked
			// value must never pick up credentials from a different target
			// after the caller reorders or edits operations.
			if d.name == DocOverlay {
				parts, _ := SplitPath(path)
				if len(parts) >= 3 && parts[0] == "patches" {
					prefix := JoinPath("", parts[:2]...)
					for _, key := range []string{"op", "path"} {
						a, b := unalias(d.Get(prefix+"/"+key)), unalias(base.Get(prefix+"/"+key))
						if a == nil || b == nil || a.Value != b.Value {
							err = fmt.Errorf("%s: masked overlay operation changed target; supply its credential again", path)
							return
						}
					}
				}
			}
		}
		if old == nil || old.Kind != yaml.ScalarNode || old.Value == Mask {
			err = fmt.Errorf("%s: masked value has no stored value to keep", path)
			return
		}
		v.Value, v.Tag, v.Style = old.Value, old.Tag, old.Style
	})
	return err
}
