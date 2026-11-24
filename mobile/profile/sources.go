package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

func (b *Bundle) prepareSources(ctx context.Context, profile *model.Profile, options PrepareOptions, read func(string) ([]byte, error)) error {
	// dns.from selects a source's DNS whether or not the profile imports
	// anything else from that source.
	dnsSource := ""
	if !options.NodesOnly && profile.DNS != nil {
		dnsSource = profile.DNS.From
	}
	if len(options.Sources) == 0 || len(profile.Imports) == 0 && dnsSource == "" {
		return nil
	}
	// A rule marker also imports the rule sets of an already loaded source.
	ruleSources := make(map[string]bool)
	if !options.NodesOnly {
		for _, rule := range profile.Rules {
			if rule.Source != "" {
				ruleSources[rule.Source] = true
			}
		}
	}
	document := struct {
		SchemaVersion int               `json:"schema-version"`
		Sources       []json.RawMessage `json:"sources"`
	}{SchemaVersion: model.SchemaVersion}
	seen := make(map[string]bool)
	size, resourceBytes := 0, 0
	add := func(id string, keys []string) error {
		path, ok := options.Sources[id]
		if !ok || seen[id] {
			return nil // The compiler reports missing and duplicate sources.
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if id == dnsSource {
			keys = append(keys, dnsKeys...)
		}
		entry, resources, err := loadSource(id, path, keys, read)
		if err != nil {
			return fmt.Errorf("cannot read source %s: %w", id, err)
		}
		size += len(entry)
		for hash, data := range resources {
			if _, exists := b.Resources[hash]; !exists {
				b.Resources[hash] = data
				resourceBytes += len(data)
			}
		}
		if size > MaxBundleBytes {
			return errBundleTooLarge
		}
		if resourceBytes > maxAssetBytes {
			return errors.New("imported rule resources exceed 32 MiB")
		}
		document.Sources = append(document.Sources, entry)
		seen[id] = true
		return nil
	}
	for _, imp := range profile.Imports {
		if err := add(imp.Source, importedKeys(imp, ruleSources[imp.Source])); err != nil {
			return err
		}
	}
	if dnsSource != "" {
		if err := add(dnsSource, nil); err != nil {
			return err
		}
	}
	if len(document.Sources) == 0 {
		return nil
	}
	var err error
	b.Sources, err = json.Marshal(document)
	return err
}

// dnsKeys are a source's DNS section and the rule sets its policies may
// match, including pinned geodata slices. Servers that dial through the
// source's nodes or groups need the profile to import them, as on desktop.
var dnsKeys = []string{"dns", "rule-sets"}

// importedKeys lists the parts of a source the profile uses. The rest stays
// out of the bundle: the extension would otherwise parse and validate a
// subscription's whole rule list when the profile only imports its nodes.
func importedKeys(imp model.Import, marker bool) []string {
	if marker {
		// A rule marker routes through the source's own rules, which may
		// reference any of its parts.
		return []string{"outbounds", "groups", "rules", "rule-sets", "sub-rules"}
	}
	var keys []string
	if imp.Outbounds || imp.Groups {
		keys = append(keys, "outbounds") // Groups reference the source's nodes.
	}
	if imp.Groups {
		keys = append(keys, "groups")
	}
	if imp.RuleSets {
		keys = append(keys, "rule-sets")
	}
	if imp.SubRules {
		// Sub-rules route to the source's nodes and groups and may use its rule sets.
		keys = append(keys, "outbounds", "groups", "sub-rules", "rule-sets")
	}
	return keys
}

func loadSource(id, path string, keys []string, read func(string) ([]byte, error)) (json.RawMessage, map[string][]byte, error) {
	raw, err := readBundleFile(path)
	if err != nil {
		return nil, nil, errors.New("snapshot file is unreadable, not regular, or too large")
	}
	bundle, err := Decode(raw)
	if err != nil {
		return nil, nil, err
	}
	// Import the subscription profile without applying its own overlay.
	var profile map[string]json.RawMessage
	if json.Unmarshal(bundle.Profile, &profile) != nil || profile == nil {
		return nil, nil, errors.New("invalid subscription profile")
	}
	encodedID, _ := json.Marshal(id)
	entry := map[string]json.RawMessage{"id": encodedID}
	for _, key := range keys {
		if key == "dns" && !bundle.OwnDNS {
			continue // Preparation added default DNS; the source has none.
		}
		if value, ok := profile[key]; ok {
			entry[key] = value
		}
	}
	encoded, err := json.Marshal(entry)
	if err != nil || len(entry["rule-sets"]) == 0 {
		return encoded, nil, err
	}
	var sets []struct {
		Hash string `json:"hash"`
	}
	if json.Unmarshal(entry["rule-sets"], &sets) != nil {
		return nil, nil, errors.New("invalid subscription rule sets")
	}
	// Normalized subscriptions also pin their geodata slices as rule sets.
	resources := make(map[string][]byte)
	for _, set := range sets {
		if set.Hash == "" || resources[set.Hash] != nil {
			continue
		}
		data := bundle.Resources[set.Hash]
		if data == nil && slices.Contains(bundle.OmittedResources, set.Hash) {
			data, err = read(set.Hash)
			if err != nil || len(data) == 0 {
				return nil, nil, errSnapshotNeedsPreparation
			}
		}
		if data == nil || !resource.ValidHash(set.Hash) || resource.Hash(data) != set.Hash {
			return nil, nil, errors.New("missing or invalid locked rule resource")
		}
		resources[set.Hash] = data
	}
	return encoded, resources, nil
}

// refreshSources replaces the archived copies of imported sources with the
// bundles in options. Resources that only the old copies used are dropped.
func (b *Bundle) refreshSources(ctx context.Context, options PrepareOptions, read func(string) ([]byte, error)) error {
	profile, _, diagnostics := model.ParseProfile(b.Profile)
	if diagnostics.HasErrors() {
		return &ValidationError{"Invalid profile", diagnostics}
	}
	type pinned struct {
		Hash string `json:"hash"`
	}
	var own struct {
		RuleSets []pinned `json:"rule-sets"`
		Geodata  []pinned `json:"geodata"`
	}
	var previous struct {
		Sources []struct {
			RuleSets []pinned `json:"rule-sets"`
		} `json:"sources"`
	}
	if json.Unmarshal(b.Profile, &own) != nil || (len(b.Sources) > 0 && json.Unmarshal(b.Sources, &previous) != nil) {
		return errors.New("invalid archived profile")
	}
	kept := make(map[string]bool)
	for _, set := range append(own.RuleSets, own.Geodata...) {
		kept[set.Hash] = true
	}
	patches, err := parseOverlay(b.Overlay)
	if err != nil {
		return err
	}
	for _, patch := range patches {
		path, err := model.SplitPath(patch.Path)
		if err != nil || len(path) == 0 || path[0] != "rule-sets" {
			continue
		}
		var set pinned
		switch {
		case patch.Op == "insert" && len(path) == 1, patch.Op == "set" && len(path) == 2:
			_ = json.Unmarshal(patch.Value, &set)
		case patch.Op == "set" && len(path) == 3 && path[2] == "hash":
			_ = json.Unmarshal(patch.Value, &set.Hash)
		}
		if set.Hash != "" {
			kept[set.Hash] = true
		}
	}
	removed := make(map[string]bool)
	for _, source := range previous.Sources {
		for _, set := range source.RuleSets {
			if !kept[set.Hash] {
				delete(b.Resources, set.Hash)
				removed[set.Hash] = true
			}
		}
	}
	b.OmittedResources = slices.DeleteFunc(b.OmittedResources, func(hash string) bool { return removed[hash] })
	if b.Resources == nil {
		b.Resources = make(map[string][]byte)
	}
	b.Sources = nil
	return b.prepareSources(ctx, profile, options, read)
}
