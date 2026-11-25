package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

type sourceDocument struct {
	SchemaVersion int               `json:"schema-version"`
	Sources       []json.RawMessage `json:"sources"`
}

type pinnedResource struct {
	Hash string `json:"hash"`
}

type sourceResources struct {
	ID       string                `json:"id"`
	RuleSets []pinnedResource      `json:"rule-sets"`
	MapLocal []pinnedResource      `json:"map-local"`
	Scripts  []pinnedResource      `json:"scripts"`
	Module   *model.ModuleSnapshot `json:"module"`
	Lock     *model.SourceLock     `json:"lock"`
}

func (s sourceResources) hashes() []string {
	hashes := s.requiredHashes()
	for _, item := range s.RuleSets {
		if item.Hash != "" {
			hashes = append(hashes, item.Hash)
		}
	}
	return hashes
}

func (s sourceResources) requiredHashes() []string {
	var hashes []string
	for _, list := range [][]pinnedResource{s.MapLocal, s.Scripts} {
		for _, item := range list {
			if item.Hash != "" {
				hashes = append(hashes, item.Hash)
			}
		}
	}
	if s.Module != nil && s.Lock != nil {
		hashes = append(hashes, s.Lock.Root)
		for _, entry := range s.Lock.Resources {
			hashes = append(hashes, entry.Hash)
		}
	}
	return hashes
}

// A precompiled rule can cover a digest also used by a module, a Map Local
// entry, or a script. Those consumers need the original bytes in the snapshot.
func (b *Bundle) requiredSourceResources() map[string]bool {
	var document sourceDocument
	if len(b.Sources) == 0 || json.Unmarshal(b.Sources, &document) != nil {
		return nil
	}
	required := make(map[string]bool)
	for _, entry := range document.Sources {
		var refs sourceResources
		if json.Unmarshal(entry, &refs) == nil {
			for _, hash := range refs.requiredHashes() {
				required[hash] = true
			}
		}
	}
	return required
}

// mapLocalResourceHashes enumerates the file resources that may still be
// read by rewrites after snapshot compilation.
func (b *Bundle) mapLocalResourceHashes() map[string]bool {
	var document sourceDocument
	_ = json.Unmarshal(b.Sources, &document)
	required := make(map[string]bool)
	for _, entry := range append(document.Sources, b.Profile) {
		var refs sourceResources
		if json.Unmarshal(entry, &refs) != nil {
			continue
		}
		for _, item := range refs.MapLocal {
			required[item.Hash] = true
		}
		if refs.Module != nil && refs.Lock != nil {
			for _, lock := range refs.Lock.Resources {
				if lock.Kind == "map-local" {
					required[lock.Hash] = true
				}
			}
		}
	}
	patches, _ := parseOverlay(b.Overlay)
	for _, patch := range patches {
		if kind, hash := overlayResourceHash(patch); kind == "map-local" && hash != "" {
			required[hash] = true
		}
	}
	return required
}

func overlayResourceHash(patch model.Op) (string, string) {
	path, err := model.SplitPath(patch.Path)
	if err != nil || len(path) == 0 {
		return "", ""
	}
	var item pinnedResource
	switch {
	case patch.Op == "insert" && len(path) == 1, patch.Op == "set" && len(path) == 2:
		_ = json.Unmarshal(patch.Value, &item)
	case patch.Op == "set" && len(path) == 3 && path[2] == "hash":
		_ = json.Unmarshal(patch.Value, &item.Hash)
	}
	return path[0], item.Hash
}

func (b *Bundle) prepareSources(ctx context.Context, profile *model.Profile, options PrepareOptions, read func(string) ([]byte, error)) error {
	return b.bindSources(ctx, profile, options, read, nil, true, profile.Modules)
}

func (b *Bundle) bindSources(ctx context.Context, profile *model.Profile, options PrepareOptions, read func(string) ([]byte, error), retained []json.RawMessage, subscriptions bool, modules []model.Module) error {
	// dns.from selects a source's DNS whether or not the profile imports
	// anything else from that source.
	dnsSource := ""
	if !options.NodesOnly && profile.DNS != nil {
		dnsSource = profile.DNS.From
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
	document := sourceDocument{SchemaVersion: model.SchemaVersion, Sources: retained}
	size, resourceBytes := 0, 0
	counted := make(map[string]bool)
	countResource := func(hash string, data []byte) {
		if data != nil && !counted[hash] {
			resourceBytes += len(data)
			counted[hash] = true
		}
	}
	for _, entry := range retained {
		size += len(entry)
		var refs sourceResources
		if err := json.Unmarshal(entry, &refs); err != nil {
			return errors.New("invalid archived source")
		}
		for _, hash := range refs.hashes() {
			countResource(hash, b.Resources[hash])
		}
	}
	add := func(entry json.RawMessage, resources map[string][]byte) error {
		document.Sources = append(document.Sources, entry)
		size += len(entry)
		for hash, data := range resources {
			countResource(hash, data)
		}
		if size > MaxBundleBytes {
			return errBundleTooLarge
		}
		if resourceBytes > maxAssetBytes {
			return errors.New("imported source resources exceed 32 MiB")
		}
		maps.Copy(b.Resources, resources)
		return nil
	}
	seen := make(map[string]bool)
	addSubscription := func(id string, keys []string) error {
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
		seen[id] = true
		return add(entry, resources)
	}
	if subscriptions {
		for _, imp := range profile.Imports {
			if err := addSubscription(imp.Source, importedKeys(imp, ruleSources[imp.Source])); err != nil {
				return err
			}
		}
		if dnsSource != "" {
			if err := addSubscription(dnsSource, nil); err != nil {
				return err
			}
		}
	}
	for _, def := range modules {
		if !def.IsEnabled() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		path := options.Modules[def.ID]
		if path == "" {
			return moduleSnapshotError(def.ID, "module snapshot is missing; acquire the module")
		}
		snapshot, err := LoadModuleSnapshot(path)
		if err != nil {
			return moduleSnapshotError(def.ID, "module snapshot is unreadable or invalid; acquire the module again")
		}
		if !snapshot.matches(def) {
			return moduleSnapshotError(def.ID, "module snapshot does not match the declared ID, location, or format. Acquire the module again.")
		}
		entry, err := json.Marshal(snapshot.Source)
		if err != nil {
			return err
		}
		if err := add(entry, snapshot.Resources); err != nil {
			return err
		}
	}
	b.Sources = nil
	if len(document.Sources) == 0 {
		return nil
	}
	var err error
	b.Sources, err = json.Marshal(document)
	return err
}

func moduleSnapshotError(id, message string) *ValidationError {
	return &ValidationError{fmt.Sprintf("Module %q: %s", id, message), model.Diagnostics{{
		Severity: model.SeverityError, Code: "module.download", Document: model.DocProfile,
		Path: model.JoinPath("/modules", id), Message: message,
	}}}
}

// dnsKeys are a source's DNS section and the rule sets its policies may
// match, including pinned geodata slices. Servers that dial through the
// source's nodes or groups need the profile to import them, as on desktop.
var dnsKeys = []string{"dns", "rule-sets"}

// importedKeys lists the parts of a source the profile uses. The rest stays
// out of the bundle: the extension would otherwise parse and validate a
// subscription's whole rule list when the profile only imports its nodes.
func importedKeys(imp model.Import, marker bool) []string {
	var keys []string
	if imp.Rewrites {
		keys = append(keys, "mitm", "http-rewrites", "header-rewrites", "body-rewrites", "map-local", "scripts")
	}
	if marker {
		// A rule marker routes through the source's own rules, which may
		// reference any of its parts.
		return append(keys, "outbounds", "groups", "rules", "rule-sets", "sub-rules")
	}
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
	// Import only the selected profile sections, without its modules or overlay.
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
	if err != nil || len(entry["rule-sets"]) == 0 && len(entry["map-local"]) == 0 && len(entry["scripts"]) == 0 {
		return encoded, nil, err
	}
	var refs sourceResources
	if json.Unmarshal(encoded, &refs) != nil {
		return nil, nil, errors.New("invalid subscription resource references")
	}
	// Normalized subscriptions also pin their geodata slices as rule sets.
	resources := make(map[string][]byte)
	for _, hash := range refs.hashes() {
		if resources[hash] != nil {
			continue
		}
		data := bundle.Resources[hash]
		if data == nil && slices.Contains(bundle.OmittedResources, hash) {
			data, err = read(hash)
			if err != nil || len(data) == 0 {
				return nil, nil, errSnapshotNeedsPreparation
			}
		}
		if data == nil || !resource.ValidHash(hash) || resource.Hash(data) != hash {
			return nil, nil, errors.New("missing or invalid locked source resource")
		}
		resources[hash] = data
	}
	return encoded, resources, nil
}

// refreshSources replaces the selected kinds of archived sources and drops
// resources referenced only by the replaced entries.
func (b *Bundle) refreshSources(ctx context.Context, profile *model.Profile, previousDeviceModules []string, options PrepareOptions, read func(string) ([]byte, error)) error {
	var own struct {
		sourceResources
		Geodata []pinnedResource `json:"geodata"`
	}
	var previous sourceDocument
	if json.Unmarshal(b.Profile, &own) != nil || (len(b.Sources) > 0 && json.Unmarshal(b.Sources, &previous) != nil) {
		return errors.New("invalid archived profile")
	}
	kept := make(map[string]bool)
	for _, hash := range own.hashes() {
		kept[hash] = true
	}
	for _, set := range own.Geodata {
		kept[set.Hash] = true
	}
	if b.Precompiled != nil {
		for _, hash := range b.Precompiled.Sets {
			kept[hash] = true
		}
	}
	patches, err := parseOverlay(b.Overlay)
	if err != nil {
		return err
	}
	for _, patch := range patches {
		kind, hash := overlayResourceHash(patch)
		if hash != "" && (kind == "rule-sets" || kind == "map-local" || kind == "scripts") {
			kept[hash] = true
		}
	}
	var retained []json.RawMessage
	var replacedHashes []string
	deviceDefinitions := make(map[string]model.Module)
	if options.DeviceModules != nil && options.Modules == nil {
		for _, def := range profile.Modules {
			if slices.Contains(b.DeviceModules, def.ID) {
				deviceDefinitions[def.ID] = def
			}
		}
	}
	retainedModules := make(map[string]bool)
	for _, entry := range previous.Sources {
		var refs sourceResources
		if json.Unmarshal(entry, &refs) != nil {
			return errors.New("invalid archived source")
		}
		replace := options.RefreshSources
		if refs.Module != nil {
			replace = options.Modules != nil
			if !replace && options.DeviceModules != nil && slices.Contains(previousDeviceModules, refs.ID) {
				def, found := deviceDefinitions[refs.ID]
				// A module at the same location can use its archived lock.
				replace = !found || !def.IsEnabled() || def.RequestHash() != refs.Module.Request
			}
			if !replace {
				retainedModules[refs.ID] = true
			}
		}
		if replace {
			replacedHashes = append(replacedHashes, refs.hashes()...)
			continue
		}
		retained = append(retained, entry)
		for _, hash := range refs.hashes() {
			kept[hash] = true
		}
	}
	removed := make(map[string]bool)
	for _, hash := range replacedHashes {
		if !kept[hash] {
			delete(b.Resources, hash)
			removed[hash] = true
		}
	}
	b.OmittedResources = slices.DeleteFunc(b.OmittedResources, func(hash string) bool { return removed[hash] })
	if b.Resources == nil {
		b.Resources = make(map[string][]byte)
	}
	var modules []model.Module
	for _, def := range profile.Modules {
		if _, device := deviceDefinitions[def.ID]; options.Modules != nil || device && !retainedModules[def.ID] {
			modules = append(modules, def)
		}
	}
	return b.bindSources(ctx, profile, options, read, retained, options.RefreshSources, modules)
}
