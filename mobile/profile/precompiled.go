package profile

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/rulesdata"
	"github.com/MimoProxy/reka/internal/secret"
)

type precompiledRuleSets struct {
	Version int               `json:"version"`
	Sets    map[string]string `json:"sets"`
}

func (p *precompiledRuleSets) reader(read func(string) (*router.PrecompiledRuleSet, []byte)) func(string) (*router.PrecompiledRuleSet, []byte) {
	if p == nil || p.Version != router.PrecompiledRuleSetVersion || len(p.Sets) == 0 {
		return nil
	}
	return func(id string) (*router.PrecompiledRuleSet, []byte) {
		hash := p.Sets[id]
		if !resource.ValidHash(hash) {
			return nil, nil
		}
		return read(hash)
	}
}

func (b *Bundle) readPrecompiledRuleSet(hash string) (*router.PrecompiledRuleSet, []byte) {
	data, err := b.readResource(hash)
	if err != nil || resource.Hash(data) != hash {
		return nil, nil
	}
	return readPrecompiledRuleSet(bytes.NewReader(data)), data
}

func readPrecompiledRuleSet(r io.Reader) *router.PrecompiledRuleSet {
	set, _ := router.ReadPrecompiledRuleSet(r, iosRuleMemoryBudget, rulesdata.MaxEntries*2)
	return set
}

func (b *Bundle) compileForPreparation(secrets secret.Store) (*compile.Effective, model.Diagnostics) {
	opts := b.compileOptions(b.readResource, secrets, true)
	opts.MaxPrecompiledRuleBytes = iosRuleMemoryBudget
	sets := make(map[string]string)
	blobs := make(map[string][]byte)
	coverage := make(map[string][]string)
	opts.RecordPrecompiledCoverage = func(hash string, keys []string) {
		coverage[hash] = keys
	}
	opts.RecordPrecompiledRuleSet = func(key string, data []byte) {
		hash := resource.Hash(data)
		sets[key] = hash
		blobs[hash] = data
	}
	eff, diagnostics := b.compile(opts)
	if diagnostics.HasErrors() || b.Precompiled == nil && len(sets) == 0 {
		return eff, diagnostics
	}
	b.Resources = b.originalResources()
	maps.Copy(b.Resources, blobs)
	b.precompiledCoverage = coverage
	b.Precompiled = nil
	if len(sets) > 0 {
		b.Precompiled = &precompiledRuleSets{Version: router.PrecompiledRuleSetVersion, Sets: sets}
	}
	return eff, diagnostics
}

func (b *Bundle) originalResources() map[string][]byte {
	// Overlay retries use shallow copies of the bundle.
	resources := make(map[string][]byte, len(b.Resources))
	maps.Copy(resources, b.Resources)
	if b.Precompiled != nil {
		for _, hash := range b.Precompiled.Sets {
			delete(resources, hash)
		}
	}
	return resources
}

func (b *Bundle) restoreOmittedResources(read func(string) ([]byte, error)) {
	var unavailable []string
	for _, hash := range b.OmittedResources {
		if b.Resources[hash] != nil {
			continue
		}
		data, err := read(hash)
		if err != nil || len(data) == 0 || resource.Hash(data) != hash {
			unavailable = append(unavailable, hash)
			continue
		}
		if b.Resources == nil {
			b.Resources = make(map[string][]byte)
		}
		b.Resources[hash] = data
	}
	b.OmittedResources = unavailable
}

func marshalPreparedBundle(b *Bundle) ([]byte, []string, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return nil, nil, err
	}
	if len(data) <= MaxBundleBytes {
		return data, b.OmittedResources, nil
	}
	if b.Precompiled == nil {
		return nil, nil, errBundleTooLarge
	}

	trimmed := *b
	trimmed.Resources = maps.Clone(b.Resources)
	trimmed.OmittedResources = slices.Clone(b.OmittedResources)
	for _, hash := range slices.Sorted(maps.Keys(b.precompiledCoverage)) {
		if trimmed.Resources[hash] != nil {
			delete(trimmed.Resources, hash)
			trimmed.OmittedResources = append(trimmed.OmittedResources, hash)
		}
	}
	if len(trimmed.OmittedResources) > len(b.OmittedResources) {
		data, err = json.Marshal(&trimmed)
		if err != nil || len(data) <= MaxBundleBytes {
			return data, trimmed.OmittedResources, err
		}
	}
	data, err = trimmed.trimOptionalPrecompiled()
	if errors.Is(err, errBundleTooLarge) && len(trimmed.OmittedResources) > len(b.OmittedResources) {
		trimmed.restoreLargerCaches(b.Resources)
		data, err = trimmed.trimOptionalPrecompiled()
		if !errors.Is(err, errBundleTooLarge) {
			return data, trimmed.OmittedResources, err
		}
		data, err = b.trimOptionalPrecompiled()
		return data, b.OmittedResources, err
	}
	return data, trimmed.OmittedResources, err
}

// Restore sources that take less space than their required artifacts.
func (b *Bundle) restoreLargerCaches(originals map[string][]byte) {
	uses := make(map[string]int)
	for _, source := range b.OmittedResources {
		for _, key := range b.precompiledCoverage[source] {
			uses[b.Precompiled.Sets[key]]++
		}
	}
	b.OmittedResources = slices.DeleteFunc(b.OmittedResources, func(source string) bool {
		original := originals[source]
		if original == nil {
			return false
		}
		cost := len(source) + len(`"",`)
		artifacts := make(map[string]int)
		for _, key := range b.precompiledCoverage[source] {
			hash := b.Precompiled.Sets[key]
			cost += len(key) + len(hash) + jsonPairDelimiters
			artifacts[hash]++
		}
		for hash, n := range artifacts {
			if uses[hash] == n {
				cost += resourceJSONCost(hash, b.Resources[hash])
			}
		}
		if cost < resourceJSONCost(source, original) {
			return false
		}
		for hash, n := range artifacts {
			uses[hash] -= n
		}
		b.Resources[source] = original
		return true
	})
}

const jsonPairDelimiters = len(`"":"",`)

func resourceJSONCost(hash string, data []byte) int {
	return len(hash) + base64.StdEncoding.EncodedLen(len(data)) + jsonPairDelimiters
}

func (b *Bundle) trimOptionalPrecompiled() ([]byte, error) {
	trimmed := *b
	trimmed.Resources = b.originalResources()
	manifest := precompiledRuleSets{Version: b.Precompiled.Version, Sets: make(map[string]string)}
	for _, source := range b.OmittedResources {
		for _, key := range b.precompiledCoverage[source] {
			hash := b.Precompiled.Sets[key]
			manifest.Sets[key] = hash
			trimmed.Resources[hash] = b.Resources[hash]
		}
	}
	trimmed.Precompiled = nil
	if len(manifest.Sets) > 0 {
		trimmed.Precompiled = &manifest
	}
	data, err := json.Marshal(&trimmed)
	if err != nil {
		return nil, err
	}
	room := MaxBundleBytes - len(data)
	if room < 0 {
		return nil, errBundleTooLarge
	}
	if trimmed.Precompiled == nil {
		header, _ := json.Marshal(manifest)
		room -= len(`,"precompiled-rule-sets":`) + len(header)
	}
	if len(trimmed.Resources) == 0 {
		room -= len(`,"resources":{}`)
	}
	// Keep optional matchers in size order with the remaining space.
	keys := slices.Sorted(maps.Keys(b.Precompiled.Sets))
	slices.SortStableFunc(keys, func(a, c string) int {
		return cmp.Compare(len(b.Resources[b.Precompiled.Sets[c]]), len(b.Resources[b.Precompiled.Sets[a]]))
	})
	for _, key := range keys {
		if manifest.Sets[key] != "" {
			continue
		}
		hash := b.Precompiled.Sets[key]
		blob := b.Resources[hash]
		cost := len(key) + len(hash) + jsonPairDelimiters
		if trimmed.Resources[hash] == nil {
			cost += resourceJSONCost(hash, blob)
		}
		if cost <= room {
			manifest.Sets[key] = hash
			trimmed.Resources[hash] = blob
			room -= cost
		}
	}
	if len(manifest.Sets) == 0 {
		return data, nil
	}
	trimmed.Precompiled = &manifest
	return json.Marshal(&trimmed)
}
