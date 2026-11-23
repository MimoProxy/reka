package profile

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
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
	sets := make(map[string]string)
	blobs := make(map[string][]byte)
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

func marshalPreparedBundle(b *Bundle) ([]byte, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if len(data) <= MaxBundleBytes {
		return data, nil
	}
	if b.Precompiled == nil {
		return nil, errBundleTooLarge
	}

	trimmed := *b
	trimmed.Precompiled = nil
	trimmed.Resources = b.originalResources()
	data, err = json.Marshal(&trimmed)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBundleBytes {
		return nil, errBundleTooLarge
	}

	// Keep the optional cache within the snapshot limit, prioritizing large
	// matchers. All keys and digests are generated hex strings.
	manifest := precompiledRuleSets{Version: b.Precompiled.Version, Sets: make(map[string]string)}
	header, _ := json.Marshal(manifest)
	room := MaxBundleBytes - len(data) - len(`,"precompiled-rule-sets":`) - len(header)
	if len(trimmed.Resources) == 0 {
		room -= len(`,"resources":{}`)
	}
	keys := slices.Sorted(maps.Keys(b.Precompiled.Sets))
	slices.SortStableFunc(keys, func(a, c string) int {
		return cmp.Compare(len(b.Resources[b.Precompiled.Sets[c]]), len(b.Resources[b.Precompiled.Sets[a]]))
	})
	const pairDelimiters = len(`"":"",`)
	for _, key := range keys {
		hash := b.Precompiled.Sets[key]
		blob := b.Resources[hash]
		cost := len(key) + len(hash) + pairDelimiters
		if trimmed.Resources[hash] == nil {
			cost += len(hash) + base64.StdEncoding.EncodedLen(len(blob)) + pairDelimiters
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
