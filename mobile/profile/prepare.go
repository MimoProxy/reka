package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/subscription"
	"go.yaml.in/yaml/v3"
)

const maxAssetBytes = 32 << 20
const dnsCacheLimit = 512
const dnsUpstreamLimit = 2

type PrepareOptions struct {
	NodesOnly         bool                               `json:"nodesOnly"`
	ProviderDirectory string                             `json:"providerDirectory"`
	PreviousState     string                             `json:"previousState"`
	OutputState       string                             `json:"outputState"`
	RefreshAsset      string                             `json:"refreshAsset"`
	ForceProviders    bool                               `json:"forceProviders"`
	Scenes            []SceneDefinition                  `json:"scenes"`
	RebindSnapshot    string                             `json:"rebindSnapshot"`
	GeodataSources    map[string]string                  `json:"geodataSources,omitempty"`
	Overlay           json.RawMessage                    `json:"overlay,omitempty"` // Overlay document for a new preparation.
	Secrets           secret.Store                       `json:"-"`
	ClientFor         func(string) (*http.Client, error) `json:"-"`
	// Sources maps source IDs to prepared bundles of subscriptions. Only the
	// sources a native profile imports are read.
	Sources map[string]string `json:"sources,omitempty"`
	// RefreshSources makes a rebind read Sources again instead of keeping the
	// archived copies, so a subscription update reaches the profiles that
	// import it without fetching their own resources.
	RefreshSources bool `json:"refreshSources,omitempty"`
}

type SceneDefinition struct {
	ID        string   `json:"id"`
	Interface string   `json:"interface,omitempty"`
	IPCIDR    []string `json:"ip-cidr,omitempty"`
}

func sceneSettings(scenes []SceneDefinition) (json.RawMessage, error) {
	if len(scenes) > 32 {
		return nil, errors.New("at most 32 network scenes are supported")
	}
	if len(scenes) == 0 {
		return nil, nil
	}
	return json.Marshal(struct {
		Version int               `json:"schema-version"`
		Scenes  []SceneDefinition `json:"network-scenes"`
	}{1, scenes})
}

type Asset struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Source       string   `json:"source"`
	UpdatedMS    int64    `json:"updatedMs,omitempty"`
	NextMS       int64    `json:"nextMs,omitempty"`
	Automatic    bool     `json:"automatic,omitempty"`
	Members      []string `json:"members,omitempty"`
	UsesFallback bool     `json:"usesFallback,omitempty"`
	Shared       bool     `json:"shared,omitempty"`
	URL          string   `json:"url,omitempty"`
	Codes        []string `json:"codes,omitempty"`
	Size         int64    `json:"size,omitempty"`
}

type ValidationError struct {
	Message     string            `json:"message"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
}

func (e *ValidationError) Error() string { return e.Message }

type preparer struct {
	options PrepareOptions
	cache   string
	client  *http.Client
	fetcher *subscription.Fetcher
	batch   *subscription.Batch
	assets  []Asset
}

func PrepareFile(ctx context.Context, input, output, geodataCache string) error {
	return PrepareFileWithOptions(ctx, input, output, geodataCache, PrepareOptions{})
}

// PrepareFileWithOptions writes files under the app's candidate revision. They
// become the last-good source and validators when the app publishes that revision.
func PrepareFileWithOptions(ctx context.Context, input, output, cache string, options PrepareOptions) error {
	client := subscription.HTTPClientWithControl(nil, systemLookup)
	defer client.CloseIdleConnections()
	return prepareFile(ctx, input, output, cache, options, client)
}

// systemLookup resolves through the platform resolver. The app sandbox on iOS
// has no resolv.conf, so Go's own resolver would only query 127.0.0.1:53.
func systemLookup(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func prepareFile(ctx context.Context, input, output, cache string, options PrepareOptions, client *http.Client) error {
	info, err := os.Stat(input)
	if err != nil || !info.Mode().IsRegular() || info.Size() > model.MaxDocumentSize {
		return errors.New("cannot read profile")
	}
	raw, err := os.ReadFile(input)
	if err != nil || len(raw) > model.MaxDocumentSize {
		return errors.New("cannot read profile")
	}
	blobs, err := resource.Open(cache)
	if err != nil {
		return errors.New("cannot open profile resource cache")
	}
	var previous map[string]subscription.Entry
	if info, err := os.Stat(options.PreviousState); err == nil && info.Size() <= 512<<10 {
		if data, err := os.ReadFile(options.PreviousState); err == nil {
			_ = json.Unmarshal(data, &previous)
		}
	}
	fetcher := &subscription.Fetcher{Client: client, Blobs: blobs, MaxBytes: maxAssetBytes}
	p := &preparer{options: options, cache: cache, client: client, fetcher: fetcher, batch: fetcher.Batch(previous, false)}
	var bundle *Bundle
	if options.RebindSnapshot != "" {
		bundle, err = rebind(ctx, options.RebindSnapshot, options, p.readLockedResource)
		if err == nil {
			for hash, data := range bundle.originalResources() {
				if !resource.ValidHash(hash) || resource.Hash(data) != hash {
					return errors.New("archive resource digest mismatch")
				}
				if _, err := blobs.Put(data); err != nil {
					return errors.New("cannot cache archive resources")
				}
			}
			p.batch.Entries = previous
		}
	} else {
		bundle, err = prepare(ctx, raw, p)
	}
	if err != nil {
		return err
	}
	if options.RefreshAsset != "" && !slices.ContainsFunc(bundle.Summary.Resources, func(a Asset) bool { return a.ID == options.RefreshAsset }) {
		return errors.New("the selected resource is no longer referenced")
	}
	data, omitted, err := marshalPreparedBundle(bundle)
	if err != nil {
		return err
	}
	for _, hash := range omitted {
		if original := bundle.Resources[hash]; original != nil {
			if saved, err := blobs.Put(original); err != nil || saved != hash {
				return errors.New("cannot cache original rule resource")
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if options.OutputState != "" {
		for key := range p.batch.Entries {
			if strings.HasPrefix(key, "geodata/") {
				delete(p.batch.Entries, key)
			}
		}
		state, err := json.Marshal(p.batch.Entries)
		if err != nil {
			return errors.New("cannot encode resource state")
		}
		if err := writeAtomic(options.OutputState, state); err != nil {
			return err
		}
	}
	return writeAtomic(output, data)
}

func prepare(ctx context.Context, raw []byte, p *preparer) (*Bundle, error) {
	if p == nil {
		p = &preparer{}
	}
	patches, err := parseOverlay(p.options.Overlay)
	if err != nil {
		return nil, err
	}
	selectors := make(geodataSelectors)
	selectors.collectOverlay(patches)
	var native *model.Profile
	var document map[string]any
	var positions map[string]model.Pos
	var diagnostics model.Diagnostics
	format := "native"
	root, _ := model.ParseNode(model.DocProfile, raw)
	if root != nil && root.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == "schema-version" {
				native, positions, diagnostics = model.ParseProfile(raw)
				if diagnostics.HasErrors() {
					return nil, &ValidationError{"Invalid Reka profile", diagnostics}
				}
				if root.Decode(&document) != nil {
					return nil, errors.New("invalid native profile")
				}
				break
			}
		}
	}
	bundle := &Bundle{Version: bundleVersion, Resources: make(map[string][]byte)}
	if len(patches) > 0 {
		bundle.Overlay = p.options.Overlay
	}
	if document == nil {
		document, format, diagnostics, err = p.importSource(ctx, raw, selectors, bundle.Resources)
		if err != nil {
			return nil, err
		}
	} else {
		if p.options.NodesOnly {
			for _, field := range []string{"rules", "sub-rules", "rule-sets", "geodata", "routing", "dns"} {
				delete(document, field)
			}
		}
		if err := bundle.prepareSources(ctx, native, p.options, p.readLockedResource); err != nil {
			return nil, err
		}
		if err := p.nativeAssets(ctx, document, bundle.Resources); err != nil {
			return nil, err
		}
	}

	if len(patches) > 0 {
		updated, changed, err := p.overlayAssets(ctx, document, patches, bundle.Resources)
		if err != nil {
			return nil, err
		}
		if changed {
			if bundle.Overlay, err = marshalOverlay(updated); err != nil {
				return nil, errors.New("could not encode overlay")
			}
			patches = updated
		}
		// Rule sets the overlay adds or changes can reference geodata in
		// their downloaded contents, which were unknown until now.
		added := make(geodataSelectors)
		added.collectOverlayRuleSets(patches, bundle.Resources)
		if native == nil {
			added.collectDocument(document, bundle.Resources)
			if selectors.merge(added) {
				geodata, err := p.prepareGeodata(ctx, selectors, nil, bundle.Resources)
				if err != nil {
					return nil, err
				}
				pinGeodata(document, geodata)
			}
		} else {
			selectors.merge(added)
		}
	}
	if native != nil {
		selectors.collectDocument(document, bundle.Resources)
		geodata, err := p.prepareGeodata(ctx, selectors, native.Geodata, bundle.Resources)
		if err != nil {
			return nil, err
		}
		pinGeodata(document, geodata)
	}
	normalize(document)
	data, err := json.Marshal(document)
	if err != nil {
		return nil, errors.New("could not encode profile")
	}
	bundle.Profile = data
	bundle.Local, err = sceneSettings(p.options.Scenes)
	if err != nil {
		return nil, err
	}
	eff, compileDiagnostics, patchStatuses, err := bundle.compileOverlay(ctx, patches, p.options.Secrets)
	if err != nil {
		return nil, err
	}
	if !compileDiagnostics.HasErrors() {
		compileDiagnostics = appendRuleMemoryDiagnostic(compileDiagnostics, eff.RuleMemory)
	}
	for i := range compileDiagnostics {
		d := &compileDiagnostics[i]
		if pos, ok := positions[d.Path]; ok && d.Document == model.DocProfile {
			d.Line, d.Column = pos.Line, pos.Column
		} else {
			// The compiler read normalized JSON. Its line numbers don't refer
			// to the source shown in the app's editor.
			d.Line, d.Column = 0, 0
		}
	}
	diagnostics = append(diagnostics, compileDiagnostics...)
	if diagnostics.HasErrors() {
		return nil, preparationValidationError(diagnostics)
	}
	bundle.Summary = Describe(eff)
	bundle.Summary.Format = format
	bundle.Summary.Diagnostics = diagnostics
	bundle.Summary.Resources = p.assets
	bundle.Summary.Patches = patchStatuses
	return bundle, nil
}

func normalize(document map[string]any) {
	delete(document, "listeners")
	dns, ok := document["dns"].(map[string]any)
	if !ok {
		dns = map[string]any{
			"nameserver": []string{"system", "https://1.1.1.1/dns-query"}, "enhanced-mode": "fake-ip",
			"fake-ip-range": "198.18.0.0/16", "ipv6": true,
		}
		document["dns"] = dns
	}
	delete(dns, "listen")
	dns["cache-size"] = boundedNumber(dns["cache-size"], dnsCacheLimit)
	dns["max-concurrent-upstreams"] = boundedNumber(dns["max-concurrent-upstreams"], dnsUpstreamLimit)
}

func rebind(ctx context.Context, path string, options PrepareOptions, read func(string) ([]byte, error)) (*Bundle, error) {
	// Restore uses the overlay and patch statuses stored in the archive.
	if _, err := parseOverlay(options.Overlay); err != nil {
		return nil, err
	}
	raw, err := readBundleFile(path)
	if err != nil {
		return nil, errors.New("cannot read prepared archive")
	}
	bundle, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if json.Unmarshal(bundle.Profile, &document) != nil || document == nil {
		return nil, errors.New("invalid archived profile")
	}
	normalize(document)
	bundle.Profile, err = json.Marshal(document)
	if err != nil {
		return nil, err
	}
	if options.RefreshSources {
		if err := bundle.refreshSources(ctx, options, read); err != nil {
			return nil, err
		}
	}
	bundle.restoreOmittedResources(read)
	bundle.Local, err = sceneSettings(options.Scenes)
	if err != nil {
		return nil, err
	}
	eff, diagnostics := bundle.compileForPreparation(options.Secrets)
	if !diagnostics.HasErrors() {
		diagnostics = appendRuleMemoryDiagnostic(diagnostics, eff.RuleMemory)
	}
	if diagnostics.HasErrors() {
		return nil, preparationValidationError(diagnostics)
	}
	original := bundle.Summary
	bundle.Summary = Describe(eff)
	bundle.Summary.Format = original.Format
	bundle.Summary.Diagnostics = diagnostics
	bundle.Summary.Resources = original.Resources
	bundle.Summary.Patches = original.Patches
	return bundle, nil
}

func boundedNumber(value any, limit int) int {
	switch n := value.(type) {
	case int:
		if n > 0 {
			return min(n, limit)
		}
	case float64:
		if n >= 1 && n < float64(limit) {
			return int(n)
		}
	}
	return limit
}

func (p *preparer) importSource(ctx context.Context, raw []byte, selectors geodataSelectors, resources map[string][]byte) (map[string]any, string, model.Diagnostics, error) {
	req := importer.Request{SourceID: "ios", Data: string(raw), NodesOnly: p.options.NodesOnly}
	providers, err := importer.Providers(req)
	if err != nil {
		preview := importer.Import(req).Report
		return nil, "", nil, &ValidationError{"Invalid subscription or provider definition", preview.Diagnostics}
	}
	payloads := make(map[string][]byte, len(providers))
	assetStart := len(p.assets)
	total := 0
	for _, provider := range providers {
		asset := Asset{ID: "provider/" + provider.ID, Name: provider.Name, Kind: provider.Kind, Source: provider.Type, Automatic: provider.Type == "http"}
		data, err := p.loadProvider(ctx, &asset, provider)
		if err != nil {
			return nil, "", nil, assetError(asset, err)
		}
		if err := importer.ValidateProvider(provider, data); err != nil {
			return nil, "", nil, assetError(asset, err)
		}
		total += len(data)
		if total > maxAssetBytes {
			return nil, "", nil, errors.New("subscription providers exceed 32 MiB")
		}
		payloads[provider.ID] = data
		if provider.Kind == "rule" {
			resources[resource.Hash(data)] = data
		}
		p.assets = append(p.assets, asset)
	}
	refs, err := importer.GeodataSelectors(req, payloads)
	if err != nil {
		return nil, "", nil, errors.New("invalid subscription geodata reference")
	}
	hasOverlayGeodata := len(selectors) > 0
	for _, ref := range refs {
		selectors.addReference(ref)
	}
	geodata, err := p.prepareGeodata(ctx, selectors, nil, resources)
	if err != nil {
		return nil, "", nil, err
	}
	result := importer.ImportBundle(req, payloads, geodata)
	if !result.Report.CanApply {
		return nil, "", nil, &ValidationError{"The subscription contains unsupported settings", result.Report.Diagnostics}
	}
	for _, binding := range result.Report.Bindings {
		if binding.Kind != "outbound" || binding.Provider == "" || !binding.Available {
			continue
		}
		for i := assetStart; i < assetStart+len(providers); i++ {
			if p.assets[i].Kind == "proxy" && p.assets[i].Name == binding.Provider {
				p.assets[i].Members = append(p.assets[i].Members, binding.ID)
				break
			}
		}
	}
	var document map[string]any
	if json.Unmarshal(result.Source, &document) != nil || document == nil {
		return nil, "", nil, errors.New("could not convert subscription")
	}
	delete(document, "id")
	document["schema-version"] = model.SchemaVersion
	if hasOverlayGeodata {
		pinGeodata(document, geodata)
	}
	return document, result.Report.Format, result.Report.Diagnostics, nil
}

func (p *preparer) loadProvider(ctx context.Context, asset *Asset, definition importer.Provider) ([]byte, error) {
	switch definition.Type {
	case "inline":
		return definition.Inline, nil
	case "file":
		key := asset.ID + "/" + resource.Hash([]byte(definition.Path))
		if p.batch != nil && p.options.RefreshAsset != "" && p.options.RefreshAsset != asset.ID {
			old := p.batch.Previous[key]
			if old.Hash != "" {
				if data, err := p.fetcher.Blobs.Read(old.Hash); err == nil {
					p.batch.Entries[key] = old
					setAssetTimes(asset, old)
					return data, nil
				}
			}
		}
		data, err := subscription.ReadProviderFile(p.options.ProviderDirectory, definition.Path)
		if err == nil && p.batch != nil {
			data, err = p.batch.Inline(key, asset.Kind, asset.Name, data)
			if err == nil {
				entry := p.batch.Entries[key]
				entry.Checked = time.Now()
				p.batch.Entries[key] = entry
				setAssetTimes(asset, entry)
			}
		}
		return data, err
	case "http":
		return p.fetch(ctx, asset, definition.URL, http.Header(definition.Headers), definition.Proxy,
			definition.Interval, p.options.ForceProviders, definition.Fallback)
	default:
		return nil, errors.New("unsupported provider type")
	}
}

func (p *preparer) nativeAssets(ctx context.Context, document map[string]any, resources map[string][]byte) error {
	definitions, _ := document["rule-sets"].([]any)
	for _, value := range definitions {
		definition, _ := value.(map[string]any)
		if err := p.ruleSetAsset(ctx, definition, resources); err != nil {
			return err
		}
	}
	return nil
}

// ruleSetAsset loads the resource a rule set downloads or locks and pins its digest.
func (p *preparer) ruleSetAsset(ctx context.Context, definition map[string]any, resources map[string][]byte) error {
	id, _ := definition["id"].(string)
	hash, _ := definition["hash"].(string)
	asset := Asset{ID: "rule-sets/" + id, Name: id, Kind: "rule", Source: "inline"}
	if id == "" {
		return nil
	}
	download, _ := definition["download"].(map[string]any)
	address, _ := download["url"].(string)
	if address == "" && hash == "" {
		p.addAsset(asset)
		return nil
	}
	var data []byte
	var err error
	if address != "" {
		asset.Source = "http"
		asset.Automatic, _ = download["automatic"].(bool)
		interval := intervalSeconds(download["interval"])
		if name, ref := secret.ParseRef(address); ref {
			if p.options.Secrets == nil || secret.ValidName(name) != nil {
				return assetError(asset, errors.New("resource credential unavailable"))
			}
			address, err = p.options.Secrets.Get(name)
			if err != nil {
				return assetError(asset, errors.New("resource credential unavailable"))
			}
			data, err = p.fetch(ctx, &asset, address, nil, "", interval, false, nil)
			if err != nil {
				return assetError(asset, errors.New("protected resource download failed"))
			}
		} else {
			data, err = p.fetch(ctx, &asset, address, nil, "", interval, false, nil)
		}
	} else {
		asset.Source = "file"
		data, err = p.readLockedResource(hash)
	}
	if err != nil {
		return assetError(asset, err)
	}
	digest := resource.Hash(data)
	definition["hash"] = digest
	resources[digest] = data
	p.addAsset(asset)
	return nil
}

func (p *preparer) readLockedResource(hash string) ([]byte, error) {
	if !resource.ValidHash(hash) {
		return nil, errors.New("invalid resource digest")
	}
	if p.fetcher != nil {
		if data, err := p.fetcher.Blobs.Read(hash); err == nil && len(data) > 0 {
			return data, nil
		}
	}
	data, err := subscription.ReadProviderFile(p.options.ProviderDirectory, filepath.Join("resources", "sha256", hash))
	if err == nil && resource.Hash(data) != hash {
		err = errors.New("resource digest mismatch")
	}
	if err == nil && p.fetcher != nil {
		_, err = p.fetcher.Blobs.Put(data)
	}
	return data, err
}

// addAsset lists an asset, replacing an earlier entry with the same ID.
func (p *preparer) addAsset(asset Asset) {
	if i := slices.IndexFunc(p.assets, func(a Asset) bool { return a.ID == asset.ID }); i >= 0 {
		p.assets[i] = asset
		return
	}
	p.assets = append(p.assets, asset)
}

func intervalSeconds(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func (p *preparer) fetch(ctx context.Context, asset *Asset, address string, headers http.Header, proxy string, interval int, force bool, fallback []byte) ([]byte, error) {
	if p.batch == nil {
		return nil, errors.New("resource download unavailable")
	}
	if interval <= 0 {
		interval = 3600
	}
	key := asset.ID
	if proxy != "" && proxy != "DIRECT" {
		key += "/" + resource.Hash([]byte(proxy))
	}
	old := p.batch.Previous[key]
	force = force || p.options.RefreshAsset == asset.ID
	same := old.Request == subscription.RequestDigest(address, headers)
	retain := p.options.RefreshAsset != "" || !asset.Automatic && same
	if !force && (same || old.Fallback) && retain && old.Hash != "" {
		if data, err := p.fetcher.Blobs.Read(old.Hash); err == nil {
			p.batch.Entries[key] = old
			setAssetTimes(asset, old)
			return data, nil
		}
	}
	client := p.client
	if proxy != "" && proxy != "DIRECT" {
		if p.options.ClientFor == nil {
			return nil, errors.New("declared provider proxy is unavailable")
		}
		var err error
		client, err = p.options.ClientFor(proxy)
		if err != nil {
			return nil, errors.New("declared provider proxy is unavailable")
		}
		defer client.CloseIdleConnections()
	}
	p.fetcher.Client, p.batch.Force = client, force
	data, err := p.batch.FetchFallback(ctx, key, asset.Kind, asset.Name, address, headers, interval, fallback)
	if err != nil {
		return nil, err
	}
	setAssetTimes(asset, p.batch.Entries[key])
	return data, nil
}

func setAssetTimes(asset *Asset, entry subscription.Entry) {
	if !entry.Checked.IsZero() {
		asset.UpdatedMS = entry.Checked.UnixMilli()
	}
	if !entry.Next.IsZero() {
		asset.NextMS = entry.Next.UnixMilli()
	}
	asset.UsesFallback = entry.Fallback
}

func assetError(asset Asset, err error) error {
	return &ValidationError{fmt.Sprintf("Could not load %s", asset.Name), model.Diagnostics{{
		Severity: model.SeverityError, Code: "ios.resource", Path: asset.ID, Message: err.Error(),
	}}}
}

func writeAtomic(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".reka-profile-*")
	if err != nil {
		return errors.New("could not open profile storage")
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || os.Rename(file.Name(), path) != nil {
		return errors.New("could not save profile snapshot")
	}
	return nil
}
