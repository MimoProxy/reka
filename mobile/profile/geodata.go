package profile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/rulesdata"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/subscription"
)

const (
	geodataURL       = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"
	geodataSRSURL    = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/"
	geodataStateFile = "geodata-state.json"
	geodataInterval  = 7 * 24 * time.Hour
	// geodataRefreshWindow lets the other profiles of one refresh reuse a download.
	geodataRefreshWindow = time.Minute
)

var (
	geodataKinds   = [...]string{"geoip", "geosite", "asn"}
	geodataStateMu sync.Mutex
)

func (p *preparer) prepareGeodata(ctx context.Context, selectors geodataSelectors, declared []model.GeoDatabase, resources map[string][]byte) (map[string][]byte, error) {
	definitions := make(map[string]model.GeoDatabase, len(declared))
	for _, db := range declared {
		kind, code, perCode := strings.Cut(db.ID, ":")
		if len(selectors[kind]) == 0 || perCode && !slices.Contains(selectors[kind], code) {
			continue
		}
		if _, exists := definitions[db.ID]; exists {
			return nil, assetError(Asset{ID: "geodata/" + db.ID, Name: db.ID}, errors.New("duplicate database kind"))
		}
		definitions[db.ID] = db
	}
	locked := make(map[string][]byte)
	pin := func(id string, data []byte) {
		locked[id] = data
		resources[resource.Hash(data)] = data
	}
	for _, kind := range geodataKinds {
		codes := selectors[kind]
		if len(codes) == 0 {
			continue
		}
		slices.Sort(codes)
		asset := Asset{ID: "geodata/" + kind, Name: kind, Kind: "geodata", Codes: slices.Compact(codes)}
		var remaining []string
		for _, code := range asset.Codes {
			ref := kind + ":" + code
			db, ok := definitions[ref]
			if !ok {
				remaining = append(remaining, code)
				continue
			}
			data, err := p.prepareGeodataCode(ctx, &asset, code, db)
			if err != nil {
				return nil, err
			}
			pin(ref, data)
		}
		if len(remaining) > 0 {
			if err := p.prepareGeodataSource(ctx, &asset, remaining, definitions[kind], pin); err != nil {
				return nil, err
			}
		}
		p.addAsset(asset)
	}
	return locked, nil
}

func pinGeodata(document map[string]any, geodata map[string][]byte) {
	delete(document, "geodata")
	if len(geodata) == 0 {
		return
	}
	definitions := make([]map[string]string, 0, len(geodata))
	for _, id := range slices.Sorted(maps.Keys(geodata)) {
		data := geodata[id]
		format := "dat"
		if strings.Contains(id, ":") {
			format = "srs"
		}
		definitions = append(definitions, map[string]string{"id": id, "format": format, "hash": resource.Hash(data)})
	}
	document["geodata"] = definitions
}

type geodataSource struct {
	hash, address, legacyFile string
	interval                  int
	automatic, protected      bool
}

func (p *preparer) geodataSource(kind string, db model.GeoDatabase) (geodataSource, error) {
	if db.Download == nil && db.Hash != "" {
		return geodataSource{hash: db.Hash}, nil
	}

	file := kind + ".dat"
	if kind == "asn" {
		file = "GeoLite2-ASN.mmdb"
	}
	address := p.options.GeodataSources[kind]
	if address == "" {
		address = geodataURL + file
		if kind != "asn" {
			address = geodataSRSURL + kind + "/{code}.srs"
		}
	}
	source := geodataSource{address: address, interval: int(geodataInterval / time.Second), automatic: true}
	if download := db.Download; download != nil {
		source.address, source.automatic = download.URL, download.Automatic
		if download.Interval != 0 {
			source.interval = download.Interval
		}
		if source.interval < 300 || source.interval > int(geodataInterval/time.Second) {
			return geodataSource{}, errors.New("resource update interval must be 300–604800 seconds")
		}
		if name, ref := secret.ParseRef(source.address); ref {
			source.protected = true
			if p.options.Secrets == nil || secret.ValidName(name) != nil {
				return geodataSource{}, errors.New("resource credential unavailable")
			}
			var err error
			source.address, err = p.options.Secrets.Get(name)
			if err != nil {
				return geodataSource{}, errors.New("resource credential unavailable")
			}
		}
	}
	// The app's URL parser can percent-encode braces in a saved template.
	source.address = strings.ReplaceAll(source.address, "%7Bcode%7D", "{code}")
	if source.address == geodataURL+file {
		source.legacyFile = file
	}
	return source, nil
}

func (p *preparer) prepareGeodataSource(ctx context.Context, asset *Asset, codes []string, db model.GeoDatabase, pin func(string, []byte)) error {
	source, err := p.geodataSource(asset.Name, db)
	if err != nil {
		return assetError(*asset, err)
	}
	if strings.Contains(source.address, "{code}") {
		if asset.Name == "asn" {
			return assetError(*asset, errors.New("ASN requires a DAT or MMDB database"))
		}
		byFile := make(map[string][]byte)
		for _, code := range codes {
			file := geodataFileCode(asset.Name, code)
			data := byFile[file]
			if data == nil {
				data, err = p.loadGeodataCode(ctx, asset, code, source)
				if err != nil {
					return err
				}
				byFile[file] = data
			}
			pin(asset.Name+":"+code, data)
		}
		return nil
	}
	part := Asset{ID: asset.ID, Name: asset.Name, Kind: asset.Kind, Codes: codes}
	full, err := p.loadGeodata(ctx, &part, asset.Name, "", source)
	if err != nil {
		return assetError(part, err)
	}
	data, err := rulesdata.SubsetDatabase(asset.Name, full, codes)
	if err != nil {
		return assetError(part, err)
	}
	part.Size = int64(len(full))
	mergeGeodataAsset(asset, part)
	pin(asset.Name, data)
	return nil
}

func (p *preparer) prepareGeodataCode(ctx context.Context, asset *Asset, code string, db model.GeoDatabase) ([]byte, error) {
	source, err := p.geodataSource(asset.Name, db)
	if err != nil {
		return nil, assetError(*asset, err)
	}
	return p.loadGeodataCode(ctx, asset, code, source)
}

func geodataFileCode(kind, code string) string {
	if kind == "geoip" && code == "lan" {
		return "private"
	}
	return code
}

func (p *preparer) loadGeodataCode(ctx context.Context, group *Asset, code string, source geodataSource) ([]byte, error) {
	part := Asset{ID: group.ID + "/" + geodataFileCode(group.Name, code), Name: group.Name + ":" + code, Kind: group.Kind}
	data, err := p.loadGeodata(ctx, &part, group.Name, code, source)
	if err != nil {
		return nil, assetError(part, err)
	}
	part.Size = int64(len(data))
	mergeGeodataAsset(group, part)
	return data, nil
}

func mergeGeodataAsset(group *Asset, part Asset) {
	if group.Source == "" {
		group.Source, group.URL = part.Source, part.URL
	}
	if group.URL != part.URL {
		group.URL = ""
	}
	if part.Shared {
		group.Source = part.Source
	}
	group.Shared = group.Shared || part.Shared
	group.Automatic = group.Automatic || part.Automatic
	group.UsesFallback = group.UsesFallback || part.UsesFallback
	group.Size += part.Size
	if part.UpdatedMS != 0 && (group.UpdatedMS == 0 || part.UpdatedMS < group.UpdatedMS) {
		group.UpdatedMS = part.UpdatedMS
	}
	if part.NextMS != 0 && (group.NextMS == 0 || part.NextMS < group.NextMS) {
		group.NextMS = part.NextMS
	}
}

func (p *preparer) loadGeodata(ctx context.Context, asset *Asset, kind, code string, source geodataSource) ([]byte, error) {
	if source.hash != "" {
		asset.Source = "file"
		return p.readLockedResource(source.hash)
	}
	address := strings.ReplaceAll(source.address, "{code}", url.PathEscape(geodataFileCode(kind, code)))
	if !subscription.ValidURL(address) {
		return nil, errors.New("invalid geodata source URL")
	}
	parsed, _ := url.Parse(address)
	if !source.protected && parsed.User == nil && parsed.RawQuery == "" {
		asset.URL = source.address
	}
	asset.Source, asset.Shared, asset.Automatic = "http", true, source.automatic
	return p.loadSharedGeodata(ctx, asset, kind, address, source.interval, source.legacyFile, code != "")
}

func (p *preparer) loadSharedGeodata(ctx context.Context, asset *Asset, kind, address string, interval int, legacyFile string, perCode bool) ([]byte, error) {
	if p.fetcher == nil || p.batch == nil {
		return nil, errors.New("resource download unavailable")
	}
	geodataStateMu.Lock()
	defer geodataStateMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	path := filepath.Join(p.cache, geodataStateFile)
	state, err := readGeodataState(path)
	if err != nil {
		return nil, err
	}
	request := subscription.RequestDigest(address, nil)
	key := asset.ID + "/" + request
	entry, exists := state[key]
	if !exists {
		old := p.batch.Previous[asset.ID]
		// A legacy entry without a request digest was adopted from a raw file.
		if old.Request == request || old.Request == "" && legacyFile != "" {
			entry = old
		}
	}
	var cached []byte
	if entry.Hash != "" {
		cached, _ = p.fetcher.Blobs.Read(entry.Hash)
	}
	if !exists && len(cached) == 0 && legacyFile != "" {
		cached, entry = p.readLegacyGeodata(legacyFile)
	}
	entry.Request = request

	data := cached
	changed := !exists
	// A refresh shared by several profiles downloads once. The rest of the
	// batch adopts the database checked moments earlier.
	refresh := p.options.RefreshAsset == asset.ID || perCode && p.options.RefreshAsset == "geodata/"+kind
	force := refresh && !(exists && time.Since(entry.Checked) < geodataRefreshWindow)
	if len(cached) == 0 || force || exists && !time.Now().Before(entry.Next) {
		fetcher := *p.fetcher
		// Databases take far longer to download than a profile, especially
		// through a proxy. The preparation deadline bounds them instead of the
		// client's whole-request limit.
		client := *p.client
		client.Timeout = 0
		fetcher.Client = &client
		previous := entry
		if len(cached) == 0 {
			previous.Hash = ""
		}
		fetcher.ValidateBody = func(data []byte) error {
			format := rulesdata.GeodataFormat(kind, data)
			if perCode {
				format = "srs"
			}
			if err := rulesdata.ValidateDatabase(kind, format, data); err != nil {
				return err
			}
			if previous.Hash == "" && resource.ValidHash(entry.Hash) && resource.Hash(data) == entry.Hash {
				return p.repairGeodataBlob(entry.Hash, data)
			}
			return nil
		}
		// The shared Next controls expiration. Keep HTTP validators when rechecking.
		batch := fetcher.Batch(map[string]subscription.Entry{key: previous}, true)
		fresh, err := batch.Fetch(ctx, key, asset.Kind, asset.Name, address, nil, interval)
		if err == nil {
			data, entry, changed = fresh, batch.Entries[key], true
		} else if ctx.Err() != nil {
			return nil, ctx.Err()
		} else if perCode && subscription.Code(err) == "http_status_404" {
			return nil, fmt.Errorf("%s SRS file not found (HTTP 404)", asset.Name)
		} else if len(cached) == 0 {
			return nil, err
		}
	}
	if changed {
		state[key] = entry
		raw, err := json.Marshal(state)
		if err != nil || writeAtomic(path, raw) != nil {
			return nil, errors.New("could not save shared geodata state")
		}
	}
	setAssetTimes(asset, entry)
	return data, nil
}

// A store put cannot replace a corrupt blob. A verified download of the same
// digest can repair it without changing any references to that digest.
func (p *preparer) repairGeodataBlob(hash string, data []byte) error {
	root, err := os.OpenRoot(filepath.Clean(p.cache))
	if err != nil {
		return errors.New("could not open geodata cache")
	}
	defer root.Close()
	dir := filepath.Join("resources", "sha256")
	path := filepath.Join(dir, hash)
	if info, err := root.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return nil // Missing blobs are created by the store.
	}
	temp := filepath.Join(dir, ".reka-geodata-"+rand.Text())
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("could not repair cached geodata")
	}
	defer root.Remove(temp)
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || root.Rename(temp, path) != nil {
		return errors.New("could not repair cached geodata")
	}
	return nil
}

func readGeodataState(path string) (map[string]subscription.Entry, error) {
	var state map[string]subscription.Entry
	raw, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(raw, &state) != nil {
			state = nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("could not read shared geodata state")
	}
	if state == nil {
		state = make(map[string]subscription.Entry)
	}
	return state, nil
}

// Older installations kept a raw copy of each default database.
func (p *preparer) readLegacyGeodata(file string) ([]byte, subscription.Entry) {
	path := filepath.Join(p.cache, file)
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Size() <= maxAssetBytes && time.Since(info.ModTime()) < geodataInterval {
		if data, err := os.ReadFile(path); err == nil && len(data) != 0 && len(data) <= maxAssetBytes {
			if hash, err := p.fetcher.Blobs.Put(data); err == nil {
				return data, subscription.Entry{Hash: hash, Checked: info.ModTime(), Next: info.ModTime().Add(geodataInterval)}
			}
		}
	}
	return nil, subscription.Entry{}
}

type geodataSelectors map[string][]string

var geodataSections = []string{"rules", "sub-rules", "rule-sets", "sniff", "dns"}

func (s geodataSelectors) add(kind, code string) {
	code = strings.ToLower(strings.TrimSpace(code))
	switch kind {
	case "geoip", "geosite":
	case "asn", "ip-asn":
		number, err := strconv.ParseUint(strings.TrimPrefix(code, "as"), 10, 32)
		if err != nil || number == 0 {
			return
		}
		kind = "asn"
		code = strconv.FormatUint(number, 10)
	default:
		return
	}
	if code != "" {
		s[kind] = append(s[kind], code)
	}
}

func (s geodataSelectors) addReference(value string) {
	value = strings.TrimPrefix(value, "rule-set:")
	if kind, code, ok := strings.Cut(value, ":"); ok {
		s.add(kind, code)
	}
}

func (s geodataSelectors) collect(key string, value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			s.collect(key, child)
		}
	case []any:
		for _, child := range v {
			s.collect(key, child)
		}
	case string:
		if strings.Contains(v, ":") {
			s.addReference(v)
		} else if key != "geoip" || !strings.EqualFold(strings.TrimSpace(v), "lan") {
			s.add(key, v)
		}
	case int, int64, uint64, json.Number:
		if key == "ip-asn" {
			s.add(key, fmt.Sprint(v))
		}
	case float64:
		if key == "ip-asn" {
			s.add(key, strconv.FormatFloat(v, 'f', -1, 64))
		}
	}
}

func (s geodataSelectors) collectOverlay(patches []model.Op) {
	for _, patch := range patches {
		path, err := model.SplitPath(patch.Path)
		if err != nil || len(path) == 0 || !slices.Contains(geodataSections, path[0]) {
			continue
		}
		key := path[len(path)-1]
		if strings.HasPrefix(key, "#") && len(path) > 1 {
			key = path[len(path)-2]
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(patch.Value))
		decoder.UseNumber()
		if decoder.Decode(&value) == nil {
			s.collect(key, value)
		}
	}
}

// collectOverlayRuleSets reads the geodata references in the contents of
// classical rule sets that the overlay adds or replaces.
func (s geodataSelectors) collectOverlayRuleSets(patches []model.Op, resources map[string][]byte) {
	for _, patch := range patches {
		path, err := model.SplitPath(patch.Path)
		if err != nil || len(path) == 0 || path[0] != "rule-sets" ||
			!(patch.Op == "insert" && len(path) == 1 || patch.Op == "set" && len(path) == 2) {
			continue
		}
		var definition map[string]any
		if json.Unmarshal(patch.Value, &definition) != nil {
			continue
		}
		if behavior, _ := definition["behavior"].(string); behavior == "classical" {
			s.collectClassical(definition, resources)
		}
	}
}

// merge adds the selectors of other and reports whether any was new.
func (s geodataSelectors) merge(other geodataSelectors) bool {
	added := false
	for kind, codes := range other {
		for _, code := range codes {
			if !slices.Contains(s[kind], code) {
				s[kind] = append(s[kind], code)
				added = true
			}
		}
	}
	return added
}

func (s geodataSelectors) collectDocument(document map[string]any, resources map[string][]byte) {
	for _, field := range geodataSections {
		if field != "dns" {
			s.collect(field, document[field])
		}
	}
	dnsSelectors := make(geodataSelectors)
	dnsSelectors.collect("dns", document["dns"])
	// An enabled DNS fallback filter can select a country without a prefix.
	dns, _ := document["dns"].(map[string]any)
	fallback, _ := dns["fallback"].([]any)
	filter, _ := dns["fallback-filter"].(map[string]any)
	if enabled, _ := filter["geoip"].(bool); enabled && len(fallback) > 0 {
		if id, _ := filter["geoip-set"].(string); id == "" {
			code, _ := filter["geoip-code"].(string)
			if code == "" {
				code = "cn"
			}
			dnsSelectors.add("geoip", code)
		}
	}
	definitions, _ := document["rule-sets"].([]any)
	for _, definition := range definitions {
		def, _ := definition.(map[string]any)
		behavior, _ := def["behavior"].(string)
		code, _ := def["code"].(string)
		if len(dnsSelectors[behavior]) > 0 {
			// The DNS compiler can bind a selector directly to a named rule set.
			dnsSelectors[behavior] = slices.DeleteFunc(dnsSelectors[behavior], func(selector string) bool {
				return strings.EqualFold(selector, code)
			})
		}
		if behavior == "classical" {
			s.collectClassical(def, resources)
		}
	}
	for kind, codes := range dnsSelectors {
		s[kind] = append(s[kind], codes...)
	}
}

func (s geodataSelectors) collectClassical(def map[string]any, resources map[string][]byte) {
	format, _ := def["format"].(string)
	if format == "srs" {
		return
	}
	hash, _ := def["hash"].(string)
	specs, err := rulesdata.Decode("classical", format, "", resources[hash])
	if err != nil {
		return // The compiler reports an invalid rule resource.
	}
	references, _ := def["references"].([]any)
	aliases := make(map[string]bool, len(references))
	for _, value := range references {
		ref, _ := value.(map[string]any)
		if name, _ := ref["name"].(string); name != "" {
			aliases[name] = true
		}
	}
	var collect func(router.RuleSpec)
	collect = func(spec router.RuleSpec) {
		if spec.Kind == router.KindRuleSet && len(spec.Values) == 1 && !aliases[spec.Values[0]] {
			s.addReference(spec.Values[0])
		}
		for _, child := range spec.Children {
			collect(child)
		}
	}
	for _, spec := range specs {
		collect(spec)
	}
}
