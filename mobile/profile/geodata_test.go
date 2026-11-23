package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/rulesdata"
	"github.com/MimoProxy/reka/internal/subscription"
)

const geositeProfile = "schema-version: 1\nrules: [{match: {geosite: test}, outbound: reject}]\n"
const geodataFixtureHost = "http://geodata.test"

type geodataFixtureHTTP struct {
	mu       sync.Mutex
	bodies   map[string][]byte
	requests map[string]int
}

func fixtureGeodata(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../testdata/rules", file))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newGeodataFixture(t *testing.T) (*geodataFixtureHTTP, PrepareOptions) {
	t.Helper()
	options := PrepareOptions{GeodataSources: map[string]string{}}
	server := &geodataFixtureHTTP{bodies: map[string][]byte{}, requests: map[string]int{}}
	for kind, file := range map[string]string{"geosite": "geosite.dat", "geoip": "geoip.dat", "asn": "asn.mmdb"} {
		server.bodies["/"+file] = fixtureGeodata(t, file)
		options.GeodataSources[kind] = geodataFixtureHost + "/" + file
	}
	return server, options
}

// Record HTTP requests in process so these fixtures can also run without sockets.
func (s *geodataFixtureHTTP) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[req.URL.Path]++
	w := httptest.NewRecorder()
	if data := s.bodies[req.URL.Path]; data != nil {
		_, _ = w.Write(data)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	return w.Result(), nil
}

func prepareGeodataFixture(t *testing.T, raw, cache string, options PrepareOptions, server *geodataFixtureHTTP) (*Bundle, error) {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "profile.yaml"), filepath.Join(dir, "bundle.json")
	writeFixtureFile(t, input, []byte(raw))
	if err := prepareFile(t.Context(), input, output, cache, options, &http.Client{Transport: server}); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	return Decode(data)
}

func mustPrepareGeodata(t *testing.T, raw, cache string, options PrepareOptions, server *geodataFixtureHTTP) *Bundle {
	t.Helper()
	bundle, err := prepareGeodataFixture(t, raw, cache, options, server)
	if err != nil {
		var validation *ValidationError
		if errors.As(err, &validation) {
			t.Fatalf("%s: %v", validation.Message, validation.Diagnostics)
		}
		t.Fatal(err)
	}
	return bundle
}

func writeFixtureFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeFixtureState(t *testing.T, path string, state map[string]subscription.Entry) {
	t.Helper()
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, path, raw)
}

// ageSharedState moves every shared check back, outside one refresh.
func ageSharedState(t *testing.T, cache string, age time.Duration) {
	t.Helper()
	state := sharedState(t, cache)
	for key, entry := range state {
		entry.Checked = entry.Checked.Add(-age)
		state[key] = entry
	}
	writeFixtureState(t, filepath.Join(cache, geodataStateFile), state)
}

func sharedState(t *testing.T, cache string) map[string]subscription.Entry {
	t.Helper()
	state, err := readGeodataState(filepath.Join(cache, geodataStateFile))
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestPrepareSharesAndRefreshesGeodataAcrossProfiles(t *testing.T) {
	server, first := newGeodataFixture(t)
	cache, states := t.TempDir(), t.TempDir()
	first.OutputState = filepath.Join(states, "first.json")
	second := first
	second.OutputState = filepath.Join(states, "second.json")
	before := mustPrepareGeodata(t, geositeProfile, cache, first, server)
	reused := mustPrepareGeodata(t, geositeProfile, cache, second, server)
	if server.requests["/geosite.dat"] != 1 || !maps.EqualFunc(before.Resources, reused.Resources, bytes.Equal) {
		t.Fatal("separate profiles did not reuse the shared download")
	}
	asset := reused.Summary.Resources[0]
	if !asset.Shared || !asset.Automatic || asset.URL != first.GeodataSources["geosite"] ||
		asset.NextMS-asset.UpdatedMS != geodataInterval.Milliseconds() {
		t.Fatalf("unexpected shared asset: %+v", asset)
	}
	for _, path := range []string{first.OutputState, second.OutputState} {
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != "{}" {
			t.Fatalf("profile state contains shared assets: %s, %v", raw, err)
		}
	}

	server.bodies["/geosite.dat"] = bytes.ReplaceAll(server.bodies["/geosite.dat"], []byte("suffix.test"), []byte("second.test"))
	ageSharedState(t, cache, 2*geodataRefreshWindow)
	first.PreviousState, first.RefreshAsset = first.OutputState, "geodata/geosite"
	after := mustPrepareGeodata(t, geositeProfile, cache, first, server)
	// The other profile of the same refresh adopts that download.
	second.PreviousState, second.RefreshAsset = second.OutputState, "geodata/geosite"
	reused = mustPrepareGeodata(t, geositeProfile, cache, second, server)
	if server.requests["/geosite.dat"] != 2 || maps.EqualFunc(before.Resources, after.Resources, bytes.Equal) ||
		!maps.EqualFunc(after.Resources, reused.Resources, bytes.Equal) {
		t.Fatal("refresh was not published to the other profile")
	}
	assertRoute(t, reused, "sub.second.test", "reject")
	assertRoute(t, reused, "sub.suffix.test", "direct")
}

func TestPrepareGeodataUsesStaleDataOnFetchFailure(t *testing.T) {
	server, options := newGeodataFixture(t)
	cache := t.TempDir()
	before := mustPrepareGeodata(t, geositeProfile, cache, options, server)
	state := sharedState(t, cache)
	for key, entry := range state {
		entry.Next = time.Now().UTC().Add(-time.Hour)
		state[key] = entry
	}
	writeFixtureState(t, filepath.Join(cache, geodataStateFile), state)
	server.bodies["/geosite.dat"] = nil
	stale := mustPrepareGeodata(t, geositeProfile, cache, options, server)
	if server.requests["/geosite.dat"] != 2 || !maps.EqualFunc(before.Resources, stale.Resources, bytes.Equal) {
		t.Fatal("expired database was not reused after a failed request")
	}
	if got := stale.Summary.Resources[0]; got.UpdatedMS != before.Summary.Resources[0].UpdatedMS ||
		got.NextMS >= got.UpdatedMS {
		t.Fatalf("failed fetch changed the schedule: %+v", got)
	}
	_, err := prepareGeodataFixture(t, geositeProfile, t.TempDir(), options, server)
	var validation *ValidationError
	if !errors.As(err, &validation) || len(validation.Diagnostics) != 1 ||
		validation.Diagnostics[0].Path != "geodata/geosite" || validation.Diagnostics[0].Message != "http_status_503" {
		t.Fatalf("expected missing geodata to be reported as an asset error: %v", err)
	}

	server.bodies["/geosite.dat"] = []byte("<html>service unavailable</html>")
	stale = mustPrepareGeodata(t, geositeProfile, cache, options, server)
	if !maps.EqualFunc(before.Resources, stale.Resources, bytes.Equal) || !maps.Equal(state, sharedState(t, cache)) {
		t.Fatal("an invalid HTTP body replaced the last good database")
	}
}

func TestPrepareRepairsUnreadableSharedGeodata(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		name := "missing blob"
		if corrupt {
			name = "corrupt blob"
		}
		t.Run(name, func(t *testing.T) {
			server, options := newGeodataFixture(t)
			cache := t.TempDir()
			before := mustPrepareGeodata(t, geositeProfile, cache, options, server)
			full := server.bodies["/geosite.dat"]
			hash := resource.Hash(full)
			blob := filepath.Join(cache, "resources", "sha256", hash)
			if corrupt {
				writeFixtureFile(t, blob, []byte("invalid cache content"))
			} else if err := os.Remove(blob); err != nil {
				t.Fatal(err)
			}
			after := mustPrepareGeodata(t, geositeProfile, cache, options, server)
			if server.requests["/geosite.dat"] != 2 || !maps.EqualFunc(before.Resources, after.Resources, bytes.Equal) {
				t.Fatal("unreadable cached data was not downloaded again")
			}
			mustPrepareGeodata(t, geositeProfile, cache, options, server)
			if server.requests["/geosite.dat"] != 2 {
				t.Fatal("repaired data was not reused")
			}
		})
	}
}

func TestPrepareNativeGeodataWithoutDeclarations(t *testing.T) {
	server, options := newGeodataFixture(t)
	site := server.bodies["/geosite.dat"]
	// The GeoSite fixture has one category. Include an unselected category.
	server.bodies["/geosite.dat"] = append(bytes.Clone(site), bytes.Replace(site, []byte("TEST"), []byte("MORE"), 1)...)
	const raw = `
schema-version: 1
outbounds:
  - {id: country, type: direct}
  - {id: autonomous-system, type: direct}
rule-sets:
  - id: sites
    entries: [{geosite: [TEST, test, test@cn]}]
sub-rules:
  - id: countries
    rules:
      - {match: {geoip: [LAN, CN, cn]}, outbound: country}
rules:
  - {match: {rule-set: sites}, outbound: reject}
  - {match: {ip-asn: [AS64512, 64512]}, outbound: autonomous-system}
  - {match: {all: true}, call: countries}
`
	bundle := mustPrepareGeodata(t, raw, t.TempDir(), options, server)
	assertRoute(t, bundle, "x.suffix.test", "reject")
	assertIPRoutes(t, bundle, map[string]string{
		"192.0.2.1": "country", "192.168.0.1": "country", "198.51.100.1": "autonomous-system", "203.0.113.1": "direct",
	})

	locked := lockedGeodata(t, bundle)
	wantCodes := map[string][]string{"geoip": {"cn"}, "geosite": {"test", "test@cn"}, "asn": {"64512"}}
	if len(locked) != 3 || bundle.Precompiled == nil || len(bundle.Precompiled.Sets) != 2 || len(bundle.Resources) != 5 {
		t.Fatalf("unexpected geodata resources: %+v", bundle.Summary.Resources)
	}
	for _, asset := range bundle.Summary.Resources {
		if asset.Kind != "geodata" {
			continue
		}
		path := strings.TrimPrefix(asset.URL, geodataFixtureHost)
		full := server.bodies[path]
		data := locked[asset.Name]
		if asset.ID != "geodata/"+asset.Name || asset.Size != int64(len(full)) || len(data)*4 >= len(full)*3 ||
			!slices.Equal(asset.Codes, wantCodes[asset.Name]) || server.requests[path] != 1 {
			t.Fatalf("unexpected slice metadata or size: %+v (slice has %d bytes)", asset, len(data))
		}
	}
	for kind, excluded := range map[string]string{"geoip": "reverse", "geosite": "more", "asn": "13335"} {
		if _, err := rulesdata.Decode(kind, "dat", excluded, locked[kind]); err == nil {
			t.Fatalf("unselected %s code %q was retained", kind, excluded)
		}
	}
}

func TestPrepareLANWorksWithoutGeodata(t *testing.T) {
	server, options := newGeodataFixture(t)
	raw := "schema-version: 1\nrules: [{match: {geoip: LAN}, outbound: reject}]\n"
	bundle := mustPrepareGeodata(t, raw, t.TempDir(), options, server)
	if len(server.requests) != 0 || len(bundle.Resources) != 0 {
		t.Fatal("built-in LAN requested a database")
	}
	assertIPRoutes(t, bundle, map[string]string{"192.168.0.1": "reject", "198.51.100.1": "direct"})
}

func TestPrepareNativeGeodataDeclarationOverridesSharedSource(t *testing.T) {
	server, options := newGeodataFixture(t)
	cache := t.TempDir()
	defaultBundle := mustPrepareGeodata(t, geositeProfile, cache, options, server)
	server.bodies["/custom"] = bytes.ReplaceAll(server.bodies["/geosite.dat"], []byte("suffix.test"), []byte("custom.test"))
	raw := fmt.Sprintf(`
schema-version: 1
geodata:
  - id: geosite
    format: dat
    download: {url: %q, automatic: true, interval: 300}
  - id: asn
    format: mmdb
    download: {url: %q}
rules: [{match: {geosite: test}, outbound: reject}]
`, geodataFixtureHost+"/custom?token=fixture-credential", options.GeodataSources["asn"])
	custom := mustPrepareGeodata(t, raw, cache, options, server)
	if maps.EqualFunc(defaultBundle.Resources, custom.Resources, bytes.Equal) || server.requests["/custom"] != 1 ||
		server.requests["/asn.mmdb"] != 0 || len(sharedState(t, cache)) != 2 || len(lockedGeodata(t, custom)) != 1 {
		t.Fatal("custom source did not stay separate or unused geodata was materialized")
	}
	asset := custom.Summary.Resources[0]
	if !asset.Shared || asset.URL != "" || asset.NextMS-asset.UpdatedMS != 300_000 {
		t.Fatalf("unexpected custom source metadata: %+v", asset)
	}
	state, err := os.ReadFile(filepath.Join(cache, geodataStateFile))
	if err != nil || bytes.Contains(state, []byte("fixture-credential")) || bytes.Contains(custom.Profile, []byte("fixture-credential")) {
		t.Fatal("shared state or snapshot exposed the source credential", err)
	}
	assertRoute(t, custom, "sub.custom.test", "reject")
}

func TestPrepareNativeGeodataReadsLockedCountryMMDB(t *testing.T) {
	server, options := newGeodataFixture(t)
	cache, files := t.TempDir(), t.TempDir()
	full := fixtureGeodata(t, "country.mmdb")
	hash := resource.Hash(full)
	dir := filepath.Join(files, "resources", "sha256")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(dir, hash), full)
	options.ProviderDirectory = files
	raw := fmt.Sprintf("schema-version: 1\ngeodata: [{id: geoip, format: mmdb, hash: %q}]\nrules: [{match: {geoip: cn}, outbound: reject}]\n", hash)
	bundle := mustPrepareGeodata(t, raw, cache, options, server)
	slice := lockedGeodata(t, bundle)["geoip"]
	asset := bundle.Summary.Resources[0]
	if len(slice) == 0 || len(slice) >= len(full)/4 || asset.Shared || asset.Source != "file" || asset.URL != "" ||
		len(server.requests) > 0 || len(sharedState(t, cache)) > 0 {
		t.Fatalf("unexpected hash-pinned resource: %+v", asset)
	}
	assertIPRoutes(t, bundle, map[string]string{"192.0.2.1": "reject", "2001:db8::1": "reject", "198.51.100.1": "direct"})
}

func TestPrepareCollectsGeodataFromDNSAndOverlay(t *testing.T) {
	server, options := newGeodataFixture(t)
	const raw = `
schema-version: 1
dns:
  nameserver: [system]
  fake-ip-filter: ["geoip:cn"]
rules:
  - {id: final, match: {all: true}, outbound: direct}
`
	options.Overlay = json.RawMessage(`{"schema-version":1,"patches":[
		{"op":"insert","path":"/rules","before":"final","value":{"id":"site","match":{"geosite":"test"},"outbound":"reject"}},
		{"op":"set","path":"/rules/site/match/geosite","value":"test@cn"}
	]}`)
	bundle := mustPrepareGeodata(t, raw, t.TempDir(), options, server)
	checkPatchStatuses(t, bundle.Summary.Patches, "", "")
	if bundle.Precompiled == nil || len(bundle.Precompiled.Sets) != 1 {
		t.Fatal("expected a precompiled selector for the applied overlay")
	}
	assertRoute(t, bundle, "x.suffix.test", "reject")
	assertRoute(t, bundle, "exact.test", "direct")
	if server.requests["/geosite.dat"] != 1 || server.requests["/geoip.dat"] != 1 {
		t.Fatalf("unexpected geodata requests: %v", server.requests)
	}
	if codes := bundle.Summary.Resources[1].Codes; !slices.Equal(codes, []string{"test", "test@cn"}) {
		t.Fatalf("overlay selectors are missing: %v", codes)
	}
}

func TestPrepareClashASNUsesCompactDAT(t *testing.T) {
	server, options := newGeodataFixture(t)
	const raw = "rules: ['IP-ASN,AS13335,REJECT', 'MATCH,DIRECT']\n"
	bundle := mustPrepareGeodata(t, raw, t.TempDir(), options, server)
	if bundle.Summary.Format != "clash" || len(bundle.Resources) != 1 || server.requests["/asn.mmdb"] != 1 {
		t.Fatalf("unexpected Clash ASN snapshot: %+v", bundle.Summary)
	}
	full := server.bodies["/asn.mmdb"]
	for _, data := range bundle.Resources {
		if len(data) >= len(full)/4 || rulesdata.GeodataFormat("asn", data) != "dat" {
			t.Fatalf("ASN snapshot contains %d bytes of %d", len(data), len(full))
		}
	}
	assertIPRoutes(t, bundle, map[string]string{"192.0.2.7": "reject", "2001:db8::1": "reject", "198.51.100.3": "direct"})
}

func TestPrepareMigratesLegacyGeodata(t *testing.T) {
	t.Run("profile state", func(t *testing.T) {
		server, options := newGeodataFixture(t)
		cache := t.TempDir()
		store, err := resource.Open(cache)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := store.Put(server.bodies["/geosite.dat"])
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Add(-time.Hour)
		old := subscription.Entry{
			Hash: hash, Request: subscription.RequestDigest(options.GeodataSources["geosite"], nil),
			Checked: now, Next: now.Add(geodataInterval), ETag: "legacy",
		}
		options.PreviousState = filepath.Join(t.TempDir(), "old.json")
		writeFixtureState(t, options.PreviousState, map[string]subscription.Entry{"geodata/geosite": old})
		bundle := mustPrepareGeodata(t, geositeProfile, cache, options, server)
		options.PreviousState = ""
		mustPrepareGeodata(t, geositeProfile, cache, options, server)
		entry := sharedState(t, cache)["geodata/geosite/"+old.Request]
		if len(server.requests) != 0 || entry != old || bundle.Summary.Resources[0].UpdatedMS != old.Checked.UnixMilli() {
			t.Fatalf("legacy state was not adopted: %+v, %v", entry, server.requests)
		}
	})

	t.Run("raw cache", func(t *testing.T) {
		server, options := newGeodataFixture(t)
		cache := t.TempDir()
		options.GeodataSources = nil
		writeFixtureFile(t, filepath.Join(cache, "geosite.dat"), server.bodies["/geosite.dat"])
		bundle := mustPrepareGeodata(t, geositeProfile, cache, options, server)
		if len(server.requests) != 0 || len(sharedState(t, cache)) != 1 || bundle.Summary.Resources[0].URL != geodataURL+"geosite.dat" {
			t.Fatal("legacy raw cache was not adopted")
		}
	})
}

func TestConcurrentPreparationsShareGeodata(t *testing.T) {
	server, options := newGeodataFixture(t)
	cache := t.TempDir()
	t.Run("profiles", func(t *testing.T) {
		for _, raw := range []string{geositeProfile, geositeProfile, "rules: ['IP-ASN,13335,REJECT']\n"} {
			t.Run("prepare", func(t *testing.T) {
				t.Parallel()
				mustPrepareGeodata(t, raw, cache, options, server)
			})
		}
	})
	if len(sharedState(t, cache)) != 2 || server.requests["/geosite.dat"] != 1 || server.requests["/asn.mmdb"] != 1 {
		t.Fatalf("concurrent preparations lost shared state or downloaded twice: %v", server.requests)
	}
}

func lockedGeodata(t *testing.T, bundle *Bundle) map[string][]byte {
	t.Helper()
	var profile struct {
		Geodata []struct {
			ID, Format, Hash string
			Download         json.RawMessage
		}
	}
	if err := json.Unmarshal(bundle.Profile, &profile); err != nil {
		t.Fatal(err)
	}
	locked := map[string][]byte{}
	for _, db := range profile.Geodata {
		data := bundle.Resources[db.Hash]
		if db.Format != "dat" || len(db.Download) != 0 || len(data) == 0 || db.Hash != resource.Hash(data) {
			t.Fatalf("invalid locked geodata: %+v", db)
		}
		locked[db.ID] = data
	}
	return locked
}

func assertIPRoutes(t *testing.T, bundle *Bundle, routes map[string]string) {
	t.Helper()
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	for ip, outbound := range routes {
		got := eff.Router.Route(t.Context(), router.Metadata{Addr: netip.MustParseAddr(ip)}, nil)
		if got.Outbound != outbound {
			t.Fatalf("%s routed to %q, want %q", ip, got.Outbound, outbound)
		}
	}
}

// slowBody delays the response body past the client's whole-request limit
// and fails like a network body when the request is cancelled first.
type slowBody struct {
	io.ReadCloser
	ctx   context.Context
	delay time.Duration
	err   error
	once  sync.Once
}

func (b *slowBody) Read(p []byte) (int, error) {
	b.once.Do(func() {
		select {
		case <-time.After(b.delay):
		case <-b.ctx.Done():
			b.err = b.ctx.Err()
		}
	})
	if b.err != nil {
		return 0, b.err
	}
	return b.ReadCloser.Read(p)
}

type slowTransport struct {
	server *geodataFixtureHTTP
	delay  time.Duration
}

func (t slowTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.server.RoundTrip(req)
	if err == nil {
		response.Body = &slowBody{ReadCloser: response.Body, ctx: req.Context(), delay: t.delay}
	}
	return response, err
}

func TestPrepareGeodataOutlastsClientTimeout(t *testing.T) {
	server, options := newGeodataFixture(t)
	dir := t.TempDir()
	input, output := filepath.Join(dir, "profile.yaml"), filepath.Join(dir, "bundle.json")
	writeFixtureFile(t, input, []byte(geositeProfile))
	client := &http.Client{Transport: slowTransport{server: server, delay: 200 * time.Millisecond}, Timeout: 50 * time.Millisecond}
	if err := prepareFile(t.Context(), input, output, t.TempDir(), options, client); err != nil {
		t.Fatalf("slow geodata download failed: %v", err)
	}
}

func TestPrepareFileResolvesSourceHostsThroughSystemResolver(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixtureGeodata(t, "geosite.dat"))
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "profile.yaml"), filepath.Join(dir, "bundle.json")
	writeFixtureFile(t, input, []byte(geositeProfile))
	options := PrepareOptions{GeodataSources: map[string]string{"geosite": "http://localhost:" + port + "/geosite.dat"}}
	if err := PrepareFileWithOptions(t.Context(), input, output, t.TempDir(), options); err != nil {
		t.Fatalf("named source host was not resolved: %v", err)
	}
}

func TestPrepareOverlayRuleSetContentsSelectGeodata(t *testing.T) {
	for name, raw := range map[string]string{
		"clash":  "rules: ['MATCH,DIRECT']\n",
		"native": "schema-version: 1\nrules: [{id: final, match: {all: true}, outbound: direct}]\n",
	} {
		t.Run(name, func(t *testing.T) {
			server, options := newGeodataFixture(t)
			server.bodies["/rules/service.yaml"] = []byte("payload:\n  - DOMAIN-SUFFIX,service.test\n  - IP-ASN,13335\n")
			options.Overlay = json.RawMessage(`{"schema-version":1,"patches":[
				{"op":"insert","path":"/rule-sets","value":{"id":"service","behavior":"classical","format":"yaml","download":{"url":"` + geodataFixtureHost + `/rules/service.yaml","interval":86400}}},
				{"op":"insert","path":"/rules","before":"#0","value":{"id":"service-rule","match":{"rule-set":"service"},"outbound":"reject"}}
			]}`)
			bundle := mustPrepareGeodata(t, raw, t.TempDir(), options, server)
			for _, status := range bundle.Summary.Patches {
				if !status.Applied {
					t.Fatalf("patch %d not applied: %s", status.Index, status.Reason)
				}
			}
			if server.requests["/asn.mmdb"] != 1 {
				t.Fatalf("ASN data was not loaded for the added rule set: %v", server.requests)
			}
			assertRoute(t, bundle, "api.service.test", "reject")
			assertIPRoutes(t, bundle, map[string]string{"192.0.2.7": "reject", "198.51.100.3": "direct"})
		})
	}
}
