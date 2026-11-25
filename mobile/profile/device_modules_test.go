package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
)

const deviceModuleBody = `#!name=Device filter
#!arguments=Host:a.example.com
[URL Rewrite]
^https://rewrite\.example\.com/reject$ - reject
[MITM]
hostname = %APPEND% {{{Host}}}
[Map Local]
^https://rewrite\.example\.com/data$ data-type=json data=https://module.example.com/data
`

const (
	deviceModuleDataURL = "https://module.example.com/data"
	deviceModuleData    = `{"locked":true}`
)

func acquireDeviceModuleFixture(t *testing.T) (model.Module, string) {
	t.Helper()
	def := model.Module{ID: "device-filter", URL: "https://module.example.com/filter.sgmodule"}
	var requests []string
	client := &http.Client{Transport: modulePrepareTransport(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.String())
		recorder := httptest.NewRecorder()
		switch req.URL.String() {
		case def.URL:
			fmt.Fprint(recorder, deviceModuleBody)
		case deviceModuleDataURL:
			fmt.Fprint(recorder, deviceModuleData)
		default:
			http.NotFound(recorder, req)
		}
		return recorder.Result(), nil
	})}
	path := filepath.Join(t.TempDir(), "module.json")
	result := AcquireModule(t.Context(), ModuleAcquireRequest{Module: def, OutputSnapshot: path}, ModuleAcquireOptions{Client: client})
	if result.Status != "updated" || !slices.Equal(requests, []string{def.URL, deviceModuleDataURL}) {
		t.Fatalf("acquire = %+v, requests = %v", result, requests)
	}
	return def, path
}

func TestPrepareClashWithDeviceModule(t *testing.T) {
	def, modulePath := acquireDeviceModuleFixture(t)
	bundle, path := prepareSourceFixture(t, clashSourceFixture, PrepareOptions{
		DeviceModules: []model.Module{def},
		Modules:       map[string]string{def.ID: modulePath},
		MITM:          &LocalMITM{Enabled: true},
	})
	if bundle.Summary.Format != "clash" || !slices.Equal(bundle.DeviceModules, []string{def.ID}) {
		t.Fatalf("format = %q, device modules = %v", bundle.Summary.Format, bundle.DeviceModules)
	}
	if modules := bundle.Summary.Modules; len(modules) != 1 || modules[0].ID != def.ID ||
		modules[0].Origin != "device" || !modules[0].Enabled || modules[0].Report == nil {
		t.Fatalf("device module summary = %+v", modules)
	}
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if report := eff.Modules[def.ID]; !report.CanApply || report.Rewrites.Imported != 2 {
		t.Fatalf("effective module report = %+v", report)
	}
	if !slices.Contains(eff.MITM.Hostnames, "a.example.com") {
		t.Fatalf("effective MITM hostnames = %v", eff.MITM.Hostnames)
	}
	reject := eff.HTTPRewrite.Request(httprewrite.Request{URL: "https://rewrite.example.com/reject"})
	if reject.Local == nil || reject.Local.StatusCode != http.StatusNotFound {
		t.Fatalf("device URL Rewrite did not reject: %+v", reject)
	}
	mapped := eff.HTTPRewrite.Request(httprewrite.Request{URL: "https://rewrite.example.com/data"})
	if mapped.Local == nil || string(mapped.Local.Body) != deviceModuleData {
		t.Fatalf("device Map Local did not serve pinned bytes: %+v", mapped)
	}
	sources, _, diagnostics := model.ParseSources(bundle.Sources)
	if diagnostics.HasErrors() || len(sources.Sources) != 1 || sources.Sources[0].Lock == nil {
		t.Fatalf("module source not locked: %s (%v)", bundle.Sources, diagnostics)
	}
	locked := sources.Sources[0].Lock.Resources
	dataHash := resource.Hash([]byte(deviceModuleData))
	if len(locked) != 1 || locked[0].Hash != dataHash || string(bundle.Resources[dataHash]) != deviceModuleData ||
		slices.Contains(bundle.OmittedResources, dataHash) {
		t.Fatalf("Map Local resource was not pinned in the bundle: %+v", locked)
	}
	if report, err := ModuleReport(t.Context(), path, def.ID, nil); err != nil || len(report.Lines) == 0 {
		t.Fatalf("full device module report = %+v, err %v", report, err)
	}

	const raw = `schema-version: 1
imports: [{source: s-test, outbounds: true, rewrites: true}]
`
	imported, _ := prepareSourceFixture(t, raw, PrepareOptions{Sources: map[string]string{"s-test": path}})
	importedEff, err := imported.Compile()
	if err != nil {
		t.Fatal(err)
	}
	importedSources, _, diagnostics := model.ParseSources(imported.Sources)
	if diagnostics.HasErrors() || len(importedSources.Sources) != 1 {
		t.Fatalf("unexpected imported sources: %s (%v)", imported.Sources, diagnostics)
	}
	source := importedSources.Sources[0]
	if len(source.Outbounds) != 2 || source.Module != nil || source.Lock != nil || len(importedEff.Modules) != 0 ||
		len(imported.DeviceModules) != 0 || len(imported.Summary.Modules) != 0 || len(importedEff.MITM.Hostnames) != 0 ||
		importedEff.HTTPRewrite != nil || len(imported.Resources) != 0 {
		t.Fatalf("import leaked device module state: sources %s, summary %+v", imported.Sources, imported.Summary)
	}
}

func TestPrepareProfileModuleTakesPrecedenceOverDeviceModule(t *testing.T) {
	def, modulePath := acquireDeviceModuleFixture(t)
	device := model.Module{ID: "device-rules", File: filepath.Join(t.TempDir(), "device.sgmodule")}
	const localBody = `[Rule]
DOMAIN,blocked.example.com,REJECT
[Map Local]
^https://local\.example\.com/data$ data-type=json data=` + deviceModuleDataURL + "\n"
	writeFixtureFile(t, device.File, []byte(localBody))
	devicePath := filepath.Join(t.TempDir(), "device.json")
	client := &http.Client{Transport: modulePrepareTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != deviceModuleDataURL {
			t.Errorf("unexpected module request %s", req.URL)
		}
		recorder := httptest.NewRecorder()
		fmt.Fprint(recorder, deviceModuleData)
		return recorder.Result(), nil
	})}
	result := AcquireModule(t.Context(), ModuleAcquireRequest{Module: device, OutputSnapshot: devicePath}, ModuleAcquireOptions{Client: client})
	if result.Status != "updated" {
		t.Fatalf("acquire local device module = %+v", result)
	}
	raw := fmt.Sprintf(`schema-version: 1
modules:
  - {id: %s, url: %q, arguments: {Host: profile.example.com}}
rules:
  - {id: first, match: {domain: allowed.example.com}, outbound: direct}
  - {module: %s}
  - {id: final, match: {all: true}, outbound: direct}
`, def.ID, def.URL, device.ID)
	shadowed := model.Module{ID: def.ID, URL: "https://other.example.com/ignored.sgmodule"}
	disabled := false
	second := model.Module{ID: "device-disabled", URL: "https://module.example.com/disabled.sgmodule", Enabled: &disabled}
	bundle, path := prepareSourceFixture(t, raw, PrepareOptions{
		DeviceModules: []model.Module{shadowed, device, second},
		Modules:       map[string]string{def.ID: modulePath, device.ID: devicePath},
	})
	profile, _, diagnostics := model.ParseProfile(bundle.Profile)
	if diagnostics.HasErrors() || len(profile.Modules) != 3 || profile.Modules[0].ID != def.ID ||
		profile.Modules[0].URL != def.URL || profile.Modules[1].ID != device.ID ||
		profile.Modules[2].ID != second.ID || !slices.Equal(bundle.DeviceModules, []string{device.ID, second.ID}) {
		t.Fatalf("merged profile modules = %+v, device IDs = %v, diagnostics = %v", profile.Modules, bundle.DeviceModules, diagnostics)
	}
	modules := bundle.Summary.Modules
	if len(modules) != 4 || modules[0].Origin != "profile" || modules[0].Shadowed ||
		!slices.Equal(modules[0].Hostnames, []string{"profile.example.com"}) {
		t.Fatalf("profile module did not win: %+v", modules)
	}
	isShadowed := func(entry ModuleSummary) bool {
		return entry.ID == def.ID && entry.Origin == "device" && entry.Shadowed && entry.Report == nil
	}
	if !slices.ContainsFunc(modules, isShadowed) {
		t.Fatalf("shadowed device module not reported: %+v", modules)
	}
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if len(eff.RuleIDs) != 3 || eff.RuleIDs[0] != "first" || !strings.HasPrefix(eff.RuleIDs[1], device.ID+"/") || eff.RuleIDs[2] != "final" {
		t.Fatalf("device rule marker was not expanded in place: %v", eff.RuleIDs)
	}

	unchanged, err := rebind(t.Context(), path, PrepareOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(unchanged.Summary.Modules, isShadowed) {
		t.Fatalf("rebind lost the archived shadowed entry: %+v", unchanged.Summary.Modules)
	}
	device.Enabled = &disabled
	rebound, err := rebind(t.Context(), path, PrepareOptions{DeviceModules: []model.Module{device}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if modules := rebound.Summary.Modules; len(modules) != 2 || modules[0].ID != def.ID ||
		modules[0].Origin != "profile" || !slices.Equal(modules[0].Hostnames, []string{"profile.example.com"}) ||
		modules[1].ID != device.ID || modules[1].Enabled || modules[1].Report != nil {
		t.Fatalf("rebind did not preserve the enabled profile module: %+v", modules)
	}
	if string(rebound.Resources[resource.Hash([]byte(deviceModuleData))]) != deviceModuleData ||
		rebound.Resources[resource.Hash([]byte(localBody))] != nil {
		t.Fatal("rebind did not keep shared Map Local data and remove the disabled module body")
	}
}

func TestPrepareRejectsDeviceModuleSourceIDConflict(t *testing.T) {
	_, sourcePath := prepareSourceFixture(t, clashSourceFixture, PrepareOptions{})
	def := model.Module{ID: "s-test", URL: "https://module.example.com/filter.sgmodule"}
	_, err := prepare(t.Context(), []byte(nodeSourceImport), &preparer{options: PrepareOptions{
		DeviceModules: []model.Module{def},
		Sources:       map[string]string{def.ID: sourcePath},
	}})
	var validation *ValidationError
	if !errors.As(err, &validation) || !strings.Contains(validation.Message, def.ID) ||
		!strings.Contains(strings.ToLower(validation.Message), "device module") || !strings.Contains(validation.Message, "source") {
		t.Fatalf("expected device module source conflict, got %v", err)
	}
}

func TestPrepareDeviceModuleRequiresMatchingSnapshotOnlyWhenEnabled(t *testing.T) {
	def, path := acquireDeviceModuleFixture(t)
	moved := def
	moved.URL += ".new"
	changedFormat := def
	changedFormat.Format = model.ModuleFormatLoon
	for _, tc := range []struct {
		name, message string
		module        model.Module
		paths         map[string]string
	}{
		{name: "missing", message: "snapshot is missing", module: def},
		{name: "moved", message: "declared ID, location, or format", module: moved, paths: map[string]string{def.ID: path}},
		{name: "changed format", message: "declared ID, location, or format", module: changedFormat, paths: map[string]string{def.ID: path}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prepare(t.Context(), []byte(clashSourceFixture), &preparer{options: PrepareOptions{
				DeviceModules: []model.Module{tc.module},
				Modules:       tc.paths,
			}})
			var validation *ValidationError
			if !errors.As(err, &validation) || !strings.Contains(validation.Message, tc.message) ||
				!strings.Contains(validation.Message, def.ID) || len(validation.Diagnostics) != 1 ||
				validation.Diagnostics[0].Path != "/modules/"+def.ID {
				t.Fatalf("expected a module snapshot diagnostic, got %v", err)
			}
		})
	}
	disabled := false
	def.Enabled = &disabled
	bundle, _ := prepareSourceFixture(t, clashSourceFixture, PrepareOptions{DeviceModules: []model.Module{def}})
	if modules := bundle.Summary.Modules; len(modules) != 1 || modules[0].Enabled ||
		modules[0].Origin != "device" || modules[0].Report != nil || len(bundle.Sources) != 0 {
		t.Fatalf("disabled module did not prepare without a snapshot: %+v", modules)
	}
}

func TestRebindClashDeviceModule(t *testing.T) {
	def, modulePath := acquireDeviceModuleFixture(t)
	initial, archive := prepareSourceFixture(t, clashSourceFixture, PrepareOptions{
		DeviceModules: []model.Module{def}, Modules: map[string]string{def.ID: modulePath},
	})
	client := &http.Client{Transport: modulePrepareTransport(func(req *http.Request) (*http.Response, error) {
		t.Errorf("rebind attempted to fetch %s", req.URL)
		return nil, errors.New("unexpected network request")
	})}
	input := filepath.Join(t.TempDir(), "profile.yaml")
	writeFixtureFile(t, input, []byte(clashSourceFixture))
	rebindArchive := func(options PrepareOptions) *Bundle {
		t.Helper()
		options.RebindSnapshot = archive
		dir := t.TempDir()
		archive = filepath.Join(dir, "snapshot.json")
		if err := prepareFile(t.Context(), input, archive, dir, options, client); err != nil {
			t.Fatal(err)
		}
		data, err := readBundleFile(archive)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		return bundle
	}
	assertEnabled := func(bundle *Bundle, hostname string) {
		t.Helper()
		eff, err := bundle.Compile()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(bundle.DeviceModules, []string{def.ID}) || !eff.Modules[def.ID].CanApply ||
			!slices.Equal(eff.MITM.Hostnames, []string{hostname}) {
			t.Fatalf("device module did not compile after rebind: module IDs %v, hostnames %v, reports %+v",
				bundle.DeviceModules, eff.MITM.Hostnames, eff.Modules)
		}
		for hash := range initial.Resources {
			if bundle.Resources[hash] == nil {
				t.Fatalf("rebind lost device module resource %s", hash)
			}
		}
	}
	assertEnabled(rebindArchive(PrepareOptions{MITM: &LocalMITM{Enabled: true}}), "a.example.com")
	def.Arguments = map[string]string{"Host": "changed.example.com"}
	assertEnabled(rebindArchive(PrepareOptions{DeviceModules: []model.Module{def}}), "changed.example.com")

	disabled := false
	off := def
	off.Enabled = &disabled
	bundle := rebindArchive(PrepareOptions{DeviceModules: []model.Module{off}})
	if modules := bundle.Summary.Modules; len(modules) != 1 || modules[0].Enabled || modules[0].Report != nil ||
		len(bundle.Sources) != 0 || len(bundle.Resources) != 0 || !slices.Equal(bundle.DeviceModules, []string{def.ID}) {
		t.Fatalf("disabled device module left sources or resources: %+v", bundle)
	}
	assertEnabled(rebindArchive(PrepareOptions{
		DeviceModules: []model.Module{def}, Modules: map[string]string{def.ID: modulePath},
	}), "changed.example.com")
	var clear PrepareOptions
	if err := json.Unmarshal([]byte(`{"deviceModules":[]}`), &clear); err != nil {
		t.Fatal(err)
	}
	bundle = rebindArchive(clear)
	if len(bundle.DeviceModules) != 0 || len(bundle.Summary.Modules) != 0 || len(bundle.Sources) != 0 || len(bundle.Resources) != 0 {
		t.Fatalf("empty device module list did not clear the archive: %+v", bundle)
	}
}
