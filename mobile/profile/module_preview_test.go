package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/subscription"
)

func TestModulePreviewUsesPreparedPoliciesWithoutAcquiringResources(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "profile.yaml")
	snapshot := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(input, []byte(`schema-version: 1
outbounds:
  - {id: choice, type: direct, name: Selected Policy}
`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareFile(t.Context(), input, snapshot, dir); err != nil {
		t.Fatal(err)
	}
	text := `#!name=Preview
#!arguments=Host:default.example.test
[Rule]
DOMAIN,example.test,Selected Policy
[MITM]
hostname = %INSERT% {{{Host}}}
hostname = %APPEND% appended.example.test
[Script]
unsupported = type=http-request
[Map Local]
^https://example\.test/ data=https://example.invalid/payload
`
	req := ModulePreviewRequest{
		ModuleInput: ModuleInput{
			Text: &text, Arguments: map[string]string{"Host": "selected.example.test"},
		},
		ProfileSnapshot: snapshot,
	}
	result, err := PreviewModule(t.Context(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := result.Report
	if report.CanApply || !report.Partial || report.Rules.Imported != 1 ||
		!slices.Equal(result.Hostnames.Insert, []string{"selected.example.test"}) ||
		!slices.Equal(result.Hostnames.Append, []string{"appended.example.test"}) {
		t.Fatalf("unexpected preview: %+v", result)
	}
	for _, want := range []module.Line{
		{Line: 9, Section: "script", Status: module.Unsupported, Code: "module.script-pattern"},
		{Line: 11, Section: "map local", Status: module.Error, Code: "module.resource-missing"},
	} {
		if !slices.ContainsFunc(report.Lines, func(line module.Line) bool {
			return line.Line == want.Line && line.Section == want.Section &&
				line.Status == want.Status && line.Code == want.Code && line.Message != ""
		}) {
			t.Fatalf("missing line outcome %+v: %+v", want, report.Lines)
		}
	}
	metadata, err := InspectModule(t.Context(), req.ModuleInput)
	if err != nil || metadata.Name != "Preview" || !reflect.DeepEqual(metadata.Arguments, []module.Argument{{
		Name: "Host", Default: "default.example.test", Value: "selected.example.test",
	}}) {
		t.Fatalf("unexpected metadata: %+v, %v", metadata, err)
	}
}

func TestModulePreparationAndPreviewUseAcquiredFormat(t *testing.T) {
	for _, tt := range []struct {
		format, extension, text string
	}{
		{model.ModuleFormatLoon, ".plugin", "#!name=Example\n[MITM]\nhostname = %INSERT% example.test\n"},
		{model.ModuleFormatStash, ".stoverride", "name: Example\nhttp:\n  mitm: ['%INSERT% example.test']\n"},
	} {
		t.Run(tt.format, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "example"+tt.extension)
			output := filepath.Join(dir, "snapshot.json")
			if err := os.WriteFile(input, []byte(tt.text), 0600); err != nil {
				t.Fatal(err)
			}
			req := ModuleAcquireRequest{Module: model.Module{ID: "example", File: input}, OutputSnapshot: output}
			acquired := AcquireModule(t.Context(), req, ModuleAcquireOptions{})
			if acquired.Status != "updated" || acquired.Format != tt.format || acquired.Hostnames == nil ||
				!slices.Equal(acquired.Hostnames.Insert, []string{"example.test"}) {
				t.Fatalf("acquire: %+v", acquired)
			}
			for _, source := range []ModuleInput{{Snapshot: output}, {File: input}, {Text: &tt.text, Filename: input}} {
				result, err := PreviewModule(t.Context(), ModulePreviewRequest{ModuleInput: source}, nil)
				if err != nil || result.Report.Format != tt.format || result.Report.Name != "Example" ||
					!slices.Equal(result.Hostnames.Insert, []string{"example.test"}) {
					t.Fatalf("preview: %+v, error %v", result, err)
				}
			}
			profile := fmt.Sprintf("schema-version: 1\nmodules: [{id: example, file: %q}]\n", input)
			bundle, _ := prepareSourceFixture(t, profile, PrepareOptions{Modules: map[string]string{req.Module.ID: output}})
			if mods := bundle.Summary.Modules; len(mods) != 1 || mods[0].Format != tt.format ||
				!slices.Equal(mods[0].Hostnames, []string{"example.test"}) {
				t.Fatalf("prepared modules: %+v", mods)
			}
			req.Module.Format = model.ModuleFormatSurge
			_, err := PreviewModule(t.Context(), ModulePreviewRequest{ModuleInput: ModuleInput{
				Snapshot: output, Format: req.Module.Format,
			}}, nil)
			if subscription.Code(err) != "module_snapshot_mismatch" {
				t.Fatalf("mismatched preview format: %v", err)
			}
		})
	}
}
