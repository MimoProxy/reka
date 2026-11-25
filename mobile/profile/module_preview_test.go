package profile

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/MimoProxy/reka/internal/config/module"
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
	if err != nil || metadata.Name != "Preview" || !slices.Equal(metadata.Arguments, []module.Argument{{
		Name: "Host", Default: "default.example.test", Value: "selected.example.test",
	}}) {
		t.Fatalf("unexpected metadata: %+v, %v", metadata, err)
	}
}
