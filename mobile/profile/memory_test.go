package profile

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestPrepareRejectsOversizedRuleProvider(t *testing.T) {
	var text strings.Builder
	// Each short regexp expands to a long program. The resource remains well
	// below the on-disk snapshot limit.
	for i := range 400 {
		fmt.Fprintf(&text, "DOMAIN-REGEX,^sub%03d[ab]{1000}\\.test$\n", i)
	}
	cache := t.TempDir()
	blobs, err := resource.Open(cache)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := blobs.Put([]byte(text.String()))
	if err != nil {
		t.Fatal(err)
	}
	input, output := filepath.Join(t.TempDir(), "native.yaml"), filepath.Join(cache, "candidate.json")
	writeFixtureFile(t, input, fmt.Appendf(nil, `schema-version: 1
rule-sets: [{id: oversized-list, behavior: classical, format: text, hash: %s}]
rules: [{id: use-list, match: {rule-set: oversized-list}, outbound: reject}]
`, hash))
	err = PrepareFile(t.Context(), input, output, cache)
	var report *ValidationError
	if !errors.As(err, &report) {
		t.Fatalf("expected an iOS rule memory error, got %v", err)
	}
	for _, diagnostic := range report.Diagnostics {
		if diagnostic.Code == "ios.memory" && diagnostic.Path == "/rule-sets/oversized-list" &&
			strings.Contains(report.Message, "oversized-list needs about") && strings.Contains(report.Message, "30 MiB") {
			return
		}
	}
	t.Fatalf("missing rule memory diagnostic: %+v", report)
}

func TestRuleMemoryBudgetNamesLargestContributor(t *testing.T) {
	estimate := compile.RuleMemoryEstimate{Bytes: 32 << 20, LargestBytes: 18 << 20, Name: "geosite:large", Path: "/geodata/geosite"}
	diagnostics := appendRuleMemoryDiagnostic(nil, estimate)
	if len(diagnostics) != 1 || diagnostics[0].Code != "ios.memory" || !strings.Contains(diagnostics[0].Message, "geosite:large at about 18.0 MiB") {
		t.Fatalf("missing cumulative memory diagnostic: %v", diagnostics)
	}
	estimate.Bytes = iosRuleMemoryBudget
	if diagnostics := appendRuleMemoryDiagnostic(nil, estimate); len(diagnostics) != 0 {
		t.Fatalf("profile within the budget was rejected: %v", diagnostics)
	}
}
