package importer

import (
	"strings"
	"testing"
)

func TestProcessRegexImport(t *testing.T) {
	data := strings.Replace(sample, "MATCH,Choice", "PROCESS-NAME-REGEX,(?<=^)chrome(?=\\.exe$),REJECT\n - MATCH,Choice", 1)
	result := Import(request(data))
	if !result.Report.CanApply || result.Report.Partial {
		t.Fatalf("process regex rejected: %+v", result.Report)
	}
	if !strings.Contains(result.Preview(true).Sources, "process-name-regex") {
		t.Fatal("process regex was not retained")
	}
}
