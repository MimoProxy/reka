package compile

import (
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
)

// Surge modules write inline Map Local data with unescaped quotes inside
// data="...". The value ends at the quote followed by whitespace or the end
// of the line, and the module must still compile.
func TestModuleMapLocalUnescapedQuotes(t *testing.T) {
	const body = `[Map Local]
^https:\/\/app\.example\.com\/x\/list\? header="content-type: application/json" data-type=text data="{"code":0,"message":"OK","list":[{}],"id":""}"
^https:\/\/app\.example\.com\/x\/close\? data-type=text data="{"type":"close_win"}" header="content-type: application/json"
^https:\/\/grpc\.example\.com\/Mode$ header="content-type: application/grpc|grpc-status: 0" data-type=base64 data="AAAAAAA="
`
	eff := compileModule(t, moduleProfile, moduleOptions(body))
	if eff.HTTPRewrite == nil {
		t.Fatal("module Map Local rules were not compiled")
	}
	for _, line := range eff.Modules["filter"].Lines {
		if line.Status != module.Supported {
			t.Errorf("line %d = %s %s", line.Line, line.Status, line.Message)
		}
	}

	result, _ := module.Convert([]byte(body), module.Options{ID: "filter", Format: model.ModuleFormatSurge})
	want := []string{`{"code":0,"message":"OK","list":[{}],"id":""}`, `{"type":"close_win"}`, "AAAAAAA="}
	if len(result.MapLocal) != len(want) {
		t.Fatalf("Map Local rules = %d", len(result.MapLocal))
	}
	for i, rule := range result.MapLocal {
		if rule.Data == nil || *rule.Data != want[i] {
			t.Errorf("rule %d data = %v, want %q", i, rule.Data, want[i])
		}
		if len(rule.Headers) == 0 {
			t.Errorf("rule %d lost its headers", i)
		}
	}
}
