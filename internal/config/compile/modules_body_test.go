package compile

import (
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
)

// Module jq and replacement body rewrites must survive the trip through the
// module layer, which encodes converted rules back into profile nodes.
func TestModuleBodyRewritesCompile(t *testing.T) {
	const body = `[Body Rewrite]
http-response-jq ^https:\/\/api\.example\.com\/vip\? 'delpaths([["activity_banner"]])'
http-response-jq ^https:\/\/api\.example\.com\/questions\/\d+ 'del(.ad_info) | if (.data | type) == "array" then .data |= map(select(.paid | not)) else . end'
http-response ^https:\/\/api\.example\.com\/search\? "recommend_queries":\{.+\} "recommend_queries":{}
http-request ^https:\/\/api\.example\.com\/upload ad noad
`
	eff := compileModule(t, moduleProfile, moduleOptions(body))
	if eff.HTTPRewrite == nil {
		t.Fatal("module body rewrites were not compiled")
	}
	for _, line := range eff.Modules["filter"].Lines {
		if line.Status != module.Supported {
			t.Errorf("line %d = %s %s", line.Line, line.Status, line.Message)
		}
	}

	result, _ := module.Convert([]byte(body), module.Options{ID: "filter", Format: model.ModuleFormatSurge})
	if len(result.BodyRewrites) != 4 {
		t.Fatalf("body rewrites = %d", len(result.BodyRewrites))
	}
	literal := result.BodyRewrites[2].Replace
	if len(literal) != 1 || *literal[0].Pattern != `"recommend_queries":\{.+\}` || *literal[0].Value != `"recommend_queries":{}` {
		t.Fatalf("quote-led replacement = %+v", literal)
	}
}
