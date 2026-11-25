package compile

import (
	"testing"

	"github.com/MimoProxy/reka/internal/config/module"
)

// Module jq and replacement body rewrites must survive the trip through the
// module layer, which encodes converted rules back into profile nodes.
func TestModuleBodyRewritesCompile(t *testing.T) {
	const body = `[Body Rewrite]
http-response-jq ^https:\/\/api\.example\.com\/vip\? 'delpaths([["activity_banner"]])'
http-response-jq ^https:\/\/api\.example\.com\/questions\/\d+ 'del(.ad_info) | if (.data | type) == "array" then .data |= map(select(.paid | not)) else . end'
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
}
