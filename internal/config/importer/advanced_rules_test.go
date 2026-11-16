package importer

import (
	"testing"
)

func TestAdvancedClashRulesConvertWithoutPartialActivation(t *testing.T) {
	input := `rules:
 - PROCESS-PATH,/opt/App/app,DIRECT
 - PROCESS-PATH-REGEX,^/opt/App/app$,REJECT
 - PROCESS-NAME-WILDCARD,app*,DIRECT
 - PROCESS-PATH-WILDCARD,/opt/*/app,DIRECT
 - IN-NAME,auth/other,DIRECT
 - IN-TYPE,HTTP/SOCKS,DIRECT
 - IN-PORT,17890/18000-18100,DIRECT
 - IN-USER,Alice/Bob,DIRECT
 - UID,10000-10100,DIRECT
 - MATCH,DIRECT
`
	r := Import(request(input))
	if !r.Report.CanApply || r.Report.Partial || r.Report.Rules.Imported != 10 {
		t.Fatal(r.Report)
	}
	compileImport(t, r)
}
