package importer

import "testing"

func TestClashActionsAndGeneratedGlobal(t *testing.T) {
	for _, action := range []string{"PASS", "COMPATIBLE", "REJECT-DROP", "GLOBAL"} {
		req := request("proxies: [{name: node, type: direct}]\nproxy-groups: [{name: Choice, type: select, proxies: [node, PASS, REJECT-DROP, COMPATIBLE]}]\nrules: ['DOMAIN,example.test," + action + "','MATCH,Choice']")
		r := Import(req)
		if !r.Report.CanApply {
			t.Fatal(action, r.Report)
		}
		eff := compileImport(t, r)
		if action == "GLOBAL" && len(eff.Groups) != 2 {
			t.Fatal("GLOBAL selector missing", eff.Groups)
		}
	}
}
