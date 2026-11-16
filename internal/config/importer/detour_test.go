package importer

import "testing"

func TestClashDetourReferencesScopesAndNodesOnlyDependencies(t *testing.T) {
	data := `proxies:
 - {name: child, type: ss, server: child.test, port: 443, cipher: aes-128-gcm, password: test, dialer-proxy: hop}
 - {name: parent, type: direct}
proxy-groups: [{name: hop, type: select, proxies: [parent]}]
`
	for _, nodesOnly := range []bool{false, true} {
		req := request(data)
		req.NodesOnly = nodesOnly
		r := Import(req)
		if !r.Report.CanApply {
			t.Fatal(nodesOnly, r.Report)
		}
		src := snapshot(t, r)
		if len(src.Groups) != 1 || src.Outbounds[0].Dialer.Proxy != src.Groups[0].ID {
			t.Fatal("node-only detour dependencies lost", src)
		}
		compileImport(t, r)
	}
}
func TestClashRejectsCombinedNodeAndGroupDetourCycle(t *testing.T) {
	r := Import(request("proxies: [{name: node, type: direct, dialer-proxy: hop}]\nproxy-groups: [{name: hop, type: select, proxies: [node]}]"))
	if r.Report.CanApply {
		t.Fatal("combined dependency cycle accepted")
	}
}
