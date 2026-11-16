package importer

import (
	"encoding/base64"
	"encoding/pem"
	S "github.com/sagernet/sing-box/common/tls"
	"strings"
	"testing"
)

func TestClashECHConfigAndStrictOptions(t *testing.T) {
	config, _, err := S.ECHKeygenDefault("public.test")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(config))
	encoded := base64.StdEncoding.EncodeToString(block.Bytes)
	const input = `proxies: [{name: node, type: http, server: node.test, port: 443, tls: true, ech-opts: {enable: true, config: CONFIG, query-server-name: query.test}}]`
	data := strings.Replace(input, "CONFIG", encoded, 1)
	r := Import(request(data))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	compileImport(t, r)
	ech := snapshot(t, r).Outbounds[0].TLS.ECH
	if ech == nil || !ech.Enabled || ech.Config != encoded || ech.QueryServerName != "query.test" {
		t.Fatal("ECH settings dropped")
	}
	for _, edit := range []struct{ from, to string }{
		{encoded, "invalid-base64"},
		{"enable: true", "enable: yes-please"},
		{"query-server-name: query.test", "made-up-option: true"},
		{"tls: true", "tls: false"},
	} {
		if Import(request(strings.Replace(data, edit.from, edit.to, 1))).Report.CanApply {
			t.Fatal("invalid ECH imported", edit.from)
		}
	}
	auto := Import(request("proxies: [{name: node, type: http, server: node.test, port: 443, tls: true, ech-opts: {enable: true}}]"))
	if !auto.Report.CanApply || snapshot(t, auto).Outbounds[0].TLS.ECH == nil {
		t.Fatal(auto.Report)
	}
}
