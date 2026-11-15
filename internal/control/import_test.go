package control

import (
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/service"
)

func TestImportAPI(t *testing.T) {
	addr, _ := startServer(t)
	client, err := Connect(addr, "import-test")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := importer.Request{SourceID: "sub", Data: "proxies: [{name: node, type: socks5, server: 127.0.0.1, port: 1080, username: test-user, password: test-private}]"}
	var preview importer.Preview
	if err := client.Call("ImportSource", map[string]any{"import": request}, &preview); err != nil || !preview.Report.CanApply || strings.Contains(preview.Sources, "test-private") {
		t.Fatalf("preview: %+v %v", preview.Report, err)
	}
	var before service.Configuration
	if err := client.Call("GetConfiguration", nil, &before); err != nil || before.Revision != 1 || before.Sources != "" {
		t.Fatal("preview has side effects", err)
	}
	var result service.Result
	if err := client.Call("CommitConfiguration", service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: 1, Import: &request}}, &result); err != nil || result.State != "committed" {
		t.Fatalf("commit: %+v %v", result, err)
	}
	var after service.Configuration
	if err := client.Call("GetConfiguration", nil, &after); err != nil || after.Revision != 2 || !strings.Contains(after.Sources, "p-") || strings.Contains(after.Sources, "test-private") {
		t.Fatal("commit result", err)
	}
}
