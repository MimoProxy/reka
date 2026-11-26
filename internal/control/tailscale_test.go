package control

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
)

func TestGetTailscaleStatus(t *testing.T) {
	const method = "GetTailscaleStatus"
	if !slices.Contains(Methods, method) {
		t.Fatalf("%s missing from the advertised methods", method)
	}
	reply := testSession(t, nil)(t, Request{ID: 2, Method: method})
	if reply.Error != nil {
		t.Fatal(reply.Error)
	}
	var status api.TailscaleStatus
	if err := json.Unmarshal(reply.Result, &status); err != nil {
		t.Fatal(err)
	}
	if status.State != api.TailscaleStopped || status.ID != "" || strings.Contains(string(reply.Result), "auth-url") ||
		status.Peers == nil || len(status.Peers) != 0 || status.TailscaleIPs == nil || len(status.TailscaleIPs) != 0 {
		t.Fatalf("unexpected stopped status: %s", reply.Result)
	}
}
