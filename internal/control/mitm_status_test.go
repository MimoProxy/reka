package control

import (
	"encoding/json"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
)

func TestGetMITMStatus(t *testing.T) {
	if !slices.Contains(Methods, "GetMITMStatus") {
		t.Fatal("GetMITMStatus missing from the advertised methods")
	}
	call := testSession(t, nil)
	reply := call(t, Request{ID: 2, Method: "GetMITMStatus"})
	var status api.MITMStatus
	if reply.Error != nil {
		t.Fatal(reply.Error)
	}
	if err := json.Unmarshal(reply.Result, &status); err != nil {
		t.Fatal(err)
	}
	if status.H2 != "enabled" || status.Enabled || status.CALoaded || status.CAError != "" ||
		status.PinningBypasses == nil || len(status.PinningBypasses) != 0 || status.Connections != 0 || status.Requests != 0 ||
		status.PlainHTTPConnections != 0 || status.PlainHTTPRequests != 0 {
		t.Fatalf("initial MITM status = %+v", status)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(reply.Result, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"plain_http_connections_total", "plain_http_requests_total"} {
		if string(fields[key]) != "0" {
			t.Fatalf("initial %s = %s, want 0", key, fields[key])
		}
	}
	wantScripts := api.MITMScriptStatus{Status: "disabled"}
	if runtime.GOOS == "ios" {
		wantScripts.Status = "unsupported"
	}
	if !reflect.DeepEqual(status.Scripts, wantScripts) {
		t.Fatalf("initial MITM script status = %+v, want %+v", status.Scripts, wantScripts)
	}
}
