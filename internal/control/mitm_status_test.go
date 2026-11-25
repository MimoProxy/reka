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
	if status.H2 != "disabled" || status.Enabled || status.CALoaded || status.CAError != "" ||
		status.PinningBypasses == nil || len(status.PinningBypasses) != 0 || status.Connections != 0 || status.Requests != 0 {
		t.Fatalf("initial MITM status = %+v", status)
	}
	wantScripts := api.MITMScriptStatus{Status: "disabled"}
	if runtime.GOOS == "ios" {
		wantScripts.Status = "unsupported"
	}
	if !reflect.DeepEqual(status.Scripts, wantScripts) {
		t.Fatalf("initial MITM script status = %+v, want %+v", status.Scripts, wantScripts)
	}
}
