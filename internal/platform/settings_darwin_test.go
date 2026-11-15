//go:build darwin

package platform

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProxyRestoreClearsEmptyEndpointAtomically(t *testing.T) {
	s, e := proxyPreferenceScript("/NetworkServices/fixture/Proxies", true, map[string]json.RawMessage{"HTTPProxy": nil, "HTTPPort": nil, "ExceptionsList": nil}, "webproxy", proxyValue{})
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"d.add HTTPEnable # 0", "d.remove HTTPProxy", "d.remove HTTPPort", "commit\napply"} {
		if !strings.Contains(s, want) {
			t.Fatal(s)
		}
	}
	if strings.Contains(s, "ExceptionsList") {
		t.Fatal("unowned settings changed")
	}
	if strings.Count(s, "commit") != 1 {
		t.Fatal("non-atomic proxy update")
	}
}
