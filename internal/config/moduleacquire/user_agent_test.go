package moduleacquire

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

// Module hosts that check the user agent must receive the client the module
// format targets, both for the module and for the scripts it references.
func TestAcquireSendsFormatUserAgent(t *testing.T) {
	const scriptURL = "https://example.com/filter.js"
	for _, tt := range []struct{ location, prefix, document string }{
		{"/filter.sgmodule", "Surge iOS/", "[Script]\nfilter = type=http-response,pattern=example,script-path=" + scriptURL + "\n"},
		{"/filter.plugin", "Loon/", "[Script]\nhttp-response example script-path=" + scriptURL + ", tag=Filter\n"},
		{"/filter.stoverride", "Stash/", "http:\n  script:\n    - {match: example, name: filter, type: response}\nscript-providers:\n  filter: {url: " + scriptURL + ", interval: 600}\n"},
	} {
		t.Run(tt.location, func(t *testing.T) {
			var agents []string
			opts := acquireTestOptions(t, func(w http.ResponseWriter, req *http.Request) {
				agent := req.Header.Get("User-Agent")
				agents = append(agents, agent)
				if !strings.HasPrefix(agent, tt.prefix) {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				if req.URL.Path == "/filter.js" {
					fmt.Fprint(w, "$done();")
					return
				}
				fmt.Fprint(w, tt.document)
			})
			result, err := Acquire(t.Context(), model.Module{ID: "filter", URL: "https://example.com" + tt.location}, opts)
			if err != nil || len(result.Snapshot.Lock.Resources) != 1 || len(result.ScriptErrors) != 0 {
				t.Fatalf("acquire = %+v, %v; user agents %q", result, err, agents)
			}
		})
	}
}
