package router

import (
	"context"
	"testing"
)

func TestProcessRegexUsesCaseInsensitiveDotNetSyntax(t *testing.T) {
	spec, err := ParseClashCondition(`PROCESS-NAME-REGEX,(?<=^)chrome(?=\.exe$)`)
	if err != nil {
		t.Fatal(err)
	}
	spec.Target = "reject"
	r := mustRouter(t, []RuleSpec{spec}, nil)
	if !r.Rules().NeedsProcess() {
		t.Fatal("process lookup was not requested")
	}
	for _, entry := range []struct {
		process string
		want    string
	}{{`C:\Program Files\CHROME.EXE`, "reject"}, {"/usr/bin/chrome.exe", "reject"}, {"/usr/bin/firefox.exe", "direct"}, {"", "direct"}} {
		if d := r.Route(context.Background(), Metadata{Network: "tcp"}, &fakeEnv{process: entry.process}); d.Outbound != entry.want {
			t.Fatalf("%q -> %+v", entry.process, d)
		}
	}
	if _, err = CompileRules([]RuleSpec{{Kind: KindProcessNameRegex, Values: []string{"(?<"}, Target: "reject"}}); err == nil {
		t.Fatal("invalid regex accepted")
	}
}

func TestRegexCSVRetainsCommasAndEscapedParentheses(t *testing.T) {
	for _, text := range []string{`PROCESS-NAME-REGEX,^app\([a,b]{1,3}\)\.exe$,reject`, `DOMAIN-REGEX,^x\([a,b]{1,3}\)\.test$,reject`} {
		r, _, err := ParseClashRule(text)
		if err != nil {
			t.Fatal(text, err)
		}
		if r.Target != "reject" || len(r.Values) != 1 {
			t.Fatalf("payload split: %+v", r)
		}
	}
}
