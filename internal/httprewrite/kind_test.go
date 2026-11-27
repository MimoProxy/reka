package httprewrite

import "testing"

func TestRewriteKinds(t *testing.T) {
	text, target := "text", "https://example.test/"
	set, err := New(Spec{
		HTTPRewrites: []HTTPRewrite{
			{ID: "url", Match: "^https://a\\.test/", Action: "header", Target: &target},
			{ID: "redirect", Match: "^https://b\\.test/", Action: "302", Target: &target},
			{ID: "reject", Match: "^https://c\\.test/", Action: "reject"},
		},
		HeaderRewrites: []HeaderRewrite{{ID: "header", Match: "^https://", Op: "del", Name: "X-Test"}},
		BodyRewrites:   []BodyRewrite{{ID: "body", Phase: "response", Match: "^https://", Replace: []Replacement{{Pattern: &text, Value: &text}}}},
		MapLocal:       []MapLocal{{ID: "local", Match: "^https://d\\.test/", DataType: &text, Data: &text}},
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{
		"url": KindURL, "redirect": KindRedirect, "reject": KindReject,
		"header": KindHeader, "body": KindBody, "local": KindMapLocal, "missing": "",
	} {
		if got := set.Kind(id); got != want {
			t.Errorf("Kind(%q) = %q, want %q", id, got, want)
		}
	}
	if (*Set)(nil).Kind("url") != "" {
		t.Error("a nil set reported a kind")
	}
}
