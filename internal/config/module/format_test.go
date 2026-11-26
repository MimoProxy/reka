package module

import "testing"

func TestDetectFormat(t *testing.T) {
	for _, tc := range []struct{ name, filename, text, want string }{
		{"extension before content", "https://example.test/filter.SGMODULE?name=file.plugin", "[Argument]", "surge"},
		{"file path", "/example/Filter.PLUGIN", "name: Example", "loon"},
		{"Windows file path", `C:\example\Filter.plugin`, "name: Example", "loon"},
		{"filename punctuation", "filter?.plugin", "name: Example", "loon"},
		{"encoded URL path", "https://example.test/filter%2Elpx?download=1", "", "loon"},
		{"override extension", "module.stoverride", "[Rule]", "stash"},
		{"YAML extension", "module.YAML", "invalid: [", "stash"},
		{"YML extension", "module.yml", "", "stash"},
		{"query is not extension", "https://example.test/file?name=a.plugin", "[Rule]", "surge"},
		{"BOM and comments", "", "\ufeff# comment\n; comment\n// comment\n [Rule]\nDOMAIN,example.test,DIRECT", "surge"},
		{"Loon argument section", "", "#!name=Filters\n[ Argument ]\nmode=input,example", "loon"},
		{"Loon version", "", "\n#!loon_version = 3\n[Rule]", "loon"},
		{"dictionary reject", "", "[Rewrite]\nexample reject-dict", "loon"},
		{"array reject", "", "[Rewrite]\nexample - reject-array", "loon"},
		{"JSON action", "", "[Rewrite]\nexample response-body-json-jq '.'", "loon"},
		{"expression", "", "[Rewrite]\nrequest if   ${url} ~= /test/ then reject()", "loon"},
		{"commented marker", "", "[Rule]\n# [Argument]\n// example reject-dict", "surge"},
		{"YAML mapping", "", "\ufeff# comment\n---\nscript-providers: {}", "stash"},
		{"YAML flow mapping", "", "{name: Example, rules: []}", "stash"},
		{"YAML proxy list", "", "proxies: [{type: tailscale, name: Tailnet}]", "stash"},
		{"unknown mapping", "", "other: []", ""},
		{"invalid YAML", "", "name: [Example", ""},
		{"unknown", "", "plain text", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectFormat(tc.filename, []byte(tc.text)); got != tc.want {
				t.Fatalf("detected %q, want %q", got, tc.want)
			}
		})
	}
}
