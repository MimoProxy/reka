package module

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

func TestMetadataArgumentsAndHostnames(t *testing.T) {
	const input = `#!name=Example filters
#!desc=Local tests # retained
#!system=ios
#!category=Filters
#!icon=https://example.com/icon.png
#!arguments=PROXY:Example route,内容:"hello, world",空:,hide:true,Host:sub.example.com
#!arguments-desc=PROXY:"Route, by name",内容:Text
#!requirement=system-version >= 10
#!author=Synthetic
#!homepage=https://example.com/
#!date=2026-01-01
#!version=1.0
#!other=value

# a comment
; a comment
// a comment
[rUlE]
DOMAIN,example.com,{{{PROXY}}}
DOMAIN,undefined.test,{{{undefined}}}
[MiTm]
hostname = %INSERT% -no.example.com, {{{Host}}}:0, , *.example.com:8443
hostname = %APPEND% example.net
hostname = example.test
h2 = TRUE
skip-server-cert-verify = false
hostname-disabled = example.com
tcp-connection = true
client-source-address = 192.0.2.1
ca-p12 = synthetic
ca-passphrase = synthetic
unknown = true
[Map Local]
^https://example\.com data-type=text data="{{{内容}}}{{{空}}}#"
`
	result, report := Convert([]byte(input), Options{
		ID: "filters", Arguments: map[string]string{"PROXY": "Alternate route", "Host": "override.example.com", "extra": ""},
		Resolve: func(name string) (string, bool) { return "alternate", name == "Alternate route" },
	})
	if report.ModuleID != "filters" || report.Format != "surge" || report.Name != "Example filters" || report.Desc != "Local tests # retained" || report.System != "ios" || report.Category != "Filters" || report.Icon != "https://example.com/icon.png" {
		t.Fatalf("invalid metadata %+v", report.Metadata)
	}
	wantArgs := []Argument{
		{Name: "PROXY", Default: "Example route", Value: "Alternate route", Description: "Route, by name"},
		{Name: "内容", Default: "hello, world", Value: "hello, world", Description: "Text"},
		{Name: "空"},
		{Name: "hide", Default: "true", Value: "true"},
		{Name: "Host", Default: "sub.example.com", Value: "override.example.com"},
	}
	if !reflect.DeepEqual(report.Arguments, wantArgs) || len(report.Diagnostics) != 1 || report.Diagnostics[0].Severity != model.SeverityWarning {
		t.Fatalf("invalid arguments %+v, diagnostics %+v", report.Arguments, report.Diagnostics)
	}
	if !report.Partial || !report.CanApply || report.Rules != (Count{Total: 2, Imported: 1, Unavailable: 1}) || report.Rewrites.Imported != 1 || report.Hostnames.Imported != 5 {
		t.Fatalf("invalid report %+v", report)
	}
	if len(result.Rules) != 1 || result.Rules[0].Outbound != "alternate" || result.Rules[0].Syntax != "DOMAIN,example.com,{{{PROXY}}}" || result.ItemLines[result.Rules[0].ID] != 19 {
		t.Fatalf("wrong converted rule %+v", result.Rules)
	}
	if !slices.Equal(result.InsertHostnames, []Hostname{{"-no.example.com", 22}, {"override.example.com:0", 22}, {"*.example.com:8443", 22}}) ||
		!slices.Equal(result.AppendHostnames, []Hostname{{"example.net", 23}, {"example.test", 24}}) ||
		result.MITM.H2 == nil || !*result.MITM.H2 || result.MITM.SkipServerCertVerify == nil || *result.MITM.SkipServerCertVerify {
		t.Fatalf("invalid MITM result %+v", result)
	}
	if *result.MapLocal[0].Data != "hello, world#" {
		t.Fatalf("hash was interpreted as a comment: %+v", result.MapLocal)
	}
	byLine := map[int]Line{}
	for _, line := range report.Lines {
		byLine[line.Line] = line
	}
	for n, want := range map[int]string{1: Supported, 8: Ignored, 13: Supported, 19: Supported, 20: Unsupported, 24: Supported, 27: Ignored, 28: Ignored, 29: Ignored, 30: Ignored, 31: Ignored, 32: Unsupported} {
		if got := byLine[n]; got.Status != want {
			t.Fatalf("line %d: got %+v, want %s", n, got, want)
		}
	}
	if byLine[24].Code != "module.hostname-append" || byLine[20].Code != "module.undefined-argument" {
		t.Fatalf("wrong diagnostics for hostname append or undefined argument: %+v", byLine)
	}
	for _, want := range []int{14, 15, 16, 17} {
		if _, ok := byLine[want]; ok {
			t.Fatalf("comment or blank line was reported: %d", want)
		}
	}
	payload, err := json.Marshal(report.Lines)
	if err != nil || strings.Contains(string(payload), "DOMAIN,example.com") {
		t.Fatalf("report contains raw lines: %s (%v)", payload, err)
	}
}

func TestIgnoredAndUnsupportedSections(t *testing.T) {
	for _, tc := range []struct{ section, status string }{
		{"General", Ignored}, {"Replica", Ignored}, {"Proxy", Ignored}, {"Proxy Group", Ignored}, {"WireGuard example", Ignored}, {"Ruleset", Ignored}, {"Ruleset example", Ignored},
		{"Script", Unsupported}, {"Panel", Unsupported}, {"MTProto", Unsupported}, {"SSID Setting", Unsupported}, {"Snell Server", Unsupported},
		{"Host", Unsupported}, {"Other", Unsupported},
	} {
		t.Run(tc.section, func(t *testing.T) {
			_, report := Convert([]byte("["+tc.section+"]\nexample.com = 192.0.2.1\n"), Options{})
			if !report.CanApply || !report.Partial || len(report.Lines) != 2 || report.Lines[1].Status != tc.status {
				t.Fatalf("wrong report %+v", report)
			}
		})
	}
}

func TestRules(t *testing.T) {
	for _, tc := range []struct {
		line, kind, target, status string
		noResolve                  bool
	}{
		{"DOMAIN,example.com,DIRECT", "domain", "direct", Supported, false},
		{"DOMAIN-SUFFIX,example.com,REJECT", "domain-suffix", "reject", Supported, false},
		{"DOMAIN-KEYWORD,example,Reject-Drop", "domain-keyword", "reject-drop", Supported, false},
		{"DOMAIN-WILDCARD,?.*.example.com,REJECT-NO-DROP", "domain-regex", "reject", Supported, false},
		{"IP-CIDR,192.0.2.0/24,REJECT-TINYGIF,no-resolve", "ip-cidr", "reject", Supported, true},
		{"IP-CIDR6,2001:db8::/32,proxy,no-resolve,extended-matching", "ip-cidr", "route", Supported, true},
		{"IP-ASN,AS64500,direct,no-resolve", "ip-asn", "direct", Supported, true},
		{"GEOIP,lan,DIRECT,no-resolve", "geoip", "direct", Supported, true},
		{"GEOIP,ZZ,DIRECT", "geoip", "direct", Supported, false},
		{"GEOSITE,example,DIRECT", "geosite", "direct", Supported, false},
		{"DST-PORT,443,REJECT", "dst-port", "reject", Supported, false},
		{"DEST-PORT,443,REJECT", "dst-port", "reject", Supported, false},
		{"SRC-IP,192.0.2.1,DIRECT", "src-ip-cidr", "direct", Supported, false},
		{"PROCESS-NAME,Example,direct,pre-matching", "process-name", "direct", Supported, false},
		{"DOMAIN,example.com,direct,extended-matching", "domain", "direct", Supported, false},
		{"DOMAIN,example.com,direct,extended-matching,future-modifier", "domain", "direct", Ignored, false},
		{"PROTOCOL,TCP,DIRECT", "network", "direct", Supported, false},
		{"PROTOCOL,udp,REJECT", "network", "reject", Supported, false},
		{"PROTOCOL,QUIC,REJECT", "and", "reject", Supported, false},
		{"AND,((PROTOCOL,QUIC),(DOMAIN-SUFFIX,example.com,extended-matching)),REJECT", "and", "reject", Supported, false},
		{"PROTOCOL,STUN,REJECT", "", "", Unsupported, false},
		{"PROTOCOL,HTTPS,DIRECT", "", "", Unsupported, false},
		{"AND,((DOMAIN,example.com),(SRC-IP,192.0.2.1)),DIRECT", "and", "direct", Supported, false},
		{"OR,((DOMAIN,example.com),(DOMAIN-SUFFIX,example.net)),REJECT", "or", "reject", Supported, false},
		{"NOT,((DOMAIN,example.com)),DIRECT", "not", "direct", Supported, false},
		{"RULE-SET,filters/example,DIRECT,no-resolve", "rule-set", "direct", Supported, true},
		{"DOMAIN-SET,examples,DIRECT", "rule-set", "direct", Supported, false},
		{`DOMAIN-REGEX,^a{1,3}\.example\.com$,DIRECT`, "domain-regex", "direct", Supported, false},
		{`DOMAIN-REGEX,(?=a)example\.com,DIRECT`, "", "", Unsupported, false},
		{`DOMAIN,example.com,"Comma, Route"`, "domain", "route", Supported, false},
		{"RULE-SET,https://example.com/sites.list,DIRECT", "", "", Unsupported, false},
		{"DOMAIN-SET,https://example.com/sites.list,DIRECT", "", "", Unsupported, false},
		{"URL-REGEX,^https://example.com,REJECT", "", "", Unsupported, false},
		{"USER-AGENT,Example,REJECT", "", "", Unsupported, false},
		{"SCRIPT,example,REJECT", "", "", Unsupported, false},
		{"SUBNET,example.net,REJECT", "", "", Unsupported, false},
		{"CELLULAR-RADIO,LTE,REJECT", "", "", Unsupported, false},
		{"FINAL,DIRECT", "", "", Unsupported, false},
		{"MATCH,DIRECT", "", "", Unsupported, false},
		{"DOMAIN,example.com,missing", "", "", Error, false},
		{"DOMAIN,example.com,ambiguous", "", "", Error, false},
	} {
		t.Run(tc.line, func(t *testing.T) {
			result, report := Convert([]byte("[RULE]\n"+tc.line), Options{Resolve: func(name string) (string, bool) {
				if name == "ambiguous" {
					return "ambiguous policy display name", false
				}
				return "route", name == "proxy" || name == "Comma, Route"
			}})
			if got := report.Lines[1].Status; got != tc.status || report.CanApply != (tc.status != Error) {
				t.Fatalf("unexpected report %+v", report)
			}
			if tc.kind == "" {
				if len(result.Rules) != 0 || report.Rules.Unavailable != 1 {
					t.Fatalf("unexpected rule %+v", result.Rules)
				}
				if tc.status == Error && (len(report.Diagnostics) != 1 || report.Diagnostics[0].Line != 2) {
					t.Fatalf("missing error diagnostic %+v", report.Diagnostics)
				}
				return
			}
			if len(result.Rules) != 1 || report.Rules.Imported != 1 {
				t.Fatalf("rule missing %+v", result)
			}
			rule := result.Rules[0]
			if rule.Match.Kind != tc.kind || rule.Outbound != tc.target || rule.Match.NoResolve != tc.noResolve {
				t.Fatalf("wrong rule %+v", rule)
			}
			if strings.Contains(tc.line, "REJECT-NO-DROP") || strings.Contains(tc.line, "REJECT-TINYGIF") {
				if report.Lines[1].Code != "module.policy-approximate" {
					t.Fatal(report.Lines)
				}
			}
		})
	}
}

func TestRuleApproximationNotes(t *testing.T) {
	for _, tc := range []struct {
		line, code string
		notes      []string
		match      model.Match
	}{
		{"DOMAIN,example.com,DIRECT,extended-matching", "module.rule-approximate", []string{extendedMatchingNote}, model.Match{Kind: "domain", Values: []string{"example.com"}}},
		{"PROTOCOL,QUIC,REJECT-TINYGIF", "module.policy-approximate", []string{quicProtocolNote, "policy approximated by native reject"}, model.Match{Kind: "and", Children: []model.Match{
			{Kind: "network", Values: []string{"udp"}},
			{Kind: "dst-port", Values: []string{"443"}},
		}}},
		{"AND,((PROTOCOL,QUIC),(DOMAIN-SUFFIX,example.com,extended-matching)),REJECT", "module.rule-approximate", []string{extendedMatchingNote, quicProtocolNote}, model.Match{Kind: "and", Children: []model.Match{
			{Kind: "and", Children: []model.Match{
				{Kind: "network", Values: []string{"udp"}},
				{Kind: "dst-port", Values: []string{"443"}},
			}},
			{Kind: "domain-suffix", Values: []string{"example.com"}},
		}}},
	} {
		t.Run(tc.line, func(t *testing.T) {
			result, report := Convert([]byte("[Rule]\n"+tc.line), Options{})
			line := report.Lines[1]
			if line.Status != Supported || line.Code != tc.code || report.Partial || len(result.Rules) != 1 {
				t.Fatalf("unexpected report %+v", report)
			}
			for _, note := range tc.notes {
				if !strings.Contains(line.Message, note) {
					t.Fatalf("message %q lacks %q", line.Message, note)
				}
			}
			if !reflect.DeepEqual(result.Rules[0].Match, tc.match) {
				t.Fatalf("match = %+v", result.Rules[0].Match)
			}
		})
	}
}

func TestDomainWildcardMatchesAcrossLabelsAndClasses(t *testing.T) {
	const rule = "DOMAIN-WILDCARD,api-*[1-3]?.EXAMPLE.COM.,DIRECT"
	result, report := Convert([]byte("[Rule]\n"+rule), Options{})
	if !report.CanApply || report.Partial || len(result.Rules) != 1 {
		t.Fatal(report)
	}
	match := regexp.MustCompile(result.Rules[0].Match.Values[0])
	for _, test := range []struct {
		host string
		want bool
	}{
		{"api-1x.example.com", true}, {"api-a.b2x.example.com", true},
		{"api-4x.example.com", false}, {"api-1.example.com", false}, {"another.test", false},
	} {
		if got := match.MatchString(test.host); got != test.want {
			t.Errorf("match for %s: got %t, want %t", test.host, got, test.want)
		}
	}
}

func TestExpandedArgumentsAreBounded(t *testing.T) {
	value := strings.Repeat("x", 1<<20)
	text := "#!arguments=host:" + value + "\n[MITM]\nhostname=" + strings.Repeat("{{{host}}}", 17)
	_, report := Convert([]byte(text), Options{})
	if report.CanApply || len(report.Diagnostics) != 1 || report.Diagnostics[0].Code != "module.arguments-size" || report.Diagnostics[0].Line != 3 {
		t.Fatalf("invalid expansion diagnostic %+v", report.Diagnostics)
	}
}

func TestURLRewriteActions(t *testing.T) {
	for _, tc := range []struct{ action, native, response string }{
		{"header", "header", ""}, {"302", "302", ""}, {"307", "307", ""},
		{"reject", "reject", "error"}, {"reject-200", "reject", "200"},
		{"reject-img", "reject", "gif"}, {"reject-tinygif", "reject", "gif"},
		{"reject-dict", "reject", "dict"}, {"reject-array", "reject", "array"},
		{"reject-drop", "reject", "drop"}, {"reject-no-drop", "reject", "error"},
		{"invalid", "", ""},
	} {
		t.Run(tc.action, func(t *testing.T) {
			const expr = `^https://example\.com/(a b)(.*)`
			replacement := "https://example.net/$2#fragment"
			if tc.response != "" {
				replacement = "-"
			}
			for _, args := range []string{replacement + " " + tc.action, tc.action} {
				if tc.response == "" && args == tc.action {
					continue
				}
				result, report := Convert([]byte("[URL Rewrite]\n\""+expr+"\" "+args), Options{})
				if tc.native == "" {
					if len(result.HTTPRewrites) != 0 || report.Lines[1].Status != Unsupported {
						t.Fatalf("invalid action accepted %+v", result)
					}
					continue
				}
				if len(result.HTTPRewrites) != 1 || !report.CanApply || report.Partial {
					t.Fatalf("missing rewrite %+v", report)
				}
				rule := result.HTTPRewrites[0]
				if rule.Match != expr || rule.Action != tc.native || tc.response != "" && (rule.Response == nil || *rule.Response != tc.response || rule.Target != nil) || tc.response == "" && *rule.Target != replacement {
					t.Fatalf("wrong URL rewrite %+v", rule)
				}
			}
		})
	}
}

func TestHeaderAndBodyRewrites(t *testing.T) {
	const input = `#!arguments=mode:original
[Header Rewrite]
^https://example\.com header-add X-Example "two words"
http-request ^https://example\.com header-del X-Old
http-response ^https://example\.com header-replace X-Old empty
http-response ^https://example\.com header-replace-regex X-Test "(one two)" "$1#"
^https://example\.com header-del Content-Length
^https://example\.com header-del transfer-encoding
^https://example\.com header-del Connection
^https://example\.com header-replace-regex X-Test (?<=a)b x
[Body Rewrite]
http-request ^https://example\.com "x y" z a ""
http-response ^https://example\.com x y
http-request-jq ^https://example\.com '.test = "{{{mode}}}"'
http-response-jq ^https://example\.com "del(.test)"
http-response-jq ^https://example\.com jq-path=example.jq
http-response ^https://example\.com (?=a)b x
http-response-jq ^https://example\.com '??'
`
	result, report := Convert([]byte(input), Options{Arguments: map[string]string{"mode": "new"}})
	if n := len(result.HeaderRewrites); n != 4 {
		t.Fatalf("expected four header rewrites, got %d (%+v)", n, report)
	}
	for i, want := range []struct{ phase, op, name, pattern, value string }{
		{"request", "add", "X-Example", "", "two words"}, {"request", "del", "X-Old", "", ""},
		{"response", "replace", "X-Old", "", "empty"}, {"response", "replace-regex", "X-Test", "(one two)", "$1#"},
	} {
		rule := result.HeaderRewrites[i]
		if *rule.Phase != want.phase || rule.Op != want.op || rule.Name != want.name || rule.Pattern != nil && *rule.Pattern != want.pattern || rule.Value != nil && *rule.Value != want.value {
			t.Fatalf("incorrect header rule %+v", rule)
		}
	}
	if n := len(result.BodyRewrites); n != 4 {
		t.Fatalf("expected four body rewrites, got %d (%+v)", n, report)
	}
	body := result.BodyRewrites
	if body[0].Phase != "request" || len(body[0].Replace) != 2 || *body[0].Replace[0].Pattern != "x y" || *body[0].Replace[1].Value != "" || body[1].Phase != "response" ||
		*body[2].JQ != `.test = "new"` || *body[3].JQ != "del(.test)" {
		t.Fatalf("incorrect body rewrites %+v", body)
	}
	if !report.CanApply || !report.Partial || report.Rewrites != (Count{Total: 15, Imported: 8, Unavailable: 7}) {
		t.Fatal(report)
	}
}

func TestMapLocalAndInspect(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("X-Example:hello: world|X-Two:second"))
	input := `#!name=Example
#!arguments=Location:https://example.net/data
[Map Local]
^https://example\.com/one data-type=text data="hello world" header="X-Example:one|X-Two:two words" status-code=404
^https://example\.com/two data-type=json data="{\"ok\":true}" header=` + encoded + `
^https://example\.com/three data-type=base64 data=aGVsbG8=
^https://example\.com/four data-type=tiny-gif
^https://example\.com/five data={{{Location}}}
^https://example\.com/six data-type=json data={{{Location}}}
^https://example\.com/seven data-type=text data=https://example.net/other header="content-type:application/example"
^https://example\.com/eight data-type=text data=https://example.net/text
^https://example\.com/nine data-type=base64 data=https://example.net/base64
^https://example\.com/ten data-type=tiny-gif data=https://example.net/gif
^https://example\.com/local data=/tmp/never-read
^https://example\.com/link data=https://example.net/not-used header=not%base64
^https://example\.com/blocked data=https://example.net/not-used status-code=10
(?=x)^https://example\.com/bad data=https://example.net/not-used
`
	args := map[string]string{"Location": "https://example.net/overridden"}
	metadata, refs := Inspect([]byte(input), args)
	wantURLs := []string{"https://example.net/overridden", "https://example.net/other", "https://example.net/text", "https://example.net/base64", "https://example.net/gif"}
	if metadata.Name != "Example" || !slices.Equal(refs.MapLocal, wantURLs) {
		t.Fatalf("wrong URLs or metadata %+v, %+v", metadata, refs.MapLocal)
	}
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	result, report := Convert([]byte(input), Options{Arguments: args, Resource: func(url string) (string, bool) { return hash, slices.Contains(wantURLs, url) }})
	if !report.CanApply || !report.Partial || report.Rewrites != (Count{Total: 14, Imported: 10, Unavailable: 4}) || !reflect.DeepEqual(metadata, report.Metadata) {
		t.Fatalf("invalid report %+v", report)
	}
	for i, want := range []struct{ kind, data, header string }{
		{"text", "hello world", "one"}, {"json", `{"ok":true}`, "hello: world"}, {"base64", "aGVsbG8=", ""}, {"tiny-gif", "", ""},
		{"file", "", ""}, {"file", "", "application/json"}, {"file", "", "application/example"}, {"file", "", "text/plain"}, {"file", "", ""}, {"file", "", ""},
	} {
		rule := result.MapLocal[i]
		if *rule.DataType != want.kind || rule.Data != nil && *rule.Data != want.data || (rule.Hash != nil) != (i >= 4) || i >= 4 && *rule.Hash != hash || rule.Download != nil ||
			want.header != "" && (len(rule.Headers) == 0 || *rule.Headers[0].Value != want.header) {
			t.Fatalf("wrong response %d %+v", i, rule)
		}
	}
	if *result.MapLocal[0].StatusCode != 404 || *result.MapLocal[0].Headers[1].Value != "two words" {
		t.Fatal(result.MapLocal[0])
	}
	missing, report := Convert([]byte(input), Options{Arguments: args})
	if len(missing.MapLocal) != 4 || report.CanApply || len(report.Diagnostics) != 6 || report.Diagnostics[0].Code != "module.resource-missing" || report.Diagnostics[0].Line != 8 {
		t.Fatalf("missing resource errors were incorrect %+v", report)
	}
}

func TestStableIDs(t *testing.T) {
	const input = `[Rule]
DOMAIN,example.com,DIRECT
DOMAIN,EXAMPLE.COM.,direct
[URL Rewrite]
example\.com - reject
example\.com reject
[Header Rewrite]
example\.com header-del X-Example
http-request example\.com header-del x-example
[Body Rewrite]
http-response example\.com x y
http-response example\.com x y
[Map Local]
example\.com data=https://example.net/
example\.com data-type=file data=https://example.net/
`
	resource := func(hash byte) Options {
		return Options{Resource: func(string) (string, bool) { return strings.Repeat(string(hash), 64), true }}
	}
	one, _ := Convert([]byte(input), resource('a'))
	two, _ := Convert([]byte(strings.Replace(input, "DOMAIN,example.com,DIRECT", "DOMAIN,other.test,DIRECT\nDOMAIN,example.com,DIRECT", 1)), resource('b'))
	if len(one.ItemLines) != 10 || len(two.ItemLines) != 11 {
		t.Fatalf("unexpected items %+v, %+v", one, two)
	}
	for _, ids := range [][2]string{
		{one.Rules[0].ID, one.Rules[1].ID}, {one.HTTPRewrites[0].ID, one.HTTPRewrites[1].ID},
		{one.HeaderRewrites[0].ID, one.HeaderRewrites[1].ID}, {one.BodyRewrites[0].ID, one.BodyRewrites[1].ID},
		{one.MapLocal[0].ID, one.MapLocal[1].ID},
	} {
		if ids[1] != ids[0]+"-2" || two.ItemLines[ids[0]] != one.ItemLines[ids[0]]+1 || two.ItemLines[ids[1]] != one.ItemLines[ids[1]]+1 {
			t.Fatalf("unexpected IDs or lines for %+v", ids)
		}
	}
}

func FuzzConvert(f *testing.F) {
	for _, sample := range []string{
		"#!arguments=策略:DIRECT\n[Rule]\nDOMAIN,example.com,{{{策略}}}",
		"[Rule]\nNOT,((DOMAIN,example.com)),REJECT",
		"[MITM]\nhostname=%INSERT% -example.com,*:0",
		"[Body Rewrite]\nhttp-response-jq example\\.com '.example = \"test\"'",
		"[Map Local]\nexample\\.com data=\"https://example.net/\"", "\xff\xfe\x00",
	} {
		f.Add([]byte(sample))
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		if len(text) > 64<<10 {
			t.Skip()
		}
		args := map[string]string{"策略": "REJECT"}
		Inspect(text, args)
		Convert(text, Options{Arguments: args})
	})
}
