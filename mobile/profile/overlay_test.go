package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

func TestPrepareClashOverlayAcrossRefresh(t *testing.T) {
	const initial = `
proxies:
  - {name: Removable, type: direct}
  - {name: Alternate, type: socks5, server: first.example.test, port: 1080}
  - {name: Default, type: direct}
proxy-groups:
  - {name: Choice, type: select, proxies: [Default, Alternate, Removable]}
rules:
  - DOMAIN,removed.example.test,REJECT
  - DOMAIN,kept.example.test,Choice
  - MATCH,DIRECT
`
	const refreshed = `
proxies:
  - {name: Default, type: direct}
  - {name: Alternate, type: socks5, server: second.example.test, port: 2080}
proxy-groups:
  - {name: Choice, type: select, proxies: [Default, Alternate]}
rules:
  - DOMAIN,kept.example.test,Choice
  - DOMAIN,removed.example.test,REJECT
  - MATCH,DIRECT
`
	base, err := prepare(t.Context(), []byte(initial), nil)
	if err != nil {
		t.Fatal(err)
	}
	eff, err := base.Compile()
	if err != nil {
		t.Fatal(err)
	}
	removeRule, keepRule, finalRule := eff.RuleIDs[0], eff.RuleIDs[1], eff.RuleIDs[2]
	idFor := func(name string) string {
		t.Helper()
		for id, label := range base.Summary.Names {
			if label == name {
				return id
			}
		}
		t.Fatalf("missing name %q", name)
		return ""
	}
	removable, alternate, choice := idFor("Removable"), idFor("Alternate"), idFor("Choice")
	var options PrepareOptions
	if err := json.Unmarshal(fmt.Appendf(nil, `{"overlay":{"schema-version":1,"patches":[
		{"op":"set","path":"/outbounds/%s/name","value":"Renamed"},
		{"op":"set","path":"/groups/%s/selected","value":"%s"},
		{"op":"remove","path":"/rules/%s"},
		{"op":"insert","path":"/rules","before":"%s","value":{"id":"custom","match":{"domain":"added.example.test"},"outbound":"reject"}}
	]}}`, removable, choice, alternate, removeRule, finalRule), &options); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "source.yaml")
	materialize := func(raw, name string, options PrepareOptions) (*Bundle, string) {
		t.Helper()
		if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		snapshot := filepath.Join(dir, name)
		if err := PrepareFileWithOptions(t.Context(), input, snapshot, dir, options); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		return bundle, snapshot
	}
	checkCompiled := func(bundle *Bundle, port uint16) {
		t.Helper()
		eff, err := bundle.Compile()
		if err != nil {
			t.Fatal(err)
		}
		info := Describe(eff)
		if info.Names[removable] != bundle.Summary.Names[removable] || bundle.Summary.Rules != 3 {
			t.Fatalf("compiled snapshot differs from the prepared summary: %+v", info)
		}
		if out, ok := eff.Outbound(alternate); !ok || out.Port != port {
			t.Fatal("surviving node ID did not track the refreshed endpoint")
		}
		if !slices.Equal(eff.RuleIDs, []string{keepRule, "custom", finalRule}) {
			t.Fatalf("unexpected rule IDs or order: %v", eff.RuleIDs)
		}
		for _, summary := range []Summary{bundle.Summary, info} {
			if i := slices.IndexFunc(summary.Groups, func(g Group) bool { return g.ID == choice }); i < 0 || summary.Groups[i].Selected != alternate {
				t.Fatalf("group selection was not applied: %+v", summary.Groups)
			}
		}
		updated, err := ApplyControls(eff, info, Controls{Mode: "rule"})
		if err != nil {
			t.Fatal(err)
		}
		for domain, target := range map[string]string{
			"kept.example.test": alternate, "removed.example.test": "direct", "added.example.test": "reject",
		} {
			if decision := updated.Router.Route(t.Context(), router.Metadata{Domain: domain}, nil); decision.Outbound != target {
				t.Fatalf("route for %s: got %q, want %q", domain, decision.Outbound, target)
			}
		}
	}
	first, _ := materialize(initial, "first.json", options)
	checkPatchStatuses(t, first.Summary.Patches, "", "", "", "")
	if first.Summary.Names[removable] != "Renamed" {
		t.Fatalf("missing renamed node: %+v", first.Summary.Names)
	}
	checkCompiled(first, 1080)

	next, snapshot := materialize(refreshed, "refresh.json", options)
	checkPatchStatuses(t, next.Summary.Patches, "overlay.path", "", "", "")
	if _, exists := next.Summary.Names[removable]; exists {
		t.Fatal("removed node is still present")
	}
	checkCompiled(next, 2080)

	restored, _ := materialize(initial, "restored.json", PrepareOptions{RebindSnapshot: snapshot})
	if !bytes.Equal(restored.Overlay, next.Overlay) || !slices.Equal(restored.Summary.Patches, next.Summary.Patches) {
		t.Fatalf("restore changed the overlay or patch statuses: %+v", restored.Summary.Patches)
	}
	checkCompiled(restored, 2080)
}

func TestPrepareOverlaySkipsInvalidChanges(t *testing.T) {
	const raw = `schema-version: 1
outbounds:
  - {id: first, type: direct}
  - {id: second, type: direct}
groups:
  - {id: choice, type: select, members: [first, second], selected: first}
`
	p := &preparer{options: PrepareOptions{Overlay: json.RawMessage(`{"schema-version":1,"patches":[
		{"op":"set","path":"/groups/choice/selected","value":"missing"},
		{"op":"remove","path":"/outbounds/first"},
		{"op":"set","path":"/outbounds/first/name","value":"Kept"},
		{"op":"set","path":"/dns/listen","value":"127.0.0.1:5353"},
		{"op":"set","path":"/dns/cache-size","value":256}
	]}`)}}
	bundle, err := prepare(t.Context(), []byte(raw), p)
	if err != nil {
		t.Fatal(err)
	}
	checkPatchStatuses(t, bundle.Summary.Patches, "group.selected", "group.member", "", "ios.dns-limit", "")
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if node, ok := eff.Outbound("first"); !ok || node.Name != "Kept" || eff.Groups[0].Selected != "first" {
		t.Fatalf("an invalid patch affected compilation: %+v", Describe(eff))
	}
	if eff.DNS.Listen != "" || eff.DNS.CacheSize != 256 {
		t.Fatal("overlay did not respect the packet tunnel DNS limits")
	}
}

func TestPrepareOverlayKeepsRelatedEditsWhenTargetDisappears(t *testing.T) {
	const raw = `schema-version: 1
outbounds:
  - {id: removable, type: direct}
  - {id: remaining, type: direct}
groups:
  - {id: choice, type: select, members: [removable, remaining], selected: removable}
`
	p := &preparer{options: PrepareOptions{Overlay: json.RawMessage(`{"schema-version":1,"patches":[
		{"op":"remove","path":"/outbounds/removable"},
		{"op":"set","path":"/outbounds/absent/name","value":"Renamed"},
		{"op":"set","path":"/groups/choice/members","value":["remaining"]},
		{"op":"set","path":"/groups/choice/selected","value":"remaining"}
	]}`)}}
	bundle, err := prepare(t.Context(), []byte(raw), p)
	if err != nil {
		t.Fatal(err)
	}
	checkPatchStatuses(t, bundle.Summary.Patches, "", "overlay.path", "", "")
	if bundle.Summary.Nodes != 1 || bundle.Summary.Groups[0].Selected != "remaining" {
		t.Fatalf("related edits were lost: %+v", bundle.Summary)
	}
}

func TestPrepareOverlayRejectsNestedIdentityChanges(t *testing.T) {
	const raw = `schema-version: 1
dns:
  nameserver: [system]
  hosts: [{id: host.example.test, addresses: [192.0.2.1]}]
`
	p := &preparer{options: PrepareOptions{Overlay: json.RawMessage(`{"schema-version":1,"patches":[
		{"op":"set","path":"/dns/hosts/host.example.test/id","value":"changed.example.test"},
		{"op":"set","path":"/dns/hosts/host.example.test/addresses","value":["192.0.2.2"]}
	]}`)}}
	bundle, err := prepare(t.Context(), []byte(raw), p)
	if err != nil {
		t.Fatal(err)
	}
	checkPatchStatuses(t, bundle.Summary.Patches, "overlay.path", "")
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if hosts := eff.DNS.Hosts; len(hosts) != 1 || hosts[0].ID != "host.example.test" || !slices.Equal(hosts[0].Addresses, []string{"192.0.2.2"}) {
		t.Fatalf("unexpected hosts after rejected edit: %+v", hosts)
	}
}

func TestPrepareFileRejectsMalformedOverlay(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "source.yaml"), filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(input, []byte("schema-version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, overlay, code string }{
		{"malformed JSON", `{"schema-version":1,"patches":[`, "overlay.json"},
		{"valid YAML", `schema-version: 1`, "overlay.json"},
		{"invalid patch list", `{"schema-version":1,"patches":{}}`, "yaml.type"},
		{"unsupported version", `{"schema-version":2,"patches":[]}`, "schema.version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := PrepareFileWithOptions(t.Context(), input, output, dir, PrepareOptions{Overlay: json.RawMessage(tc.overlay)})
			var validation *ValidationError
			if !errors.As(err, &validation) || !slices.ContainsFunc(validation.Diagnostics, func(d model.Diagnostic) bool {
				return d.Document == model.DocOverlay && d.Code == tc.code
			}) {
				t.Fatalf("expected overlay validation error: %v (%+v)", err, validation)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid overlay wrote a snapshot: %v", err)
			}
		})
	}
}

func TestDecodeLegacyBundleWithoutOverlay(t *testing.T) {
	bundle, err := Decode([]byte(`{"version":1,"profile":{"schema-version":1,"outbounds":[{"id":"legacy","type":"direct"}]},"summary":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Overlay != nil || bundle.Summary.Patches != nil || eff.Final != NodeGroup {
		t.Fatal("legacy snapshot did not retain the default node selector")
	}
}

func checkPatchStatuses(t *testing.T, statuses []PatchStatus, reasons ...string) {
	t.Helper()
	if len(statuses) != len(reasons) {
		t.Fatalf("got patch statuses %+v, want %d statuses", statuses, len(reasons))
	}
	for i, reason := range reasons {
		status := statuses[i]
		if status.Index != i || status.Applied != (reason == "") ||
			reason == "" && status.Reason != "" || !strings.Contains(status.Reason, reason) {
			t.Fatalf("status at %d: %+v, want reason %q", i, status, reason)
		}
	}
}
