package compile

import (
	"strings"
	"testing"
)

func TestDetourFingerprintTracksWholeParentGraph(t *testing.T) {
	const input = `schema-version: 1
outbounds:
 - {id: child, name: Child, type: direct, dialer: {proxy: hop}}
 - {id: a, type: shadowsocks, server: a.test, port: 443, method: aes-128-gcm, password: first}
 - {id: b, type: direct}
groups: [{id: hop, type: select, members: [a,b], selected: b}]
rules: [{match: {all: true}, outbound: child}]
`
	get := func(input string) *Effective {
		t.Helper()
		eff, ds := Compile([]byte(input), nil, Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		return eff
	}
	base := get(input)
	child, _ := base.Outbound("child")
	for _, tc := range []struct {
		from, to string
		replaced bool
	}{
		{"name: Child", "name: Renamed", false},
		{"password: first", "password: second", true}, // unselected parents are dependencies too.
		{"selected: b", "selected: a", true},
		{"members: [a,b]", "members: [b]", true},
		{"all: true", "network: tcp", false},
	} {
		eff := get(strings.Replace(input, tc.from, tc.to, 1))
		next, _ := eff.Outbound("child")
		if (next.Fingerprint != child.Fingerprint) != tc.replaced {
			t.Fatalf("replacement for %s: %v", tc.from, !tc.replaced)
		}
	}
	_, ds := Compile([]byte(strings.Replace(input, "{id: b, type: direct}", "{id: b, type: direct, dialer: {proxy: child}}", 1)), nil, Options{})
	if !ds.HasErrors() {
		t.Fatal("cycle through an unselected group member accepted")
	}
}
