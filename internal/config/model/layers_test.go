package model

import (
	"strings"
	"testing"
)

func TestLayerMasksAndAliases(t *testing.T) {
	cases := []struct{ name, data string }{
		{DocSources, `sources:
 - id: sub
   outbounds:
    - {id: first, type: socks, username: test-user, password: &pw test-password}
    - {id: second, type: socks, username: test-user, password: *pw}
`},
		{DocOverlay, `patches:
 - {op: set, path: /outbounds/sub~1first/password, value: &pw test-password}
 - {op: set, path: /outbounds/sub~1second/password, value: *pw}
 - {op: set, path: /outbounds/sub~1first, value: {id: sub/first, username: test-user, password: test-password}}
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, ds := LoadDoc(tc.name, []byte(tc.data))
			if ds.HasErrors() {
				t.Fatal(ds)
			}
			doc, ds := LoadDoc(tc.name, []byte(tc.data))
			if ds.HasErrors() {
				t.Fatal(ds)
			}
			if doc.MaskSecrets() == 0 || strings.Contains(string(doc.Bytes()), "test-password") || strings.Contains(string(doc.Bytes()), "test-user") {
				t.Fatal("credentials not masked")
			}
			if err := doc.UnmaskSecrets(base); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(doc.Bytes()), "test-password") {
				t.Fatal("credentials not restored")
			}
		})
	}
	base, _ := LoadDoc(DocOverlay, []byte("patches: [{op: set, path: /outbounds/sub~1first/password, value: original}]"))
	changed, _ := LoadDoc(DocOverlay, []byte("patches: [{op: set, path: /outbounds/sub~1second/password, value: '********'}]"))
	if err := changed.UnmaskSecrets(base); err == nil {
		t.Fatal("mask copied another node's secret")
	}
}

func TestSubscriptionMasksKeepHeaderIdentity(t *testing.T) {
	base, _ := LoadDoc(DocSources, []byte("sources: [{id: sub, subscription: {url: 'https://sub.example?token=private', headers: [{name: X-First, value: first-private},{name: X-Second, value: second-private}]}}]"))
	masked, _ := LoadDoc(DocSources, base.Bytes())
	if masked.MaskSecrets() != 3 {
		t.Fatal("URL/header masks missing")
	}
	if strings.Contains(string(masked.Bytes()), "private") {
		t.Fatal("subscription credential leaked")
	}
	if err := masked.UnmaskSecrets(base); err != nil {
		t.Fatal(err)
	}
	masked, _ = LoadDoc(DocSources, []byte("sources: [{id: sub, subscription: {url: '********', headers: [{name: X-Second, value: '********'},{name: X-First, value: '********'}]}}]"))
	if err := masked.UnmaskSecrets(base); err == nil {
		t.Fatal("reordered header copied another credential")
	}
}
