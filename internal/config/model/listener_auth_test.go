package model

import (
	"strings"
	"testing"
)

func TestListenerAuthenticationMaskRoundTripAndIdentity(t *testing.T) {
	input := []byte(`listeners: [{id: auth, type: mixed, listen: '127.0.0.1:17890', users: [{username: Alice, password: 'password-private'}]}]`)
	base, ds := LoadDoc(DocLocal, input)
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	masked, ds := LoadDoc(DocLocal, input)
	if ds.HasErrors() || masked.MaskSecrets() != 2 {
		t.Fatal(ds)
	}
	if strings.Contains(string(masked.Bytes()), "Alice") || strings.Contains(string(masked.Bytes()), "password-private") {
		t.Fatal("listener credentials were not masked")
	}
	if err := masked.UnmaskSecrets(base); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(masked.Bytes()), "password-private") {
		t.Fatal("masked listener password was not restored")
	}
	changed, ds := LoadDoc(DocLocal, []byte(strings.Replace(string(input), "username: Alice, password: 'password-private'", "username: Bob, password: '********'", 1)))
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if err := changed.UnmaskSecrets(base); err == nil {
		t.Fatal("a changed authentication identity reused another user's password")
	}
}

func TestListenerAuthenticationOverlayMask(t *testing.T) {
	input := []byte(`patches: [{op: set, path: /listeners/auth/users, value: [{username: Alice, password: password-private}]}]`)
	doc, ds := LoadDoc(DocOverlay, input)
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if doc.MaskSecrets() != 2 || strings.Contains(string(doc.Bytes()), "password-private") {
		t.Fatal("listener override leaked credentials")
	}
}
