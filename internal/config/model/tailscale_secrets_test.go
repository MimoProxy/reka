package model

import (
	"strings"
	"testing"
)

func TestTailscaleAuthKeyMask(t *testing.T) {
	const path = "/link/tailscale/home/auth-key"
	const local = "link: {tailscale: [{id: home, auth-key: private-key}]}\n"
	load := func(s string) *Doc {
		t.Helper()
		doc, diags := LoadDoc(DocLocal, []byte(s))
		if diags.HasErrors() {
			t.Fatal(diags)
		}
		return doc
	}
	base, masked := load(local), load(local)
	if !IsSensitive(path) || IsSensitive("/link/tailscale/home/hostname") || masked.MaskSecrets() != 1 || masked.Get(path).Value != Mask {
		t.Fatal("inline Tailscale auth key was not masked")
	}
	if err := masked.UnmaskSecrets(base); err != nil || string(masked.Bytes()) != string(base.Bytes()) {
		t.Fatal("masked Tailscale auth key was not restored", err)
	}
	ref := load(strings.Replace(local, "private-key", "secret://tailscale/auth", 1))
	if ref.MaskSecrets() != 0 || ref.Get(path).Value != "secret://tailscale/auth" {
		t.Fatal("Tailscale auth key reference should remain visible")
	}
	changed := load("link: {tailscale: [{id: other, auth-key: '********'}]}\n")
	if err := changed.UnmaskSecrets(base); err == nil {
		t.Fatal("masked auth key was restored for a different Tailscale link")
	}
}
