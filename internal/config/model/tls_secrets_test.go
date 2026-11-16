package model

import (
	"strings"
	"testing"
)

func TestTLSIdentityMaskedInProfileSourceAndOverlay(t *testing.T) {
	for _, sample := range []struct {
		kind  string
		input string
	}{
		{DocProfile, "schema-version: 1\noutbounds: [{id: node, type: http, tls: {certificate: certificate-private, private-key: private-material}}]"},
		{DocSources, "schema-version: 1\nsources: [{id: airport, outbounds: [{id: node, type: http, tls: {certificate: certificate-private, private-key: private-material}}]}]"},
		{DocOverlay, "schema-version: 1\npatches: [{op: set, path: /outbounds/node/tls/private-key, value: private-material}, {op: set, path: /outbounds/node/tls, value: {certificate: certificate-private, private-key: private-material}}]"},
	} {
		doc, ds := LoadDoc(sample.kind, []byte(sample.input))
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		original, _ := LoadDoc(sample.kind, []byte(sample.input))
		if n := doc.MaskSecrets(); n < 2 {
			t.Fatal("TLS secrets not masked", n)
		}
		if b := string(doc.Bytes()); strings.Contains(b, "certificate-private") || strings.Contains(b, "private-material") {
			t.Fatal("client identity leaked")
		}
		if err := doc.UnmaskSecrets(original); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(doc.Bytes()), "private-material") {
			t.Fatal("masked client identity lost")
		}
	}
}
