package model

import (
	"bytes"
	"testing"
)

func FuzzDocuments(f *testing.F) {
	for _, s := range []string{sample, "schema-version: 1\nrules: [{match: {all: true}, outbound: direct}]", "network: {mode: off}", "patches: []", "schema-version: 1\nsources: []", "schema-version: 1\nrules: &a [*a]"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			t.Skip()
		}
		for _, doc := range []string{DocProfile, DocLocal, DocSources, DocOverlay} {
			var ds Diagnostics
			switch doc {
			case DocProfile:
				_, _, ds = ParseProfile(b)
			case DocLocal:
				_, _, ds = ParseLocal(b)
			case DocSources:
				_, _, ds = ParseSources(b)
			case DocOverlay:
				_, _, ds = ParseOverlay(b)
			}
			if ds.HasErrors() {
				continue
			}
			d, ds := LoadDoc(doc, b)
			if ds.HasErrors() {
				t.Fatal(ds)
			}
			one := d.Bytes()
			d2, ds := LoadDoc(doc, one)
			if ds.HasErrors() || !bytes.Equal(one, d2.Bytes()) {
				t.Fatalf("canonical form unstable: %s", doc)
			}
		}
	})
}
