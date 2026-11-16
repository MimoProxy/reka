package compile

import "testing"

func TestProcessCollectionModesAndLocalOverride(t *testing.T) {
	eff, ds := Compile([]byte("schema-version: 1\n"), nil, Options{})
	if ds.HasErrors() || eff.Process.Mode != "rule" {
		t.Fatal(eff, ds)
	}
	for _, mode := range []string{"off", "rule", "always"} {
		eff, ds = Compile([]byte("schema-version: 1\nprocess: {mode: always}\n"), []byte("process: {mode: "+mode+"}\n"), Options{})
		if ds.HasErrors() || eff.Process.Mode != mode {
			t.Fatal(eff, ds)
		}
		if origin, ok := eff.OriginOf("/process/mode"); !ok || origin.Layer != LayerLocal {
			t.Fatal(origin)
		}
	}
	if _, ds := Compile([]byte("schema-version: 1\nprocess: {mode: invent}\n"), nil, Options{}); !ds.HasErrors() {
		t.Fatal("invalid collection mode accepted")
	}
}
