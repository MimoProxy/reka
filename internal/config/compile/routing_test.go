package compile

import (
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

func TestRoutingBlockQUIC(t *testing.T) {
	for _, tt := range []struct {
		name, profile, local, want string
	}{
		{name: "omitted", want: "off"},
		{name: "empty", profile: "routing: {block-quic: \"\"}\n", want: "off"},
		{name: "off", profile: "routing: {block-quic: off}\n", want: "off"},
		{name: "proxy", profile: "routing: {block-quic: proxy}\n", want: "proxy"},
		{name: "all", profile: "routing: {block-quic: all}\n", want: "all"},
		{name: "local overrides profile", profile: "routing: {block-quic: all}\n", local: "routing: {block-quic: proxy}\n", want: "proxy"},
		{name: "local replaces whole routing object", profile: "routing: {block-quic: all}\n", local: "routing: {mode: direct}\n", want: "off"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			eff, ds := Compile([]byte("schema-version: 1\n"+tt.profile), []byte(tt.local), Options{})
			if ds.HasErrors() {
				t.Fatal(ds)
			}
			if got := eff.Routing.BlockQUIC; got != tt.want {
				t.Fatalf("block-quic = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRoutingBlockQUICRejectsInvalidValue(t *testing.T) {
	const invalid = "routing: {block-quic: invalid}\n"
	for _, tt := range []struct{ doc, profile, local string }{
		{doc: model.DocProfile, profile: invalid},
		{doc: model.DocLocal, local: invalid},
	} {
		t.Run(tt.doc, func(t *testing.T) {
			eff, ds := Compile([]byte("schema-version: 1\n"+tt.profile), []byte(tt.local), Options{})
			errs := ds.Errors()
			if eff != nil || len(errs) != 1 {
				t.Fatalf("effective config = %v, diagnostics = %v", eff, ds)
			}
			if d := errs[0]; d.Document != tt.doc || d.Path != "/routing/block-quic" || d.Code != "routing.block-quic" {
				t.Fatalf("unexpected diagnostic: %+v", d)
			}
		})
	}
}
