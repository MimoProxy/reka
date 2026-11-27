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
		{name: "per-policy", profile: "routing: {block-quic: per-policy}\n", want: "per-policy"},
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

func TestRoutingFallbackOptions(t *testing.T) {
	eff, ds := Compile([]byte(`schema-version: 1
routing: {udp-fallback: direct, dns-failure: final}
outbounds:
  - {id: node, type: socks, server: 127.0.0.1, port: 9, block-quic: true}
`), nil, Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if eff.Routing.UDPFallback != "direct" || eff.Routing.DNSFailure != "final" || !eff.Outbounds[0].BlockQUIC {
		t.Fatalf("routing = %+v, outbound = %+v", eff.Routing, eff.Outbounds[0])
	}
	for _, tt := range []struct{ profile, path string }{
		{"routing: {udp-fallback: proxy}\n", "/routing/udp-fallback"},
		{"routing: {dns-failure: drop}\n", "/routing/dns-failure"},
	} {
		eff, ds := Compile([]byte("schema-version: 1\n"+tt.profile), nil, Options{})
		if errs := ds.Errors(); eff != nil || len(errs) != 1 || errs[0].Path != tt.path {
			t.Fatalf("%s: diagnostics = %v", tt.profile, ds)
		}
	}
}
