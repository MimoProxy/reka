package importer

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	VE "github.com/MimoProxy/reka/internal/compat/vlessenc"
	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestClashEncryptedVLESSVisionImportMaskAndFingerprint(t *testing.T) {
	_, public, _, err := VE.GenX25519("")
	if err != nil {
		t.Fatal(err)
	}
	encrypted := "mlkem768x25519plus.native.0rtt." + public + ".100-35-35"
	data := fmt.Sprintf(`proxies: [{name: node, type: vless, server: node.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, encryption: %q, flow: xtls-rprx-vision, network: ws, ws-opts: {path: /encrypted}}]`, encrypted)
	r := Import(request(data))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	eff := compileImport(t, r)
	out := eff.Outbounds[0]
	if out.Encryption != encrypted || out.TLS != nil || out.Transport.Type != "ws" {
		t.Fatal("encrypted Vision transport changed")
	}
	if strings.Contains(r.Preview(false).Sources, public) {
		t.Fatal("encryption keys exposed in preview")
	}
	serialized, _ := json.Marshal(eff)
	if strings.Contains(string(serialized), public) {
		t.Fatal("effective output exposed encryption keys")
	}
	_, next, _, _ := VE.GenX25519("")
	updated := Import(request(strings.Replace(data, public, next, 1)))
	after := compileImport(t, updated)
	if after.Outbounds[0].Fingerprint == out.Fingerprint {
		t.Fatal("encryption edit reused old transport")
	}
	if Import(request(strings.Replace(data, encrypted, "none", 1))).Report.CanApply {
		t.Fatal("Vision over unencrypted WS accepted")
	}
	if Import(request(strings.Replace(data, encrypted, "bad-encryption", 1))).Report.CanApply {
		t.Fatal("malformed encryption accepted")
	}
	// Native compilation must resolve encryption references before validating
	// and fingerprinting; the missing reference remains an explicit diagnostic.
	_, ds := compile.Compile([]byte("schema-version: 1\noutbounds: [{id: node, type: vless, server: node.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, encryption: 'secret://missing'}]"), nil, compile.Options{})
	if !ds.HasErrors() {
		t.Fatal("unresolved encryption reference accepted")
	}
}
