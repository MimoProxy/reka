package appbridge

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/mobile/profile"
	"software.sslmate.com/src/go-pkcs12"
)

func TestMITMCAOperations(t *testing.T) {
	var stored, scratch []byte
	var writes int
	store := KeychainStore{
		Read: func(name string, output []byte) int {
			if name != ca.SecretName {
				return -1
			}
			return copy(output, stored)
		},
		Write: func(name string, value []byte) bool {
			if name != ca.SecretName {
				return false
			}
			writes++
			stored = bytes.Clone(value)
			scratch = value
			return true
		},
	}
	bridge := New(store)
	send := func(input string) []byte {
		t.Helper()
		return appReply(t, bridge, []byte(input))
	}
	if result := send(`{"action":"mitmCAStatus"}`); string(result) != `{"installed":false}` {
		t.Fatalf("unexpected uninstalled status: %s", result)
	}
	assertAppError(t, send(`{"action":"mitmCAExport"}`), "not_found")

	generate := []byte(`{"action":"mitmCAGenerate","replace":true}`)
	required := bridge.WriteResponse(generate, nil)
	if required >= 0 || writes != 1 {
		t.Fatal("a size request must generate the CA once")
	}
	reply := make([]byte, -required)
	if n := bridge.WriteResponse(generate, reply); n != -required || writes != 1 {
		t.Fatal("the retry did not replay the generation result")
	}
	for _, b := range scratch {
		if b != 0 {
			t.Fatal("the temporary write buffer was not cleared")
		}
	}
	generated := appResult[api.MITMCAStatus](t, reply)
	if !generated.Installed || generated.FingerprintSHA256 == "" {
		t.Fatal("missing generated CA details")
	}
	assertAppError(t, send(`{"action":"mitmCAGenerate"}`), "conflict")

	certPEM, rest := pem.Decode(stored)
	keyPEM, _ := pem.Decode(rest)
	if certPEM == nil || keyPEM == nil || keyPEM.Type != "PRIVATE KEY" {
		t.Fatal("the writer did not receive the full CA")
	}
	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyPEM.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	const password = "test-password"
	p12, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	replacement := appResult[api.MITMCAStatus](t, send(string(generate)))
	if generated.FingerprintSHA256 == replacement.FingerprintSHA256 {
		t.Fatal("replace kept the old CA")
	}
	p12Base64 := base64.StdEncoding.EncodeToString(p12)
	importRequest, err := json.Marshal(map[string]any{
		"action": "mitmCAImport", "pkcs12": p12Base64, "password": password, "replace": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	importReply := appReply(t, bridge, importRequest)
	if bytes.Contains(importReply, []byte(password)) || bytes.Contains(importReply, []byte(p12Base64)) {
		t.Fatal("import returned a credential")
	}
	imported := appResult[api.MITMCAStatus](t, importReply)
	if !imported.Installed || imported.FingerprintSHA256 != generated.FingerprintSHA256 {
		t.Fatal("import did not restore the original CA")
	}
	if status := appResult[api.MITMCAStatus](t, send(`{"action":"mitmCAStatus"}`)); status != imported {
		t.Fatal("stored status differs from import result")
	}

	pemExport := appResult[api.ExportMITMCAResult](t, send(`{"action":"mitmCAExport","format":"pem"}`))
	block, rest := pem.Decode([]byte(pemExport.Data))
	if pemExport.Format != "pem" || pemExport.FingerprintSHA256 != imported.FingerprintSHA256 ||
		block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || !bytes.Equal(block.Bytes, cert.Raw) {
		t.Fatal("PEM export must contain only the CA certificate")
	}
	derExport := appResult[api.ExportMITMCAResult](t, send(`{"action":"mitmCAExport","format":"der"}`))
	der, err := base64.StdEncoding.DecodeString(derExport.Data)
	if err != nil || derExport.Format != "der" || derExport.FingerprintSHA256 != imported.FingerprintSHA256 ||
		!bytes.Equal(der, cert.Raw) {
		t.Fatal("DER export must contain only the CA certificate")
	}

	probe := appResult[trustProbe](t, send(`{"action":"mitmCATrustProbe"}`))
	leaf, err := x509.ParseCertificate(probe.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if probe.Hostname != trustProbeHostname || !bytes.Equal(probe.CADER, cert.Raw) ||
		leaf.NotAfter.After(time.Now().Add(trustProbeValidity)) {
		t.Fatal("invalid trust probe response")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: probe.Hostname}); err != nil {
		t.Fatal(err)
	}

	if got := appResult[api.DeleteMITMCAResult](t, send(`{"action":"mitmCADelete"}`)); !got.Deleted || stored != nil {
		t.Fatal("CA was not removed by the writer")
	}
	assertAppError(t, send(`{"action":"mitmCADelete"}`), "not_found")
	assertAppError(t, send(`{"action":"mitmCATrustProbe"}`), "not_found")
	if result := send(`{"action":"mitmCAStatus"}`); string(result) != `{"installed":false}` {
		t.Fatalf("unexpected deleted status: %s", result)
	}
}

func TestAppOperationInput(t *testing.T) {
	bridge := New(nil)
	for _, input := range [][]byte{nil, []byte(`{`), make([]byte, MaxInputBytes+1)} {
		assertAppError(t, appReply(t, bridge, input), "bad_request")
	}
	assertAppError(t, appReply(t, bridge, []byte(`{"action":"unknown"}`)), api.CodeUnknownMethod)
	assertAppError(t, appReply(t, bridge, []byte(`{"action":"mitmCAStatus"}`)), api.CodeInternal)
}

func TestAppModuleOperations(t *testing.T) {
	bridge := New(nil)
	send := func(action string, fields map[string]any) []byte {
		t.Helper()
		fields["action"] = action
		input, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return appReply(t, bridge, input)
	}
	dir := t.TempDir()
	moduleFile := filepath.Join(dir, "example.sgmodule")
	moduleSnapshot := filepath.Join(dir, "module.json")
	profileFile := filepath.Join(dir, "profile.yaml")
	profileSnapshot := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(moduleFile, []byte(`#!name=Example Module
[MITM]
hostname = %APPEND% module.example.test
[Script]
unsupported = type=http-request
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profileFile, fmt.Appendf(nil, "schema-version: 1\nmodules: [{id: example, file: %q}]\n", moduleFile), 0o600); err != nil {
		t.Fatal(err)
	}
	acquired := appResult[profile.ModuleAcquireResult](t, send("moduleAcquire", map[string]any{
		"module": model.Module{ID: "example", File: moduleFile}, "outputSnapshot": moduleSnapshot,
	}))
	if acquired.Status != "updated" || acquired.Metadata == nil || acquired.Metadata.Name != "Example Module" {
		t.Fatalf("unexpected acquisition result: %+v", acquired)
	}
	metadata := appResult[module.Metadata](t, send("moduleInspect", map[string]any{"snapshot": moduleSnapshot}))
	if metadata.Name != "Example Module" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	preview := appResult[profile.ModulePreviewResult](t, send("modulePreview", map[string]any{"snapshot": moduleSnapshot}))
	if !preview.Report.Partial || !slices.Equal(preview.Hostnames.Append, []string{"module.example.test"}) {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	opts := profile.PrepareOptions{Modules: map[string]string{"example": moduleSnapshot}}
	if err := profile.PrepareFileWithOptions(t.Context(), profileFile, profileSnapshot, dir, opts); err != nil {
		t.Fatal(err)
	}
	report := appResult[module.Report](t, send("moduleReport", map[string]any{"snapshot": profileSnapshot, "moduleId": "example"}))
	if report.ModuleID != "example" || !report.Partial || len(report.Lines) == 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
	assertAppError(t, send("moduleReport", map[string]any{"snapshot": profileSnapshot, "moduleId": "absent"}), "not_found")
}

func appReply(t *testing.T, bridge *Bridge, input []byte) []byte {
	t.Helper()
	output := make([]byte, 4096)
	n := bridge.WriteResponse(input, output)
	if n < 0 {
		output = make([]byte, -n)
		n = bridge.WriteResponse(input, output)
	}
	if n <= 0 {
		t.Fatal("operation did not return a JSON response")
	}
	output = output[:n]
	if bytes.Contains(output, []byte("PRIVATE KEY")) {
		t.Fatal("response contains a private key marker")
	}
	return output
}

func appResult[T any](t *testing.T, data []byte) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertAppError(t *testing.T, data []byte, code string) {
	t.Helper()
	if got := appResult[errorResponse](t, data).Error; got.Code != code || got.Message == "" {
		t.Fatalf("expected %q error, got %s", code, data)
	}
}
