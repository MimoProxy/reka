package control

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/secret"
	"software.sslmate.com/src/go-pkcs12"
)

func TestMITMCAControlRoundTrip(t *testing.T) {
	store, err := secret.NewFileStore(filepath.Join(t.TempDir(), "secrets.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var response []byte
	svc, call := testSessionWithObserver(t, store, func(frame []byte) { response = frame })
	var forbidden []string
	var id uint64 = 2
	send := func(method string, params any, code string) Message {
		t.Helper()
		payload, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		reply := call(t, Request{ID: id, Method: method, Params: payload})
		id++
		assertNoMITMCASecrets(t, method, response, forbidden)
		if code == "" && reply.Error != nil || code != "" && (reply.Error == nil || reply.Error.Code != code) {
			t.Fatalf("%s did not return expected error code %q", method, code)
		}
		return reply
	}
	if reply := send("GetMITMCA", nil, ""); string(reply.Result) != `{"installed":false}` {
		t.Fatal("expected an uninstalled status")
	}
	send("ExportMITMCA", nil, service.CodeNotFound)
	send("DeleteMITMCA", nil, service.CodeNotFound)

	generated := mitmCATestResult[api.MITMCAStatus](t, send("GenerateMITMCA", nil, ""))
	cert, key, keyMarkers := mitmCATestKey(t, store)
	forbidden = append(forbidden, keyMarkers...)
	assertNoMITMCASecrets(t, "GenerateMITMCA", response, forbidden)
	if !generated.Installed || generated.Expired || generated.Ref != secret.Ref(ca.SecretName) ||
		generated.Subject != cert.Subject.CommonName || generated.KeyType != "ECDSA P-256" ||
		generated.SerialNumber == "" || generated.FingerprintSHA256 == "" ||
		!generated.NotBefore.Equal(cert.NotBefore) || !generated.NotAfter.Equal(cert.NotAfter) {
		t.Fatal("invalid generated CA status")
	}
	if reply := send("GenerateMITMCA", nil, service.CodeConflict); !strings.Contains(reply.Error.Message, "replace:true") {
		t.Fatal("generation conflict did not describe how to replace the CA")
	}

	const password = "test-pkcs12-password"
	p12, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(p12)
	forbidden = append(forbidden, password, encoded[:64], "test-invalid-base64!")
	request := api.ImportMITMCARequest{PKCS12: encoded, Password: password}
	if reply := send("ImportMITMCA", request, service.CodeConflict); !strings.Contains(reply.Error.Message, "replace:true") {
		t.Fatal("import conflict did not describe how to replace the CA")
	}
	request.Replace = true
	request.Password = "test-incorrect-password"
	forbidden = append(forbidden, request.Password)
	send("ImportMITMCA", request, service.CodeBadRequest)
	send("ImportMITMCA", api.ImportMITMCARequest{PKCS12: "test-invalid-base64!", Password: password, Replace: true}, service.CodeBadRequest)
	if got := mitmCATestResult[api.MITMCAStatus](t, send("GetMITMCA", nil, "")); got.FingerprintSHA256 != generated.FingerprintSHA256 {
		t.Fatal("failed import changed the CA")
	}

	replacement := mitmCATestResult[api.MITMCAStatus](t, send("GenerateMITMCA", api.GenerateMITMCARequest{Replace: true}, ""))
	_, _, replacementMarkers := mitmCATestKey(t, store)
	forbidden = append(forbidden, replacementMarkers...)
	assertNoMITMCASecrets(t, "GenerateMITMCA", response, forbidden)
	if replacement.FingerprintSHA256 == generated.FingerprintSHA256 {
		t.Fatal("generation did not replace the CA")
	}
	request.PKCS12 = " \n" + encoded[:64] + "\r\n" + encoded[64:] + "\n\t"
	request.Password = password
	imported := mitmCATestResult[api.MITMCAStatus](t, send("ImportMITMCA", request, ""))
	if imported.FingerprintSHA256 != generated.FingerprintSHA256 || !imported.Installed {
		t.Fatal("import did not replace the CA")
	}
	if got := mitmCATestResult[api.MITMCAStatus](t, send("GetMITMCA", nil, "")); got != imported {
		t.Fatal("stored CA status differs from import result")
	}

	for _, format := range []string{"pem", "der"} {
		var params any
		if format == "der" {
			params = api.ExportMITMCARequest{Format: format}
		}
		export := mitmCATestResult[api.ExportMITMCAResult](t, send("ExportMITMCA", params, ""))
		if export.Format != format || export.FingerprintSHA256 != imported.FingerprintSHA256 {
			t.Fatal("unexpected CA export metadata")
		}
		if format == "pem" {
			block, rest := pem.Decode([]byte(export.Data))
			if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Bytes, cert.Raw) {
				t.Fatal("PEM export must contain exactly the CA certificate")
			}
		} else if der, err := base64.StdEncoding.DecodeString(export.Data); err != nil || !bytes.Equal(der, cert.Raw) {
			t.Fatal("DER export must contain exactly the CA certificate")
		}
	}
	send("ExportMITMCA", api.ExportMITMCARequest{Format: "pkcs12"}, service.CodeBadRequest)

	for _, method := range []string{"SetSecret", "DeleteSecret"} {
		reply := send(method, map[string]any{"name": ca.SecretName, "value": "replacement", "apply": false}, service.CodeBadRequest)
		if !strings.Contains(reply.Error.Message, "MITMCA") {
			t.Fatalf("%s did not point to a dedicated method", method)
		}
	}
	if got := send("ListSecrets", nil, ""); string(got.Result) != `{"names":["mitm/ca"]}` {
		t.Fatal("secret list must contain the reserved name only")
	}

	send("ExportManifest", api.ExportManifestRequest{Reveal: true}, "")
	send("GetConfiguration", map[string]bool{"reveal": true}, "")
	svc.Events().Publish(service.EventLog, map[string]string{"message": "test log entry"})
	if got := send("GetLogs", nil, ""); !bytes.Contains(got.Result, []byte("test log entry")) {
		t.Fatal("expected the retained log entry")
	}
	staged := []byte("unreferenced test resource")
	send("StageResource", api.StageResourceRequest{Hash: resource.Hash(staged), Size: len(staged), Data: staged}, "")
	archive := mitmCATestResult[api.ProfileArchiveManifest](t, send("ExportProfileArchive", api.ExportManifestRequest{Reveal: true}, ""))
	for _, entry := range archive.Resources {
		req := api.ReadResourceRequest{ArchiveHash: archive.ArchiveHash, BaseRevision: archive.Revision, Hash: entry.Hash, Reveal: true}
		chunk := mitmCATestResult[api.ReadResourceResult](t, send("ReadResource", req, ""))
		if !chunk.EOF || len(chunk.Data) != entry.Size {
			t.Fatal("did not read the complete archived resource")
		}
		assertNoMITMCASecrets(t, "archive resource", chunk.Data, forbidden)
	}
	if archive.ArchiveHash == "" || len(archive.Resources) == 0 {
		t.Fatal("expected a downloadable archive")
	}

	if deleted := mitmCATestResult[api.DeleteMITMCAResult](t, send("DeleteMITMCA", nil, "")); !deleted.Deleted {
		t.Fatal("expected a deletion confirmation")
	}
	if _, err := store.Get(ca.SecretName); !errors.Is(err, secret.ErrNotFound) {
		t.Fatal("CA was not removed from the secret store")
	}
	if reply := send("GetMITMCA", nil, ""); string(reply.Result) != `{"installed":false}` {
		t.Fatal("expected an uninstalled status after deletion")
	}
}

func TestMITMCARequiresSecretStore(t *testing.T) {
	call := testSession(t, nil)
	for _, method := range []string{"GenerateMITMCA", "ImportMITMCA", "GetMITMCA", "ExportMITMCA", "DeleteMITMCA"} {
		reply := call(t, Request{ID: 2, Method: method})
		if reply.Error == nil || reply.Error.Code != CodeInternal || reply.Error.Message != "no secret store" {
			t.Fatalf("%s did not report the missing secret store", method)
		}
	}
}

type panickingMITMCAStore struct{ secret.Store }

func (panickingMITMCAStore) Set(_, value string) error {
	panic(value)
}

func TestMITMCAPanicKeepsKeyOutOfLogs(t *testing.T) {
	store, err := secret.NewFileStore(filepath.Join(t.TempDir(), "secrets.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	call := testSession(t, panickingMITMCAStore{store})
	var log bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	reply := call(t, Request{ID: 2, Method: "GenerateMITMCA"})
	if reply.Error == nil || reply.Error.Code != CodeInternal || reply.Error.Message != "request handler panicked" {
		t.Fatal("expected a generic internal error")
	}
	assertNoMITMCASecrets(t, "panic log", log.Bytes(), nil)
	if !strings.Contains(log.String(), "GenerateMITMCA") {
		t.Fatal("expected the panic to be logged")
	}
	if reply := call(t, Request{ID: 3, Method: "GetMITMCA"}); reply.Error != nil {
		t.Fatal("session did not handle the next request")
	}
}

func mitmCATestResult[T any](t *testing.T, reply Message) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(reply.Result, &result); err != nil {
		t.Fatal("invalid MITM CA test result")
	}
	return result
}

func mitmCATestKey(t *testing.T, store secret.Store) (*x509.Certificate, *ecdsa.PrivateKey, []string) {
	t.Helper()
	bundle, err := store.Get(ca.SecretName)
	if err != nil {
		t.Fatal("could not read the test CA bundle")
	}
	certBlock, rest := pem.Decode([]byte(bundle))
	keyBlock, _ := pem.Decode(rest)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("invalid test CA bundle")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal("invalid test CA certificate")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		t.Fatal("invalid test CA key")
	}
	scalar := privateKey.D.Text(16)
	return cert, privateKey, []string{
		base64.StdEncoding.EncodeToString(keyBlock.Bytes),
		base64.StdEncoding.EncodeToString([]byte(bundle)),
		scalar,
		strings.ToUpper(scalar),
	}
}

func assertNoMITMCASecrets(t *testing.T, path string, data []byte, forbidden []string) {
	t.Helper()
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		t.Fatalf("%s contains a private key marker", path)
	}
	for _, value := range forbidden {
		if bytes.Contains(data, []byte(value)) {
			t.Fatalf("%s contains sensitive data", path)
		}
	}
}
