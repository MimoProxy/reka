package importer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestClashCertificatePinAndVerificationName(t *testing.T) {
	pin := strings.Repeat("12", 32)
	for _, typ := range []string{"http", "socks5", "vless", "vmess", "trojan", "hysteria2", "tuic"} {
		extra := ""
		if typ == "vless" || typ == "vmess" || typ == "tuic" {
			extra += ", uuid: b831381d-6324-4d53-ad4f-8cda48b30811"
		}
		if typ == "trojan" || typ == "hysteria2" || typ == "tuic" {
			extra += ", password: test"
		}
		r := Import(request("proxies: [{name: node, type: " + typ + ", server: node.test, port: 443, tls: true, fingerprint: '" + pin + "', name-cert-verify: cert.test" + extra + "}]"))
		if !r.Report.CanApply {
			t.Fatal(typ, r.Report)
		}
		out := snapshot(t, r).Outbounds[0]
		if out.TLS.CertificatePin != pin || out.TLS.VerifyName != "cert.test" {
			t.Fatal("TLS certificate options dropped")
		}
		compileImport(t, r)
	}
}

func TestClashTLSFileAttachmentsAreExplicitMaskedAndValidated(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	req := request(`proxies: [{name: node, type: http, server: node.test, port: 443, tls: true, certificate: /foreign/client.pem, private-key: /foreign/client.key}]`)
	if r := Import(req); r.Report.CanApply {
		t.Fatal("unattached foreign paths accepted")
	}
	req.CertificateFiles = map[string]string{"/foreign/client.pem": certPEM, "/foreign/client.key": keyPEM}
	r := Import(req)
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	compileImport(t, r)
	if got := snapshot(t, r).Outbounds[0].TLS; got.Certificate != certPEM || got.PrivateKey != keyPEM {
		t.Fatal("attachment contents changed")
	}
	if preview := r.Preview(false); strings.Contains(preview.Sources, "BEGIN ") || preview.Masked != 2 {
		t.Fatal("attached identity exposed in preview")
	}
	realmRequest := req
	realmRequest.Data = `proxies: [{name: node, type: hysteria2, password: test, realm-opts: {enable: true, server-url: https://control.test, realm-id: room, stun-servers: [stun.test], certificate: /foreign/client.pem, private-key: /foreign/client.key}}]`
	realmRequest.CertificateFiles = nil
	if Import(realmRequest).Report.CanApply {
		t.Fatal("unattached Realm identity accepted")
	}
	realmRequest.CertificateFiles = req.CertificateFiles
	realmResult := Import(realmRequest)
	if !realmResult.Report.CanApply {
		t.Fatal(realmResult.Report)
	}
	realmTLS := compileImport(t, realmResult).Outbounds[0].Protocol.Realm.TLS
	if realmTLS.Certificate != certPEM || realmTLS.PrivateKey != keyPEM {
		t.Fatal("Realm attachments changed")
	}
	if strings.Contains(realmResult.Preview(false).Sources, "BEGIN ") {
		t.Fatal("Realm identity exposed")
	}

	pluginRequest := req
	pluginRequest.Data = `proxies: [{name: node, type: ss, server: node.test, port: 443, cipher: aes-128-gcm, password: test, plugin: shadow-tls, plugin-opts: {host: target.test, version: 3, password: outer-secret, certificate: /foreign/client.pem, private-key: /foreign/client.key}}]`
	pluginRequest.CertificateFiles = nil
	if Import(pluginRequest).Report.CanApply {
		t.Fatal("unattached plugin identity accepted")
	}
	pluginRequest.CertificateFiles = req.CertificateFiles
	pluginResult := Import(pluginRequest)
	if !pluginResult.Report.CanApply {
		t.Fatal(pluginResult.Report)
	}
	pluginTLS := compileImport(t, pluginResult).Outbounds[0].Plugin.TLS
	if pluginTLS.Certificate != certPEM || pluginTLS.PrivateKey != keyPEM {
		t.Fatal("plugin attachments changed")
	}
	if strings.Contains(pluginResult.Preview(false).Sources, "BEGIN ") {
		t.Fatal("plugin identity exposed")
	}

	req.CertificateFiles["/foreign/client.key"] = certPEM
	if Import(req).Report.CanApply {
		t.Fatal("invalid key attachment accepted")
	}
	req.CertificateFiles = map[string]string{"unrelated": strings.Repeat("x", 9<<20)}
	if Import(req).Report.CanApply {
		t.Fatal("oversized attachments accepted")
	}
}
