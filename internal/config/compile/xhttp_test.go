package compile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/model"
)

const xhttpProfile = `schema-version: 1
outbounds:
 - id: node
   type: vless
   server: upload.test
   port: 443
   uuid: b831381d-6324-4d53-ad4f-8cda48b30811
   tls: {server-name: upload.test, alpn: [h2], reality: {public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}}
   transport:
    type: xhttp
    host: upload.test
    path: /split
    headers: [{name: X-Upload-Key, value: 'secret://xhttp/upload'}]
    xhttp:
     mode: stream-up
     xmux: {max-connections: '4', h-keep-alive-period: '45'}
     download-settings:
      server: download.test
      port: 443
      tls: {server-name: download.test, alpn: [h3], certificate: 'secret://xhttp/certificate', private-key: 'secret://xhttp/key'}
      headers: [{name: X-Download-Key, value: 'secret://xhttp/download'}]
`

func TestXHTTPCompileResolvesDownloadIdentityAndFingerprint(t *testing.T) {
	s := store(t)
	for name, value := range map[string]string{"xhttp/upload": "upload-secret", "xhttp/download": "download-secret"} {
		if err := s.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	cert, key := xhttpClientIdentity(t)
	if err := s.Set("xhttp/certificate", cert); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("xhttp/key", key); err != nil {
		t.Fatal(err)
	}
	eff, ds := Compile([]byte(xhttpProfile), nil, Options{Secrets: s})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	node, _ := eff.Outbound("node")
	d := node.Transport.XHTTP.DownloadSettings
	if d.Headers[0].Value != "download-secret" || d.TLS.Certificate != cert || d.TLS.PrivateKey != key || d.TLS.Reality != nil {
		t.Fatal("separate download identity was lost or unresolved")
	}
	for _, name := range []string{"xhttp/upload", "xhttp/download"} {
		if err := s.Set(name, "rotated-secret"); err != nil {
			t.Fatal(err)
		}
		next, ds := Compile([]byte(xhttpProfile), nil, Options{Secrets: s})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		updated, _ := next.Outbound("node")
		if updated.Fingerprint == node.Fingerprint {
			t.Fatalf("rotating %s did not replace the transport", name)
		}
		node = updated
	}
	cert, key = xhttpClientIdentity(t)
	_ = s.Set("xhttp/certificate", cert)
	_ = s.Set("xhttp/key", key)
	next, ds := Compile([]byte(xhttpProfile), nil, Options{Secrets: s})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	updated, _ := next.Outbound("node")
	if updated.Fingerprint == node.Fingerprint {
		t.Fatal("download client identity rotation was not fingerprinted", ds)
	}
}

func TestXHTTPCompileRejectsInvalidCombinations(t *testing.T) {
	base := `schema-version: 1
outbounds: [{id: node, type: vless, server: node.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: {server-name: node.test, alpn: [h2]}, transport: {type: xhttp, xhttp: {mode: packet-up}}}]
`
	for name, data := range map[string]string{
		"multiple ALPN":             strings.Replace(base, "[h2]", "[h2, http/1.1]", 1),
		"unknown mode":              strings.Replace(base, "packet-up", "unknown", 1),
		"oversized padding":         strings.Replace(base, "mode: packet-up", "x-padding-bytes: '9000'", 1),
		"endpoint at main":          strings.Replace(base, "mode: packet-up", "server: remote.test", 1),
		"unknown option":            strings.Replace(base, "mode: packet-up", "unknown: true", 1),
		"nested download":           strings.Replace(base, "mode: packet-up", "download-settings: {download-settings: {}}", 1),
		"stream-one download":       strings.Replace(base, "mode: packet-up", "mode: stream-one, download-settings: {}", 1),
		"disabled TLS identity":     strings.Replace(base, "mode: packet-up", "download-settings: {disable-tls: true, tls: {}}", 1),
		"invalid download identity": strings.Replace(base, "mode: packet-up", "download-settings: {tls: {certificate: bad, private-key: bad}}", 1),
		"download h3 reality":       strings.Replace(base, "mode: packet-up", "download-settings: {tls: {server-name: node.test, alpn: [h3], reality: {public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}}}", 1),
		"H3 TCP fingerprint":        strings.Replace(base, "alpn: [h2]", "alpn: [h3], fingerprint: chrome", 1),
		"VMess":                     strings.Replace(base, "type: vless", "type: vmess", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ds := Compile([]byte(data), nil, Options{}); !ds.HasErrors() {
				t.Fatal("invalid XHTTP configuration accepted")
			}
		})
	}
	for _, alpn := range []string{"http/1.1", "h2", "h3"} {
		if _, ds := Compile([]byte(strings.Replace(base, "[h2]", "["+alpn+"]", 1)), nil, Options{}); ds.HasErrors() {
			t.Fatal(alpn, ds)
		}
	}
}

func TestXHTTPCompileDoesNotMutateSourceOptions(t *testing.T) {
	s := store(t)
	_ = s.Set("xhttp/header", "resolved-value")
	ob := model.Outbound{Type: "vless", Server: "node.test", Transport: &model.Transport{Type: "xhttp", XHTTP: &model.XHTTPOptions{DownloadSettings: &model.XHTTPOptions{Headers: []model.SubscriptionHeader{{Name: "X-Key", Value: "secret://xhttp/header"}}, TLS: &model.TLS{Carrier: &model.TLSCarrier{Type: "jls", Username: "name", Password: "secret://xhttp/header"}}}}}}
	c := &compiler{opts: Options{Secrets: s}}
	out := &Outbound{}
	c.protocol("/outbounds/node", ob, out)
	if c.diags.HasErrors() {
		t.Fatal(c.diags)
	}
	if ob.Transport.XHTTP.DownloadSettings.Headers[0].Value != "secret://xhttp/header" || ob.Transport.XHTTP.DownloadSettings.TLS.Carrier.Password != "secret://xhttp/header" {
		t.Fatal("secret resolution mutated the original document")
	}
	if out.Transport.XHTTP.DownloadSettings.TLS.Carrier.Password != "resolved-value" {
		t.Fatal("download TLS carrier secret was not resolved")
	}
}

func xhttpClientIdentity(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}
