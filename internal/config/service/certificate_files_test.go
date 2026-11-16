package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

func TestSubscriptionCertificateAttachmentsRefreshMaskAndRetain(t *testing.T) {
	identity := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer identity.Close()
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.TLS.Certificates[0].Certificate[0]}))
	der, err := x509.MarshalPKCS8PrivateKey(identity.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`proxies: [{name: node, type: http, server: node.test, port: 443, tls: true, certificate: client.pem, private-key: client.key}]`))
	}))
	defer origin.Close()
	e := newEnv(t)
	e.sec.Set("tls/client-key", key)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	spec := &model.Subscription{URL: origin.URL, CertificateFiles: []model.CertificateFile{{Path: "client.pem", Value: cert}, {Path: "client.key", Value: "secret://tls/client-key"}}}
	if _, err = s.ConfigureSubscription(context.Background(), s.ActiveRevision(), "airport", spec); err != nil {
		t.Fatal(err)
	}
	masked := s.GetConfiguration(false).Sources
	if strings.Contains(masked, "BEGIN ") {
		t.Fatal("attachment leaked in masked source")
	}
	sources, _, ds := model.ParseSources([]byte(masked))
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	maskedSpec := sources.Sources[0].Subscription
	if maskedSpec.CertificateFiles[0].Value != model.Mask || maskedSpec.CertificateFiles[1].Value != "secret://tls/client-key" {
		t.Fatal("attachment masking changed references")
	}
	if _, err = s.ConfigureSubscription(context.Background(), s.ActiveRevision(), "airport", maskedSpec); err != nil {
		t.Fatal(err)
	}
	if maskedSpec.CertificateFiles[0].Value != model.Mask {
		t.Fatal("configuration mutated its caller's attachment slice")
	}
	if status := refreshNow(t, s, "airport"); status.State != "current" {
		t.Fatal(status)
	}
	sources, _, ds = model.ParseSources([]byte(s.GetConfiguration(true).Sources))
	if ds.HasErrors() || len(sources.Sources[0].Outbounds) != 1 {
		t.Fatal(ds)
	}
	got := sources.Sources[0].Outbounds[0].TLS
	if got.Certificate != cert || got.PrivateKey != key {
		t.Fatal("refresh lost explicit certificate attachments")
	}
	if strings.Contains(s.GetConfiguration(false).Sources, "BEGIN ") {
		t.Fatal("materialized identity leaked")
	}
	maskedSpec.CertificateFiles[0].Path = "another.pem"
	if _, err = s.ConfigureSubscription(context.Background(), s.ActiveRevision(), "airport", maskedSpec); err == nil {
		t.Fatal("masked attachment moved to a new identity")
	}
}
