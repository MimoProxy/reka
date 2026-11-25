//go:build !ios

package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/control"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/testnet"
)

func TestMITMScriptNotificationEvents(t *testing.T) {
	authority, err := ca.Generate(ca.GenerateOptions{CommonName: "Test interception CA"})
	if err != nil {
		t.Fatal(err)
	}
	var k *Kernel
	proxyAddr := testnet.RetryAddr(t, func(addr netip.AddrPort) error {
		stateRoot := t.TempDir()
		secrets, err := secret.NewFileStore(filepath.Join(stateRoot, "secrets.json"), nil)
		if err != nil {
			return err
		}
		if err := ca.Save(secrets, authority); err != nil {
			return err
		}
		resources, err := resource.Open(stateRoot)
		if err != nil {
			return err
		}
		hash, err := resources.Put([]byte(`
for (let i = 0; i < 12; i++) {
  $notification.post("Test notice", "Script subtitle", "Script body", {
    "open-url": "https://example.test/notice",
    "clipboard": "test value"
  });
}
$done({response: {status: 201, body: "script response"}});
`))
		if err != nil {
			return err
		}
		k, err = Start(Options{
			StateRoot:      stateRoot,
			Secrets:        secrets,
			ControlAddress: "-",
			Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			InitialLocal:   []byte("mitm: {enabled: true, ca: 'secret://mitm/ca'}\n"),
			InitialProfile: []byte(fmt.Sprintf(`schema-version: 1
listeners: [{id: proxy, type: mixed, listen: %q}]
mitm: {hostnames: [example.test]}
rules: [{match: {all: true}, outbound: direct}]
scripts:
  - {id: notice, type: http-request, pattern: '^https://example[.]test/notice$', hash: %s}
`, addr.String(), hash)),
		})
		return err
	})
	t.Cleanup(k.Close)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	controlServer := control.NewServer(k.Handler)
	defer controlServer.Close()
	go controlServer.ServeConn(serverConn)
	client, err := api.NewClient(clientConn, "script notification test")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Call("Subscribe", map[string]any{"types": []string{service.EventScriptNotification}}, nil); err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.CertificatePEM()) {
		t.Fatal("failed to load the test CA")
	}
	transport := &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr.String()}),
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	res, err := httpClient.Get("https://example.test/notice")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != http.StatusCreated || string(body) != "script response" {
		t.Fatalf("script response: %d %q (%v)", res.StatusCode, body, err)
	}

	var status api.MITMStatus
	if err := client.Call("GetMITMStatus", nil, &status); err != nil {
		t.Fatal(err)
	}
	if got := status.Scripts; got.Status != "enabled" || got.Count != 1 || got.Runs != 1 || got.Notifications != 5 || got.NotificationsDropped != 7 {
		t.Fatalf("script status: %+v", got)
	}

	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for received := 0; received < int(status.Scripts.Notifications); {
		select {
		case event, ok := <-client.Events:
			if !ok {
				t.Fatal("control API closed")
			}
			if event.Type == service.EventSnapshot {
				continue
			}
			if event.Type != service.EventScriptNotification || event.Dropped != 0 {
				t.Fatalf("unexpected control event: %+v", event)
			}
			var notification api.ScriptNotification
			data, err := json.Marshal(event.Data)
			if err != nil {
				t.Fatal(err)
			}
			var options map[string]string
			if err := json.Unmarshal(data, &notification); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(notification.Options, &options); err != nil {
				t.Fatal(err)
			}
			if notification.ScriptID != "notice" || notification.Title != "Test notice" || notification.Subtitle != "Script subtitle" ||
				notification.Body != "Script body" || notification.Time.IsZero() || options["open-url"] != "https://example.test/notice" || options["clipboard"] != "test value" {
				t.Fatalf("unexpected script notification: %s", data)
			}
			received++
		case <-timeout.C:
			t.Fatalf("received %d script notification events", received)
		}
	}
}
