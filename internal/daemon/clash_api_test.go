package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/clashapi"
	"github.com/MimoProxy/reka/internal/router"
	"golang.org/x/net/websocket"
)

func TestClashControllerReadsStreamsAndCommits(t *testing.T) {
	var content atomic.Value
	content.Store("original.test\n")
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, content.Load())
	}))
	defer source.Close()
	const token = "test-token-for-controller"
	const origin = "https://dashboard.example"
	k, err := Start(Options{
		StateRoot: t.TempDir(), ControlAddress: "-", DeferNetwork: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		InitialProfile: []byte(`schema-version: 1
groups: [{id: choice, name: "Test / group", type: select, members: [direct, reject]}]
rules: [{match: {all: true}, outbound: choice}]
`),
		ClashAPI: clashapi.Options{Listen: "127.0.0.1:0", Version: "test", Token: token, AllowOrigins: []string{origin}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	baseURL := "http://" + k.ClashAddress
	client := &http.Client{Timeout: 8 * time.Second}
	defer client.CloseIdleConnections()
	send := func(method, path, body, bearer, requestOrigin, host string, status int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, baseURL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if requestOrigin != "" {
			req.Header.Set("Origin", requestOrigin)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != status {
			t.Fatalf("%s %s: got %d %s (%v), want %d", method, path, resp.StatusCode, data, err, status)
		}
		if requestOrigin == origin && resp.Header.Get("Access-Control-Allow-Origin") != origin {
			t.Fatal("allowed dashboard origin was not returned")
		}
		return data
	}
	send("GET", "/version", "", "", "", "", http.StatusUnauthorized)
	send("GET", "/version", "", token, "https://other.example", "", http.StatusForbidden)
	send("GET", "/version", "", token, "", "other.example", http.StatusForbidden)
	send("OPTIONS", "/proxies", "", "", origin, "", http.StatusNoContent)
	send("GET", "/version", "", token, origin, "", http.StatusOK)

	groupPath := "/proxies/" + url.PathEscape("Test / group")
	before := send("GET", groupPath, "", token, origin, "", http.StatusOK)
	if !strings.Contains(string(before), `"now":"DIRECT"`) {
		t.Fatalf("wrong initial selection: %s", before)
	}
	revision := k.Service.ActiveRevision()
	send("PUT", groupPath, `{"name":"not-a-member"}`, token, origin, "", http.StatusBadRequest)
	if k.Service.ActiveRevision() != revision {
		t.Fatal("a rejected selection wrote config")
	}
	send("PUT", groupPath, `{"name":"REJECT"}`, token, origin, "", http.StatusNoContent)
	if now := k.Service.GetConfiguration(true).Effective.Router.Route(context.Background(), router.Metadata{}, nil); now.Outbound != "reject" ||
		k.Service.ActiveRevision() <= revision {
		t.Fatalf("selection did not reach the configured router: %+v", now)
	}
	rules := send("GET", "/rules", "", token, origin, "", http.StatusOK)
	if !strings.Contains(string(rules), `"proxy":"Test / group"`) {
		t.Fatalf("inconsistent rule names: %s", rules)
	}
	var connections map[string]any
	if err := json.Unmarshal(send("GET", "/connections", "", token, origin, "", http.StatusOK), &connections); err != nil || connections["connections"] == nil {
		t.Fatal("malformed connection snapshot", connections, err)
	}
	send("PUT", "/configs", "{}", token, origin, "", http.StatusMethodNotAllowed)

	result, err := k.Service.InstallManagedResource(context.Background(), api.InstallManagedResourceRequest{
		BaseRevision: k.Service.ActiveRevision(), Kind: "rule-set", ID: "sample", URL: source.URL + "?private=not-for-dashboard",
		Format: "text", Behavior: "domain",
	})
	if err != nil || result.State != "committed" {
		t.Fatalf("install: %+v %v", result, err)
	}
	list := send("GET", "/providers/rules", "", token, origin, "", http.StatusOK)
	if !strings.Contains(string(list), "rule-set/sample") || strings.Contains(string(list), "not-for-dashboard") {
		t.Fatalf("invalid provider projection: %s", list)
	}
	content.Store("updated.test\n")
	send("PUT", "/providers/rules/"+url.PathEscape("rule-set/sample"), "", token, origin, "", http.StatusNoContent)
	if k.Service.ActiveRevision() <= result.Revision {
		t.Fatal("provider refresh did not publish a revision")
	}
	for _, endpoint := range []string{"/traffic", "/connections"} {
		config, err := websocket.NewConfig("ws://"+k.ClashAddress+endpoint+"?token="+token, origin)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := websocket.DialConfig(config)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var frame map[string]any
		if err := websocket.JSON.Receive(conn, &frame); err != nil || frame["uploadTotal"] == nil && frame["upTotal"] == nil {
			t.Fatalf("stream %s: %+v %v", endpoint, frame, err)
		}
	}
	// Shutdown must stop streams that are still open.
	done := make(chan struct{})
	go func() { k.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("shutdown blocked on an open dashboard stream")
	}
}
