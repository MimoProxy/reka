//go:build with_gvisor

package packettunnel

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/MimoProxy/reka/mobile/profile"
)

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func proxyGet(port int, user *url.Userinfo, target string) (*http.Response, error) {
	proxy := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port), User: user}
	client := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	return client.Get(target)
}

func TestLANProxySharesTheProfile(t *testing.T) {
	const config = `schema-version: 1
rules: [{match: {all: true}, outbound: direct}]
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "through the tunnel")
	}))
	defer server.Close()

	port := freeTCPPort(t)
	controls := profile.Controls{Mode: "rule", LANProxy: &profile.LANProxy{Port: port, Username: "lan", Password: "secret"}}
	session, err := StartProfile(prepareSnapshot(t, config), controls, false)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	status, err := session.ProfileStatus()
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("0.0.0.0:%d", port); status.LANProxy != want || status.LANProxyError != "" {
		t.Fatalf("LAN proxy status = %q, %q; want %q", status.LANProxy, status.LANProxyError, want)
	}

	// Windows may reset the connection before the client reads the 407, so a
	// refused connection also counts as rejected.
	if resp, err := proxyGet(port, nil, server.URL); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("request without credentials returned %d, want 407", resp.StatusCode)
		}
	}
	resp, err := proxyGet(port, url.UserPassword("lan", "secret"), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "through the tunnel" {
		t.Fatalf("proxied response = %d %q", resp.StatusCode, body)
	}

	// A port held by another program leaves the tunnel running without the proxy.
	held, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	controls.LANProxy = &profile.LANProxy{Port: held.Addr().(*net.TCPAddr).Port}
	if err := session.ApplyControls(controls); err != nil {
		t.Fatalf("a busy LAN proxy port stopped the profile: %v", err)
	}
	if status, _ = session.ProfileStatus(); status.LANProxy != "" || status.LANProxyError == "" {
		t.Fatalf("busy port status = %q, %q", status.LANProxy, status.LANProxyError)
	}
	if _, err := proxyGet(port, url.UserPassword("lan", "secret"), server.URL); err == nil {
		t.Fatal("the previous LAN proxy port still accepts connections")
	}

	// An invalid request is reported the same way.
	controls.LANProxy = &profile.LANProxy{Port: 80}
	if err := session.ApplyControls(controls); err != nil {
		t.Fatal(err)
	}
	if status, _ = session.ProfileStatus(); status.LANProxyError == "" {
		t.Fatal("an invalid LAN proxy port was not reported")
	}

	// Turning it off clears the status.
	controls.LANProxy = nil
	if err := session.ApplyControls(controls); err != nil {
		t.Fatal(err)
	}
	if status, _ = session.ProfileStatus(); status.LANProxy != "" || status.LANProxyError != "" {
		t.Fatalf("disabled status = %q, %q", status.LANProxy, status.LANProxyError)
	}
}
