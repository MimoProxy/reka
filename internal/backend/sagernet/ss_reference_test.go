package sagernet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The CI reference job builds this external peer from the separate module.
// Ordinary platform jobs do not require the reference dependency graph.
func TestSSPluginsAgainstPinnedReference(t *testing.T) {
	program := os.Getenv("REKA_REFERENCE_PEER")
	if program == "" {
		t.Skip("pinned external peers run in the compatibility-reference job")
	}
	cases := []SSPluginSpec{{Type: "obfs", Mode: "http"}, {Type: "obfs", Mode: "tls"}, {Type: "shadow-tls", Version: 1}, {Type: "shadow-tls", Version: 2, Password: "outer-secret"}, {Type: "shadow-tls", Version: 3, Password: "outer-secret"}}
	cases = append(cases, legacyPluginCases()...)
	for _, kind := range []string{"v2ray-plugin", "gost-plugin"} {
		for _, mux := range []bool{false, true} {
			for _, secured := range []bool{false, true} {
				s := SSPluginSpec{Type: kind, Mode: "websocket", Mux: mux}
				if secured {
					s.TLS = &TLSSpec{}
				}
				cases = append(cases, s)
			}
		}
	}
	cases = append(cases, SSPluginSpec{Type: "v2ray-plugin", Mode: "websocket", Mux: true, HTTPUpgrade: true, FastOpen: true})
	for index, s := range cases {
		t.Run(fmt.Sprintf("%02d-%s-v%d-mux%v", index, s.Type, s.Version, s.Mux), func(t *testing.T) {
			serverAddress := loopback(freePort(t))
			server, err := StartShadowsocksServer(serverAddress, "aes-128-gcm", "test", testLogger(t))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			configuration, _ := json.Marshal(map[string]any{"Username": s.Username, "VersionHint": s.VersionHint, "Script": s.RestlsScript, "KCP": s.KCP, "Type": s.Type, "Mode": s.Mode, "Version": s.Version, "Password": s.Password, "Mux": s.Mux, "TLS": s.TLS != nil, "HTTPUpgrade": s.HTTPUpgrade, "Forward": serverAddress.String()})
			command := exec.Command(program)
			command.Stdin = bytes.NewReader(configuration)
			output, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(t.TempDir(), "peer.log")
			logFile, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			command.Stderr = logFile
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { command.Process.Kill(); command.Wait() })
			type response struct{ Address, Pin string }
			peer := make(chan response, 1)
			startup := make(chan error, 1)
			go func() {
				var info response
				err := json.NewDecoder(io.LimitReader(output, 8192)).Decode(&info)
				if err != nil {
					startup <- err
				} else {
					peer <- info
				}
			}()
			var info response
			select {
			case info = <-peer:
			case err = <-startup:
				data, _ := os.ReadFile(logPath)
				t.Fatalf("reference peer start: %v\n%s", err, data)
			case <-time.After(5 * time.Second):
				t.Fatal("reference peer startup timed out")
			}
			address, err := netip.ParseAddrPort(info.Address)
			if err != nil {
				t.Fatal(err)
			}
			if !address.Addr().IsLoopback() {
				t.Fatal("reference peer did not bind loopback")
			}
			s.Host, s.Path = "plugin.test", "/plugin"
			s.Headers = http.Header{"Host": {"plugin.test"}}
			if info.Pin != "" {
				s.TLS = &TLSSpec{ServerName: "plugin.test", CertificatePin: info.Pin, ALPN: []string{"http/1.1"}}
			}
			b := New(Options{Logger: testLogger(t)})
			defer b.Close()
			out, err := b.NewOutbound("reference", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: address.Port(), Method: "aes-128-gcm", Password: "test", Plugin: &s})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := out.Dial(ctx, "tcp", echoServer(t).String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			payload := bytes.Repeat([]byte("pinned-wire"), 1<<15)
			done := make(chan error, 1)
			go func() { _, err := c.Write(payload); done <- err }()
			reply := make([]byte, len(payload))
			if _, err = io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, payload) {
				t.Fatal("original reference interoperability", err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func startPinnedCarrierPeer(t *testing.T, configuration map[string]any) (string, string) {
	t.Helper()
	program := os.Getenv("REKA_REFERENCE_PEER")
	if program == "" {
		t.Skip("pinned original peer runs in the compatibility-reference job")
	}
	encoded, _ := json.Marshal(configuration)
	command := exec.Command(program)
	command.Stdin = bytes.NewReader(encoded)
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(t.TempDir(), "peer.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logFile.Close() })
	command.Stderr = logFile
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { command.Process.Kill(); command.Wait() })
	type response struct{ Address, Pin string }
	ready := make(chan response, 1)
	failed := make(chan error, 1)
	go func() {
		var info response
		if err := json.NewDecoder(io.LimitReader(output, 8192)).Decode(&info); err != nil {
			failed <- err
		} else {
			ready <- info
		}
	}()
	select {
	case info := <-ready:
		address, err := netip.ParseAddrPort(info.Address)
		if err != nil || !address.Addr().IsLoopback() {
			t.Fatal("invalid reference listener", info.Address)
		}
		return info.Address, info.Pin
	case err := <-failed:
		t.Fatal("reference startup", err)
	case <-time.After(5 * time.Second):
		t.Fatal("reference startup timed out")
	}
	return "", ""
}
