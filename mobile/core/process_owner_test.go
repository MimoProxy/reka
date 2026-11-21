package core

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/testnet"
	"golang.org/x/net/proxy"
)

type ownerTuple struct{ network, source, destination string }
type structuredOwnerHost struct {
	fakeHost
	value       atomic.Value
	infoCalls   atomic.Int64
	legacyCalls atomic.Int64
	tuples      chan ownerTuple
}

func (h *structuredOwnerHost) FindProcessInfo(network, source, destination string) string {
	h.infoCalls.Add(1)
	if h.tuples != nil {
		select {
		case h.tuples <- ownerTuple{network, source, destination}:
		default:
		}
	}
	value, _ := h.value.Load().(string)
	return value
}
func (h *structuredOwnerHost) FindProcess(_, _, _ string) string {
	h.legacyCalls.Add(1)
	return "org.test.app"
}
func (h *structuredOwnerHost) reset(value string) {
	h.value.Store(value)
	h.infoCalls.Store(0)
	h.legacyCalls.Store(0)
}

type legacyOwnerHost struct {
	fakeHost
	calls atomic.Int64
}

func (h *legacyOwnerHost) FindProcess(_, _, _ string) string { h.calls.Add(1); return "org.legacy.app" }

func TestEmbeddedStructuredOwnerPathAndUIDUseSingleLookup(t *testing.T) {
	host := &structuredOwnerHost{tuples: make(chan ownerTuple, 32)}
	host.reset(`{"path":"org.test.app","uid":10042}`)
	in, proxyAddress, target := startOwnerFixture(t, host)
	installOwnerRules(t, in, []any{map[string]any{"and": []any{map[string]any{"process-path": "org.test.app"}, map[string]any{"uid": "10042"}}}})
	ownerSOCKSEcho(t, proxyAddress, target, true)
	if host.infoCalls.Load() != 1 || host.legacyCalls.Load() != 0 {
		t.Fatal("path and UID repeated or downgraded the lookup", host.infoCalls.Load(), host.legacyCalls.Load())
	}
	select {
	case tuple := <-host.tuples:
		if tuple.network != "tcp" || tuple.destination != proxyAddress {
			t.Fatal("host received a rewritten ownership tuple", tuple)
		}
		ap, err := netip.ParseAddrPort(tuple.source)
		if err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 {
			t.Fatal("invalid original client socket", tuple)
		}
	default:
		t.Fatal("host never received the socket tuple")
	}
	for _, tc := range []struct{ name, value string }{
		{"missing UID", `{"path":"org.test.app"}`},
		{"unknown UID", `{"path":"org.test.app","uid":null}`},
		{"different UID", `{"path":"org.test.app","uid":10043}`},
		{"shared UID", `{"uid":10042}`},
		{"unknown owner", `{}`},
		{"malformed owner", `{"path":"org.test.app","uid":-1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host.reset(tc.value)
			ownerSOCKSEcho(t, proxyAddress, target, false)
			if host.infoCalls.Load() != 1 || host.legacyCalls.Load() != 0 {
				t.Fatal("unknown ownership retried or fabricated a path", host.infoCalls.Load(), host.legacyCalls.Load())
			}
		})
	}
	// Shared UIDs still support UID routing, without attributing the flow to
	// one of several packages or falling back to a legacy fabricated package.
	installOwnerRules(t, in, []any{map[string]any{"uid": "10042"}})
	host.reset(`{"uid":10042}`)
	ownerSOCKSEcho(t, proxyAddress, target, true)
	if host.infoCalls.Load() != 1 || host.legacyCalls.Load() != 0 {
		t.Fatal("shared UID was not preserved")
	}
}

func TestEmbeddedLegacyOwnerHostRemainsCompatible(t *testing.T) {
	host := &legacyOwnerHost{}
	in, address, target := startOwnerFixture(t, host)
	installOwnerRules(t, in, []any{map[string]any{"process-path": "org.legacy.app"}})
	ownerSOCKSEcho(t, address, target, true)
	if host.calls.Load() != 1 {
		t.Fatal("legacy path lookup was not used exactly once", host.calls.Load())
	}
	installOwnerRules(t, in, []any{map[string]any{"and": []any{map[string]any{"process-path": "org.legacy.app"}, map[string]any{"uid": "10042"}}}})
	host.calls.Store(0)
	ownerSOCKSEcho(t, address, target, false)
	if host.calls.Load() != 1 {
		t.Fatal("legacy host received repeated owner queries", host.calls.Load())
	}
}

func TestStructuredOwnerOnlyEmptyResultUsesLegacyFallback(t *testing.T) {
	host := &structuredOwnerHost{}
	md := sagernet.Metadata{Network: "tcp", Source: netip.MustParseAddrPort("127.0.0.1:40000"), Local: netip.MustParseAddrPort("127.0.0.1:17890"), Destination: sagernet.Destination{Domain: "rewritten.test", Port: 443}}
	for _, value := range []string{`{}`, `null`, `[]`, `{"path":"org.test.app","uid":-1}`, `{"path":"org.test.app","uid":4294967296}`, `{"path":"org.test.app","uid":"10042"}`, `{"path":"bad\u0000path"}`, `not-json`, strings.Repeat("x", 16385)} {
		host.reset(value)
		owner, known := processOwnerForHost(host, md)
		if known || owner.Path != "" || owner.UIDKnown || host.legacyCalls.Load() != 0 {
			t.Fatal("invalid owner result silently used legacy path")
		}
	}
	host.reset("")
	owner, known := processOwnerForHost(host, md)
	if !known || owner.Path != "org.test.app" || owner.UIDKnown || host.infoCalls.Load() != 1 || host.legacyCalls.Load() != 1 {
		t.Fatal("empty optional callback did not preserve legacy host compatibility")
	}
}

func startOwnerFixture(t *testing.T, host Host) (*Instance, string, string) {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	var in *Instance
	address := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		local := fmt.Sprintf("listeners: [{id: owner, type: socks, listen: %q}]", address)
		in, err = Start(Options{StateRoot: t.TempDir(), InitialProfile: []byte("schema-version: 1\nrules: [{match: {all: true}, outbound: reject}]\n"), InitialLocal: []byte(local), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, host)
		return err
	}).String()
	t.Cleanup(in.Stop)
	ownerAPICall(t, in, 1, "Hello", map[string]any{"versions": []int{1}})
	return in, address, echo.Addr().String()
}

func installOwnerRules(t *testing.T, in *Instance, guards []any) {
	t.Helper()
	status := ownerAPICall(t, in, 2, "GetStatus", nil)
	rules := []any{}
	for _, guard := range guards {
		rules = append(rules, map[string]any{"match": guard, "outbound": "direct"})
	}
	rules = append(rules, map[string]any{"match": map[string]any{"all": true}, "outbound": "reject"})
	profile, err := json.Marshal(map[string]any{"schema-version": 1, "rules": rules})
	if err != nil {
		t.Fatal(err)
	}
	result := ownerAPICall(t, in, 3, "CommitConfiguration", map[string]any{"base_revision": status["revision"], "profile": string(profile)})
	if result["state"] != "committed" {
		t.Fatal("owner rule configuration did not activate", result)
	}
}

func ownerAPICall(t *testing.T, in *Instance, id int, method string, params any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result map[string]any  `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err = json.Unmarshal(in.Call(raw), &response); err != nil || len(response.Error) > 0 {
		t.Fatalf("%s failed: %v %s", method, err, response.Error)
	}
	return response.Result
}

func ownerSOCKSEcho(t *testing.T, proxyAddress, target string, allowed bool) {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", proxyAddress, nil, &net.Dialer{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := dialer.Dial("tcp", target)
	if !allowed {
		if err == nil {
			c.Close()
			t.Fatal("unknown or mismatching ownership bypassed the final reject")
		}
		return
	}
	if err != nil {
		t.Fatal("known owner was not forwarded", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = io.WriteString(c, "owner-contract"); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("owner-contract"))
	if _, err = io.ReadFull(c, buffer); err != nil || string(buffer) != "owner-contract" {
		t.Fatal("owner route did not preserve payload", err)
	}
}
