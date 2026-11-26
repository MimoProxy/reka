package generation

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/platform"
	M "github.com/sagernet/sing/common/metadata"
)

const tailscaleTestLocal = "link:\n  tailscale:\n    - id: home\n      auth-key: test-key\n      routes: [10.0.0.0/24]\n"

type fakeTailscaleNode struct {
	status  api.TailscaleStatus
	updates []sagernet.TailscalePreferences
	onClose func()
}

func (n *fakeTailscaleNode) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	if n.status.State != api.TailscaleRunning {
		return nil, errors.New("Tailscale link requires login")
	}
	a, b := net.Pipe()
	b.Close()
	return a, nil
}

func (*fakeTailscaleNode) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("test node has no packet sockets")
}

func (n *fakeTailscaleNode) Status() api.TailscaleStatus { return n.status }

func (n *fakeTailscaleNode) SetPreferences(prefs sagernet.TailscalePreferences) error {
	n.updates = append(n.updates, prefs)
	return nil
}

func (n *fakeTailscaleNode) Close() error {
	if n.onClose != nil {
		n.onClose()
	}
	return nil
}

func compileTailscaleTest(t *testing.T, local, rules string) *compile.Effective {
	t.Helper()
	eff, ds := compile.Compile([]byte("schema-version: 1\n"+rules), []byte(local), compile.Options{})
	if ds.HasErrors() || eff == nil {
		t.Fatal(ds)
	}
	return eff
}

func activateTailscaleTest(t *testing.T, e *Engine, eff *compile.Effective, revision uint64) {
	t.Helper()
	p, err := e.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Activate(p, revision); err != nil {
		t.Fatal(err)
	}
}

func TestTailscaleNodeLifecycle(t *testing.T) {
	const tag = "tailscale/home"
	root := t.TempDir()
	wantDir := filepath.Join(root, "tailscale", "home")
	var events []string
	var live int
	e := NewEngine(EngineOptions{StateRoot: root, newTailscaleNode: func(gotTag string, opts sagernet.TailscaleOptions) (sagernet.TailscaleNode, error) {
		if gotTag != tag || opts.StateDirectory != wantDir || !opts.AcceptRoutes || live != 0 {
			t.Errorf("unexpected node start for %s, state dir %q, accept routes %v, live nodes %d", gotTag, opts.StateDirectory, opts.AcceptRoutes, live)
		}
		if err := os.MkdirAll(opts.StateDirectory, 0o700); err != nil {
			return nil, err
		}
		live++
		events = append(events, "start "+opts.AuthKey)
		return &fakeTailscaleNode{status: api.TailscaleStatus{State: api.TailscaleRunning}, onClose: func() {
			live--
			events = append(events, "close "+opts.AuthKey)
		}}, nil
	}})
	t.Cleanup(e.Close)
	first := compileTailscaleTest(t, tailscaleTestLocal, "")
	prepared, err := e.Prepare(first)
	if err != nil {
		t.Fatal(err)
	}
	e.Abort(prepared)
	if len(events) != 0 {
		t.Fatal("preparing and aborting started the node")
	}
	activateTailscaleTest(t, e, first, 1)
	firstWrapper := e.OutboundInstance(tag)
	firstLink := e.tailscale.Load()
	if firstWrapper == nil || firstLink == nil || !slices.Equal(events, []string{"start test-key"}) {
		t.Fatalf("node did not start at activation: %v", events)
	}
	updated := compileTailscaleTest(t, strings.Replace(tailscaleTestLocal, "10.0.0.0/24", "10.1.0.0/24", 1), "rules: [{match: {domain: example.test}, outbound: reject}]\n")
	activateTailscaleTest(t, e, updated, 2)
	if !slices.Equal(events, []string{"start test-key"}) || e.tailscale.Load() != firstLink || e.OutboundInstance(tag) != firstWrapper {
		t.Fatalf("rule reload replaced the Tailscale node or wrapper: %v", events)
	}

	// Retire one wrapper while another wrapper still uses the same node.
	pin, err := firstWrapper.Pin()
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	rewrapped := *updated
	rewrapped.Outbounds = slices.Clone(updated.Outbounds)
	for i := range rewrapped.Outbounds {
		if rewrapped.Outbounds[i].ID == tag {
			rewrapped.Outbounds[i].Fingerprint += "-replacement-wrapper"
			break
		}
	}
	activateTailscaleTest(t, e, &rewrapped, 3)
	if !firstWrapper.Lease().Retired() || e.OutboundInstance(tag) == firstWrapper {
		t.Fatal("previous wrapper did not enter retirement")
	}
	conn, err := pin.Dial(t.Context(), "tcp", "100.64.0.1:443")
	if err != nil {
		t.Fatal("draining wrapper lost its node", err)
	}
	conn.Close()
	pin.Close()
	if err := firstWrapper.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err = e.OutboundInstance(tag).Dial(t.Context(), "tcp", "100.64.0.1:443")
	if err != nil || live != 1 {
		t.Fatalf("retiring the wrapper affected the active node: live=%d, err=%v", live, err)
	}
	conn.Close()

	changed := compileTailscaleTest(t, strings.Replace(tailscaleTestLocal, "test-key", "replacement-key", 1), "")
	if !e.Plan(changed).Interrupts {
		t.Fatal("plan did not report interrupted Tailscale flows")
	}
	oldPin, err := e.OutboundInstance(tag).Pin()
	if err != nil {
		t.Fatal(err)
	}
	defer oldPin.Close()
	activateTailscaleTest(t, e, changed, 4)
	if want := []string{"start test-key", "close test-key", "start replacement-key"}; !slices.Equal(events, want) || live != 1 {
		t.Fatalf("node replacement events = %v, live=%d, want %v", events, live, want)
	}
	if conn, err := oldPin.Dial(t.Context(), "tcp", "100.64.0.1:443"); err == nil {
		conn.Close()
		t.Fatal("draining wrapper dialed through the replacement node")
	} else if !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("draining wrapper returned %v, want stopped", err)
	}
	oldPin.Close()
	activateTailscaleTest(t, e, compileTailscaleTest(t, "", ""), 5)
	if live != 0 || e.TailscaleStatus().State != api.TailscaleStopped {
		t.Fatal("removing the link did not stop the node")
	}
	if _, err := os.Stat(wantDir); err != nil {
		t.Fatalf("removing the link removed persistent state: %v", err)
	}
	activateTailscaleTest(t, e, changed, 6)
	e.Close()
	if want := []string{"start test-key", "close test-key", "start replacement-key", "close replacement-key", "start replacement-key", "close replacement-key"}; !slices.Equal(events, want) || live != 0 {
		t.Fatalf("node lifecycle events = %v, live=%d, want %v", events, live, want)
	}
}

func TestTailscaleReferencesShareNodeAndLivePreferences(t *testing.T) {
	const first = "outbounds: [{id: a, type: tailscale}]\n"
	const both = "outbounds: [{id: a, type: tailscale}, {id: b, type: tailscale}]\n"
	node := &fakeTailscaleNode{status: api.TailscaleStatus{State: api.TailscaleRunning}}
	starts := 0
	e := NewEngine(EngineOptions{StateRoot: t.TempDir(), newTailscaleNode: func(string, sagernet.TailscaleOptions) (sagernet.TailscaleNode, error) {
		starts++
		return node, nil
	}})
	t.Cleanup(e.Close)
	activateTailscaleTest(t, e, compileTailscaleTest(t, tailscaleTestLocal, first), 1)
	a := e.OutboundInstance("a")
	activateTailscaleTest(t, e, compileTailscaleTest(t, tailscaleTestLocal, both), 2)
	for _, id := range []string{"a", "b", "tailscale/home"} {
		conn, err := e.OutboundInstance(id).Dial(t.Context(), "tcp", "100.64.0.1:443")
		if err != nil {
			t.Fatalf("dial through %s: %v", id, err)
		}
		conn.Close()
	}
	if a != e.OutboundInstance("a") || starts != 1 || len(node.updates) != 0 {
		t.Fatal("adding a reference changed the existing node or wrapper")
	}
	removed := compileTailscaleTest(t, tailscaleTestLocal, first)
	if e.Plan(removed).Interrupts {
		t.Fatal("removing a reference should leave other connections running")
	}
	activateTailscaleTest(t, e, removed, 3)

	prefsLocal := tailscaleTestLocal + "      exit-node: auto\n      exit-node-allow-lan-access: true\n"
	changed := compileTailscaleTest(t, prefsLocal, first)
	p, err := e.Prepare(changed)
	if err != nil {
		t.Fatal(err)
	}
	e.Abort(p)
	if len(node.updates) != 0 || e.Plan(changed).Interrupts {
		t.Fatal("preferences were applied before activation or marked as a restart")
	}
	activateTailscaleTest(t, e, changed, 4)
	activateTailscaleTest(t, e, compileTailscaleTest(t, prefsLocal+"      accept-routes: false\n", first), 5)
	want := []sagernet.TailscalePreferences{
		{AcceptRoutes: true, ExitNode: "auto", ExitNodeAllowLANAccess: true},
		{AcceptRoutes: false, ExitNode: "auto", ExitNodeAllowLANAccess: true},
	}
	if starts != 1 || e.OutboundInstance("a") != a || !slices.Equal(node.updates, want) {
		t.Fatalf("starts=%d, preference updates=%+v", starts, node.updates)
	}
}

func TestTailscaleReferenceTracksLocalLinkAvailability(t *testing.T) {
	const profile = "outbounds: [{id: ts, type: tailscale}]\n"
	e := NewEngine(EngineOptions{newTailscaleNode: func(string, sagernet.TailscaleOptions) (sagernet.TailscaleNode, error) {
		return &fakeTailscaleNode{status: api.TailscaleStatus{State: api.TailscaleRunning}}, nil
	}})
	t.Cleanup(e.Close)
	without := compileTailscaleTest(t, "", profile)
	checkUnavailable := func() {
		t.Helper()
		out := e.OutboundInstance("ts")
		_, tcpErr := out.Dial(t.Context(), "tcp", "100.64.0.1:443")
		pin, err := out.Pin()
		if err != nil {
			t.Fatal(err)
		}
		defer pin.Close()
		_, udpErr := pin.ListenPacket(t.Context(), "100.64.0.1:53")
		for _, err := range []error{tcpErr, udpErr} {
			if err == nil || !strings.Contains(err.Error(), "not configured on this device") {
				t.Fatalf("unconfigured reference returned %v", err)
			}
		}
	}
	activateTailscaleTest(t, e, without, 1)
	checkUnavailable()
	activateTailscaleTest(t, e, compileTailscaleTest(t, tailscaleTestLocal, profile), 2)
	conn, err := e.OutboundInstance("ts").Dial(t.Context(), "tcp", "100.64.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	pinned, err := e.OutboundInstance("ts").Pin()
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	activateTailscaleTest(t, e, without, 3)
	checkUnavailable()
	if _, err := pinned.Dial(t.Context(), "tcp", "100.64.0.1:443"); err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("retired reference lost its association with the stopped link: %v", err)
	}
}

func TestTailscaleFailedActivationKeepsNode(t *testing.T) {
	var starts, closes int
	tunError := errors.New("test TUN failed to start")
	e := NewEngine(EngineOptions{StateRoot: t.TempDir(), TUNFD: 1,
		NetworkHooks: &platform.NetworkHooks{StartTUN: func(platform.TUNConfig) (io.Closer, string, error) {
			return nil, "", tunError
		}},
		newTailscaleNode: func(string, sagernet.TailscaleOptions) (sagernet.TailscaleNode, error) {
			starts++
			return &fakeTailscaleNode{status: api.TailscaleStatus{State: api.TailscaleRunning}, onClose: func() { closes++ }}, nil
		},
	})
	t.Cleanup(e.Close)
	confirmed := compileTailscaleTest(t, tailscaleTestLocal, "")
	activateTailscaleTest(t, e, confirmed, 1)
	link := e.tailscale.Load()
	changed := compileTailscaleTest(t, strings.Replace(tailscaleTestLocal, "test-key", "replacement-key", 1), "")
	changed.Network = platform.Network{Mode: "tun"}
	p, err := e.Prepare(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Activate(p, 2); !errors.Is(err, tunError) {
		t.Fatalf("activation error = %v, want %v", err, tunError)
	}
	activateTailscaleTest(t, e, confirmed, 1)
	if e.tailscale.Load() != link || starts != 1 || closes != 0 {
		t.Fatalf("rolling back replaced the confirmed node: starts=%d, closes=%d", starts, closes)
	}
	conn, err := e.OutboundInstance("tailscale/home").Dial(t.Context(), "tcp", "100.64.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestTailscaleWithoutStateDirectoryFailsOnlyTheLink(t *testing.T) {
	e := NewEngine(EngineOptions{})
	t.Cleanup(e.Close)
	activateTailscaleTest(t, e, compileTailscaleTest(t, tailscaleTestLocal, ""), 1)
	status := e.TailscaleStatus()
	if status.State != api.TailscaleError || !strings.Contains(status.LastError, "state directory") {
		t.Fatalf("unexpected status: %+v", status)
	}
	link := e.tailscale.Load()
	if _, err := link.DialContext(context.Background(), "tcp", M.ParseSocksaddr("100.64.0.2:80")); err == nil {
		t.Fatal("dial succeeded without a state directory")
	}
}

func TestTailscaleStateDirOverridesStateRoot(t *testing.T) {
	override := t.TempDir()
	var got string
	e := NewEngine(EngineOptions{StateRoot: t.TempDir(), TailscaleStateDir: override, newTailscaleNode: func(_ string, opts sagernet.TailscaleOptions) (sagernet.TailscaleNode, error) {
		got = opts.StateDirectory
		return &fakeTailscaleNode{status: api.TailscaleStatus{State: api.TailscaleRunning}}, nil
	}})
	t.Cleanup(e.Close)
	activateTailscaleTest(t, e, compileTailscaleTest(t, tailscaleTestLocal, ""), 1)
	if want := filepath.Join(override, "home"); got != want {
		t.Fatalf("state directory = %q, want %q", got, want)
	}
}

func TestTailscaleStatusNeedsLogin(t *testing.T) {
	const authURL = "https://login.example.test/authorize"
	e := NewEngine(EngineOptions{StateRoot: t.TempDir(), newTailscaleNode: func(string, sagernet.TailscaleOptions) (sagernet.TailscaleNode, error) {
		return &fakeTailscaleNode{status: api.TailscaleStatus{State: api.TailscaleNeedsLogin, AuthURL: authURL}}, nil
	}})
	t.Cleanup(e.Close)
	const profile = "outbounds: [{id: ts, type: tailscale}]\ngroups: [{id: choice, type: select, members: [ts]}]\n"
	activateTailscaleTest(t, e, compileTailscaleTest(t, tailscaleTestLocal, profile), 1)
	status := e.TailscaleStatus()
	if status.ID != "home" || status.State != api.TailscaleNeedsLogin || status.AuthURL != authURL {
		t.Fatalf("unexpected status: %+v", status)
	}
	_, err := e.ProbeOutbound(t.Context(), api.ProbeRequest{Outbound: "choice", URL: "http://100.64.0.1/"})
	if err == nil || !strings.Contains(err.Error(), "requires login") {
		t.Fatalf("probe through a Tailscale group member returned %v", err)
	}
}

func TestTailscaleStartErrorHidesAuthKey(t *testing.T) {
	var starts int
	e := NewEngine(EngineOptions{StateRoot: t.TempDir(), newTailscaleNode: func(_ string, opts sagernet.TailscaleOptions) (sagernet.TailscaleNode, error) {
		starts++
		if starts == 1 {
			return nil, errors.New("auth failed for " + opts.AuthKey)
		}
		return &fakeTailscaleNode{status: api.TailscaleStatus{State: api.TailscaleRunning}}, nil
	}})
	t.Cleanup(e.Close)
	activateTailscaleTest(t, e, compileTailscaleTest(t, tailscaleTestLocal, ""), 1)
	status := e.TailscaleStatus()
	if status.State != api.TailscaleError || status.LastError != "auth failed for [redacted]" {
		t.Fatalf("unexpected status: %+v", status)
	}
	out := e.OutboundInstance("tailscale/home")
	_, err := out.Dial(t.Context(), "tcp", "100.64.0.1:443")
	if err == nil || strings.Contains(err.Error(), "test-key") || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("unexpected dial error: %v", err)
	}
	e.ResetNetwork()
	e.ResetNetwork()
	if starts != 2 || e.TailscaleStatus().State != api.TailscaleRunning || e.OutboundInstance("tailscale/home") != out {
		t.Fatalf("network reset did not recover the existing outbound: starts=%d, status=%+v", starts, e.TailscaleStatus())
	}
}
