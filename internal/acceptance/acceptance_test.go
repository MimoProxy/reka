package acceptance

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/control"
	"github.com/MimoProxy/reka/internal/runtime/generation"
)

const baseProfile = `schema-version: 1
outbounds:
  - {id: alt, type: direct}
groups:
  - id: proxy
    type: select
    members: [direct, alt]
rules:
  - id: loopback
    match: {ip-cidr: 127.0.0.0/8}
    outbound: proxy
  - id: final
    match: {all: true}
    outbound: direct
`

func TestDomainSniffingDefaultAndOptOut(t *testing.T) {
	const profile = `schema-version: 1
outbounds:
  - {id: by-domain, type: direct}
rules:
  - {match: {domain: sniff.test}, outbound: by-domain}
  - {match: {all: true}, outbound: direct}
`
	for _, tt := range []struct {
		name, sniff, outbound string
	}{
		{name: "default", outbound: "by-domain"},
		{name: "disabled", sniff: "sniff: {enabled: false}\n", outbound: "direct"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, profile+tt.sniff)
			target := echoServer(t)
			conn, err := socks5Connect(h.proxy(), target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			const request = "GET / HTTP/1.1\r\nHost: sniff.test\r\n\r\n"
			if _, err := io.WriteString(conn, request); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(request))
			if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != request {
				t.Fatalf("original target did not echo the whole request: %q, %v", reply, err)
			}
			if rows := connsByDest(h, target.String()); len(rows) != 1 || rows[0].Outbound != tt.outbound {
				t.Fatalf("connections = %+v, want outbound %s", rows, tt.outbound)
			}
		})
	}
}

// Long connection while rules and the group selection change: the old
// connection keeps its outbound and every byte; new connections follow the
// new configuration; listeners and outbound instances are not rebuilt.
func TestRuleAndSelectionChangeKeepConnections(t *testing.T) {
	h := newHarness(t, baseProfile)
	echo := echoServer(t)
	listener := h.engine().ListenerInstance("mixed")
	direct, alt := h.engine().OutboundInstance("direct"), h.engine().OutboundInstance("alt")

	old := openStream(t, h.proxy(), echo)
	waitFor(t, "old connection", 2*time.Second, func() bool { return len(connsByDest(h, echo.String())) == 1 })
	before := connsByDest(h, echo.String())[0]
	if before.Outbound != "direct" || before.RuleID != "loopback" {
		t.Fatalf("old connection routed %+v", before)
	}
	time.Sleep(200 * time.Millisecond)

	req := patch("/groups/proxy/selected", `"alt"`)
	req.Patch = append(req.Patch, model.Op{Op: "insert", Path: "/rules", Before: "loopback",
		Value: []byte(`{"id":"echo-port","match":{"dst-port":` + fmt.Sprint(echo.Port()) + `},"outbound":"proxy"}`)})
	res := h.mustCommit(req)
	for _, o := range res.Plan.Outbounds {
		if o.Action != generation.ActionKeep {
			t.Fatalf("rule change touched outbound %+v", o)
		}
	}
	fresh := openStream(t, h.proxy(), echo)
	waitFor(t, "new connection", 2*time.Second, func() bool { return len(connsByDest(h, echo.String())) == 2 })
	for _, c := range connsByDest(h, echo.String()) {
		switch c.ID {
		case before.ID:
			if c.Outbound != "direct" || c.Generation != before.Generation {
				t.Fatalf("old connection moved: %+v", c)
			}
		default:
			if c.Outbound != "alt" || c.RuleID != "echo-port" || c.Generation == before.Generation {
				t.Fatalf("new connection not on the new generation: %+v", c)
			}
		}
	}
	time.Sleep(300 * time.Millisecond)
	if err := old.finish(); err != nil {
		t.Fatalf("old connection: %v", err)
	}
	if err := fresh.finish(); err != nil {
		t.Fatalf("new connection: %v", err)
	}
	if h.engine().ListenerInstance("mixed") != listener {
		t.Fatal("the listener was rebuilt")
	}
	if h.engine().OutboundInstance("direct") != direct || h.engine().OutboundInstance("alt") != alt {
		t.Fatal("outbound instances were rebuilt")
	}
	t.Logf("old stream %d bytes, new stream %d bytes", old.received.Load(), fresh.received.Load())
}

// Changing a node's credentials: the old instance serves only the
// connections it already has and closes once they end.
func TestCredentialChangeDrainsOldInstance(t *testing.T) {
	pw1, pw2 := newSSKey(), newSSKey()
	s1, s2 := ssServer(t, pw1), ssServer(t, pw2)
	profile := fmt.Sprintf(`schema-version: 1
outbounds:
  - {id: node, type: shadowsocks, server: 127.0.0.1, port: %d, method: %s, password: %q}
rules:
  - {id: final, match: {all: true}, outbound: node}
`, s1.Port(), ssMethod, pw1)
	h := newHarness(t, profile)
	echo := echoServer(t)
	oldInstance := h.engine().OutboundInstance("node")
	old := openStream(t, h.proxy(), echo)
	waitFor(t, "old connection", 2*time.Second, func() bool { return oldInstance.Active() == 1 })

	res := h.mustCommit(patch("/outbounds/node/port", fmt.Sprint(s2.Port()), "/outbounds/node/password", fmt.Sprintf("%q", pw2)))
	for _, o := range res.Plan.Outbounds {
		if o.ID == "node" && (o.Action != generation.ActionReplace || o.Connections != 1) {
			t.Fatalf("plan %+v", res.Plan.Outbounds)
		}
	}
	newInstance := h.engine().OutboundInstance("node")
	if newInstance == oldInstance || !oldInstance.Lease().Retired() {
		t.Fatal("instance not replaced")
	}
	fresh := openStream(t, h.proxy(), echo)
	waitFor(t, "new connection on the new instance", 2*time.Second, func() bool { return newInstance.Active() == 1 })
	if oldInstance.Active() != 1 || h.engine().Status().Draining != 1 {
		t.Fatalf("old instance active=%d draining=%d", oldInstance.Active(), h.engine().Status().Draining)
	}
	time.Sleep(300 * time.Millisecond)
	if err := old.finish(); err != nil {
		t.Fatalf("connection on the old instance: %v", err)
	}
	waitFor(t, "old instance closed", 5*time.Second, func() bool { return h.engine().Status().Draining == 0 })
	if err := fresh.finish(); err != nil {
		t.Fatalf("connection on the new instance: %v", err)
	}
	if st := h.engine().Status(); st.Forced != 0 {
		t.Fatalf("forced closes: %d", st.Forced)
	}
}

func serveControl(t *testing.T, h *harness) string {
	t.Helper()
	addr := control.DefaultAddress(h.root)
	ln, err := control.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := control.NewServer(control.NewHandler(h.svc))
	go srv.Serve(ln)
	t.Cleanup(srv.Close)
	return addr
}

// Two clients commit against the same base: one wins, the other gets a
// conflict with the field differences.
func TestTwoClientsSameBase(t *testing.T) {
	h := newHarness(t, baseProfile)
	addr := serveControl(t, h)
	a, err := control.Connect(addr, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := control.Connect(addr, "b")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var ca, cb service.Configuration
	a.Call("GetConfiguration", nil, &ca)
	b.Call("GetConfiguration", nil, &cb)
	commit := func(c *control.Client, base uint64, sel string) service.Result {
		var res service.Result
		req := service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: base,
			Patch: []model.Op{{Op: "set", Path: "/groups/proxy/selected", Value: []byte(`"` + sel + `"`)}}}}
		if err := c.Call("CommitConfiguration", req, &res); err != nil {
			t.Fatal(err)
		}
		return res
	}
	ra := commit(a, ca.Revision, "alt")
	rb := commit(b, cb.Revision, "direct")
	if ra.State != "committed" || rb.State != "rejected" || rb.Error.Code != service.CodeConflict {
		t.Fatalf("a=%+v b=%+v", ra, rb)
	}
	if len(rb.Conflict.Changes) != 1 || rb.Conflict.Changes[0].Path != "/groups/proxy/selected" {
		t.Fatalf("conflict %+v", rb.Conflict)
	}
}

// Invalid YAML or a dangling reference: line, column and path come back;
// the active revision and its traffic are unchanged.
func TestInvalidDocumentKeepsActive(t *testing.T) {
	h := newHarness(t, baseProfile)
	echo := echoServer(t)
	for _, c := range []struct {
		doc, code, path string
		line, col       int
	}{
		{"schema-version: 1\nrules:\n  - match: {all: true\n", "yaml.syntax", "", 2, 0},
		{strings.Replace(baseProfile, "outbound: proxy", "outbound: prxy", 1), "rule.outbound", "/rules/loopback/outbound", 11, 15},
		{strings.Replace(baseProfile, "members: [direct, alt]", "members: [direct, gone]", 1), "group.member", "/groups/proxy/members", 7, 14},
	} {
		doc := c.doc
		res := h.commit(service.CommitRequest{ChangeRequest: service.ChangeRequest{Profile: &doc}})
		if res.State != "rejected" || len(res.Diagnostics) == 0 {
			t.Fatalf("%s: %+v", c.code, res)
		}
		d := res.Diagnostics[0]
		if d.Code != c.code || d.Path != c.path || d.Line != c.line || (c.col > 0 && d.Column != c.col) {
			t.Fatalf("got %s (line %d col %d), want %s at %s %d:%d", d, d.Line, d.Column, c.code, c.path, c.line, c.col)
		}
	}
	if h.svc.ActiveRevision() != 1 {
		t.Fatal("revision changed")
	}
	if err := openStream(t, h.proxy(), echo).finish(); err != nil {
		t.Fatal(err)
	}
}

// A commit whose response is lost is found by its operation ID, and
// retrying it does not apply it twice.
func TestLostResponseRetry(t *testing.T) {
	h := newHarness(t, baseProfile)
	addr := serveControl(t, h)
	conn, err := control.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	send := func(id int, method string, params any) {
		p, _ := json.Marshal(params)
		b, _ := json.Marshal(control.Request{ID: uint64(id), Method: method, Params: p})
		control.WriteFrame(conn, b)
	}
	send(1, "Hello", control.HelloParams{Versions: []int{1}})
	req := service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: 1,
		Patch: []model.Op{{Op: "set", Path: "/groups/proxy/selected", Value: []byte(`"alt"`)}}}, OperationID: "lost-1"}
	send(2, "CommitConfiguration", req)
	conn.Close() // the client goes away before reading the response
	waitFor(t, "commit to land", 5*time.Second, func() bool { return h.svc.ActiveRevision() == 2 })

	c, err := control.Connect(addr, "retry")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var op service.Result
	if err := c.Call("GetOperation", map[string]string{"operation_id": "lost-1"}, &op); err != nil || op.State != "committed" || op.Revision != 2 {
		t.Fatalf("operation %+v %v", op, err)
	}
	var again service.Result
	if err := c.Call("CommitConfiguration", req, &again); err != nil || again.Revision != 2 {
		t.Fatalf("retry %+v %v", again, err)
	}
	revs, _ := h.svc.ListRevisions()
	if len(revs) != 2 || h.svc.ActiveRevision() != 2 {
		t.Fatalf("%d revisions, active %d", len(revs), h.svc.ActiveRevision())
	}
}

// A crash at each persistence and switch point: after restart exactly one
// revision is active, and the traffic, the disk and the operation record
// agree on which.
func TestCrashAtEachPoint(t *testing.T) {
	for _, point := range []string{"revision-written", "intent-written", "activated", "active-written", "op-committed"} {
		t.Run(point, func(t *testing.T) {
			h := newHarness(t, baseProfile)
			echo := echoServer(t)
			h.fail = func(p string) error {
				if p == point {
					return errors.New("crash")
				}
				return nil
			}
			req := patch("/groups/proxy/selected", `"alt"`)
			req.BaseRevision, req.OperationID = 1, "crash"
			_, err := h.svc.Commit(context.Background(), req)
			if !errors.Is(err, service.ErrCrashed) {
				t.Fatalf("commit: %v", err)
			}
			h.fail = nil
			h.svc.Close()
			h.open("")
			committed := point == "active-written" || point == "op-committed"
			want := map[bool]string{true: "alt", false: "direct"}[committed]
			s := openStream(t, h.proxy(), echo)
			waitFor(t, "connection", 2*time.Second, func() bool { return len(connsByDest(h, echo.String())) == 1 })
			got := connsByDest(h, echo.String())[0]
			if err := s.finish(); err != nil {
				t.Fatal(err)
			}
			op, opErr := h.svc.GetOperation("crash")
			t.Logf("revision %d, connection via %s, operation %+v (%v)", h.svc.ActiveRevision(), got.Outbound, op.State, opErr)
			if got.Outbound != want || got.Revision != h.svc.ActiveRevision() {
				t.Fatalf("traffic uses %s at revision %d; active %d, want %s", got.Outbound, got.Revision, h.svc.ActiveRevision(), want)
			}
			if committed != (opErr == nil && op.State == "committed") {
				t.Fatalf("operation %+v %v does not match the active revision", op, opErr)
			}
		})
	}
}

// A listener on a port that is taken: preparation fails, the old
// configuration keeps running.
func TestPortInUse(t *testing.T) {
	h := newHarness(t, baseProfile)
	echo := echoServer(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	local := fmt.Sprintf("listeners:\n  - {id: mixed, type: mixed, listen: \"127.0.0.1:%d\"}\n", h.port) +
		fmt.Sprintf("  - {id: second, type: socks, listen: %q}\n", busy.Addr().String())
	res := h.commit(service.CommitRequest{ChangeRequest: service.ChangeRequest{Local: &local}})
	if res.State != "rejected" || res.Error.Code != service.CodePrepare || res.Diagnostics[len(res.Diagnostics)-1].Path != "/listeners/second/listen" {
		t.Fatalf("%+v", res)
	}
	if err := openStream(t, h.proxy(), echo).finish(); err != nil {
		t.Fatal(err)
	}
}

// 1,000 updates (selection changes and instance replacements) with
// connections in flight; once every connection is closed, goroutines,
// descriptors and draining instances are back to the baseline.
func TestThousandUpdatesReturnToBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	h := newHarness(t, baseProfile)
	echo := echoServer(t)
	warm := openStream(t, h.proxy(), echo)
	if err := warm.finish(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	goruntime.GC()
	baseG := goruntime.NumGoroutine()
	baseFD, haveFD := fdCount()

	var open []*stream
	start := time.Now()
	for i := 0; i < 1000; i++ {
		var req service.CommitRequest
		if i%10 == 9 {
			// Replace the alt instance: its fingerprint follows udp.
			req = patch("/outbounds/alt/udp", fmt.Sprint(i%20 == 9))
		} else {
			req = patch("/groups/proxy/selected", map[bool]string{true: `"alt"`, false: `"direct"`}[i%2 == 0])
		}
		h.mustCommit(req)
		if i%50 == 0 {
			open = append(open, openStream(t, h.proxy(), echo))
		}
		if len(open) > 4 {
			if err := open[0].finish(); err != nil {
				t.Fatalf("update %d: %v", i, err)
			}
			open = open[1:]
		}
	}
	elapsed := time.Since(start)
	for _, s := range open {
		if err := s.finish(); err != nil {
			t.Fatal(err)
		}
	}
	h.engine().CloseConnections(nil)
	waitFor(t, "draining instances", 10*time.Second, func() bool { return h.engine().Status().Draining == 0 })
	var g, fd int
	waitFor(t, "goroutines and descriptors", 10*time.Second, func() bool {
		goruntime.GC()
		g = goruntime.NumGoroutine()
		fd, _ = fdCount()
		return g <= baseG+2 && (!haveFD || fd <= baseFD+2)
	})
	st := h.engine().Status()
	t.Logf("1000 commits in %v (%.1f ms each); goroutines %d -> %d, fds %d -> %d, generation %d, forced %d",
		elapsed, float64(elapsed.Microseconds())/1000/1000, baseG, g, baseFD, fd, st.Generation, st.Forced)
	if st.Connections != 0 || st.Forced != 0 {
		t.Fatalf("status %+v", st)
	}
}

// Half-close: outbounds that cannot half-close (Shadowsocks, REALITY)
// still deliver the whole reply.
func TestHalfCloseFullReply(t *testing.T) {
	pw := newSSKey()
	ss := ssServer(t, pw)
	_, realityYAML := realityServer(t)
	profile := fmt.Sprintf(`schema-version: 1
outbounds:
  - {id: ss, type: shadowsocks, server: 127.0.0.1, port: %d, method: %s, password: %q}
%sgroups:
  - {id: proxy, type: select, members: [direct, ss, reality]}
rules:
  - {id: final, match: {all: true}, outbound: proxy}
`, ss.Port(), ssMethod, pw, realityYAML)
	h := newHarness(t, profile)
	echo := echoServer(t)
	for _, via := range []string{"direct", "ss", "reality"} {
		t.Run(via, func(t *testing.T) {
			h.mustCommit(patch("/groups/proxy/selected", `"`+via+`"`))
			for i := 0; i < 10; i++ {
				c, err := socks5Connect(h.proxy(), echo)
				if err != nil {
					t.Fatal(err)
				}
				payload := make([]byte, 256<<10+i*997)
				for j := range payload {
					payload[j] = byte(j * 7)
				}
				c.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Write(payload); err != nil {
					t.Fatal(err)
				}
				c.(*net.TCPConn).CloseWrite()
				got, err := io.ReadAll(c)
				c.Close()
				if err != nil || len(got) != len(payload) {
					t.Fatalf("round %d: got %d of %d bytes: %v", i, len(got), len(payload), err)
				}
			}
		})
	}
}

// socks5UDP opens a UDP ASSOCIATE session.
type socks5UDP struct {
	ctrl  net.Conn
	udp   *net.UDPConn
	relay *net.UDPAddr
}

func associate(t *testing.T, proxy netip.AddrPort) *socks5UDP {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy.String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0})
	var b [2]byte
	io.ReadFull(c, b[:])
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	head := make([]byte, 10)
	if _, err := io.ReadFull(c, head); err != nil || head[1] != 0 {
		t.Fatalf("udp associate: %v %v", head, err)
	}
	relay := &net.UDPAddr{IP: net.IP(head[4:8]), Port: int(binary.BigEndian.Uint16(head[8:10]))}
	if relay.IP.IsUnspecified() {
		relay.IP = net.IPv4(127, 0, 0, 1)
	}
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &socks5UDP{ctrl: c, udp: u, relay: relay}
	t.Cleanup(func() { u.Close(); c.Close() })
	return s
}

func (s *socks5UDP) send(to netip.AddrPort, payload string) {
	pkt := []byte{0, 0, 0, 1}
	pkt = append(pkt, to.Addr().AsSlice()...)
	pkt = binary.BigEndian.AppendUint16(pkt, to.Port())
	s.udp.WriteToUDP(append(pkt, payload...), s.relay)
}

// recv returns replies keyed by their source.
func (s *socks5UDP) recv(wait time.Duration) map[string]string {
	out := map[string]string{}
	buf := make([]byte, 2048)
	s.udp.SetReadDeadline(time.Now().Add(wait))
	for {
		n, _, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			return out
		}
		if n < 10 {
			continue
		}
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(buf[4:8])), binary.BigEndian.Uint16(buf[8:10]))
		out[src.String()] += string(buf[10:n])
	}
}

func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			u.WriteToUDP(buf[:n], from)
		}
	}()
	return u.LocalAddr().(*net.UDPAddr).AddrPort()
}

// UDP is split by destination: in one association each destination is
// routed on its own and keeps the generation it was created in.
func TestUDPPerDestination(t *testing.T) {
	a, b, c := udpEcho(t), udpEcho(t), udpEcho(t)
	profile := fmt.Sprintf(`schema-version: 1
rules:
  - {id: block-b, match: {dst-port: %d}, outbound: reject}
  - {id: block-c, match: {dst-port: %d}, outbound: reject}
  - {id: final, match: {all: true}, outbound: direct}
`, b.Port(), c.Port())
	h := newHarness(t, profile)
	s := associate(t, h.proxy())
	s.send(a, "to-a")
	s.send(b, "to-b")
	got := s.recv(500 * time.Millisecond)
	if got[a.String()] != "to-a" || got[b.String()] != "" {
		t.Fatalf("replies %v", got)
	}
	// New rules: a is now blocked, c allowed. The existing flow to a keeps
	// its generation; c follows the new rules.
	doc := strings.Replace(strings.Replace(profile, fmt.Sprint(b.Port()), fmt.Sprint(a.Port()), 1), "block-c, match: {dst-port: "+fmt.Sprint(c.Port()), "block-c, match: {dst-port: 1", 1)
	h.mustCommit(service.CommitRequest{ChangeRequest: service.ChangeRequest{Profile: &doc}})
	s.send(a, "again-a")
	s.send(c, "to-c")
	got = s.recv(500 * time.Millisecond)
	if got[a.String()] != "again-a" || got[c.String()] != "to-c" {
		t.Fatalf("after commit: %v", got)
	}
	gens := map[string]uint64{}
	for _, cn := range h.engine().Connections() {
		if cn.Network == "udp" {
			gens[cn.Destination] = cn.Generation
		}
	}
	if len(gens) != 2 || gens[a.String()] == gens[c.String()] {
		t.Fatalf("flows %v", gens)
	}
	// Idle flows are reaped.
	waitFor(t, "idle UDP flows reaped", 5*time.Second, func() bool { return len(h.engine().Connections()) == 0 })
}
