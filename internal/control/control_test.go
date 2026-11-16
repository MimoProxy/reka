package control

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	rt "github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/secret"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const testProfile = `schema-version: 1
outbounds:
  - {id: alt, type: direct}
groups:
  - {id: proxy, type: select, members: [direct, alt]}
rules:
  - id: cn
    match: {domain-suffix: cn}
    outbound: direct
  - id: lan
    match: {ip-cidr: 10.0.0.0/8}
    outbound: reject
  - id: final
    match: {all: true}
    outbound: proxy
`

func startServer(t *testing.T) (addr string, svc *service.Service) {
	t.Helper()
	// Unix socket paths are limited to about 100 bytes; t.TempDir is long
	// on macOS.
	dir, err := os.MkdirTemp("", "rk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sec, _ := secret.NewFileStore(filepath.Join(dir, "secrets.json"), nil)
	eng := rt.NewEngine(rt.EngineOptions{Backend: sagernet.Options{Logger: quiet()}})
	svc, err = service.Open(service.Options{StateRoot: dir, Secrets: sec, Engine: eng, Logger: quiet(), InitialProfile: []byte(testProfile)})
	if err != nil {
		t.Fatal(err)
	}
	addr = DefaultAddress(dir)
	ln, err := Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(NewHandler(svc))
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); svc.Close() })
	return addr, svc
}

func TestHelloRequired(t *testing.T) {
	addr, _ := startServer(t)
	conn, err := Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	send := func(req Request) Message {
		b, _ := json.Marshal(req)
		if err := WriteFrame(conn, b); err != nil {
			t.Fatal(err)
		}
		frame, err := ReadFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		var m Message
		json.Unmarshal(frame, &m)
		return m
	}
	if m := send(Request{ID: 1, Method: "GetStatus"}); m.Error == nil || m.Error.Code != CodeHelloRequired {
		t.Fatalf("before hello: %+v", m)
	}
	if m := send(Request{ID: 2, Method: "Hello", Params: json.RawMessage(`{"versions":[99]}`)}); m.Error == nil || m.Error.Code != CodeVersion {
		t.Fatalf("bad version: %+v", m)
	}
	if m := send(Request{ID: 3, Method: "Hello", Params: json.RawMessage(`{"versions":[1,2]}`)}); m.Error != nil || m.ID != 3 {
		t.Fatalf("hello: %+v", m)
	}
	if m := send(Request{ID: 4, Method: "Nope"}); m.Error == nil || m.Error.Code != CodeUnknownMethod {
		t.Fatalf("unknown: %+v", m)
	}
	// An oversized frame header ends the session.
	conn.Write([]byte{0xff, 0xff, 0xff, 0xff})
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := ReadFrame(conn); err == nil {
		t.Fatal("session survived an oversized frame")
	}
}

func TestContract(t *testing.T) {
	addr, _ := startServer(t)
	c, err := Connect(addr, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var caps Capabilities
	if err := c.Call("GetCapabilities", nil, &caps); err != nil || caps.APIVersion != 1 || len(caps.OutboundTypes) < 6 {
		t.Fatalf("capabilities %+v %v", caps, err)
	}
	var cfg service.Configuration
	if err := c.Call("GetConfiguration", nil, &cfg); err != nil || cfg.Revision != 1 || cfg.Effective == nil {
		t.Fatalf("configuration %+v %v", cfg, err)
	}
	if o, ok := cfg.Effective.Provenance["/groups/proxy/members"]; !ok || o.Layer != "profile" {
		t.Fatalf("provenance %+v", cfg.Effective.Provenance)
	}

	bad := "schema-version: 1\nrules:\n  - match: {all: true}\n    outbound: ghost\n"
	var v service.ValidateResult
	if err := c.Call("ValidateConfiguration", service.ChangeRequest{Profile: &bad}, &v); err != nil || v.Valid || v.Diagnostics[0].Line != 4 {
		t.Fatalf("validate %+v %v", v, err)
	}

	patch := []model.Op{{Op: "set", Path: "/groups/proxy/selected", Value: json.RawMessage(`"alt"`)}}
	var plan service.PlanResult
	if err := c.Call("PlanConfiguration", service.ChangeRequest{BaseRevision: 1, Patch: patch}, &plan); err != nil || plan.Plan == nil {
		t.Fatalf("plan %+v %v", plan, err)
	}
	if len(plan.Plan.Groups) != 1 || plan.Plan.Groups[0].To != "alt" || plan.Plan.RulesChanged {
		t.Fatalf("plan content %+v", plan.Plan)
	}
	for _, o := range plan.Plan.Outbounds {
		if o.Action != rt.ActionKeep {
			t.Fatalf("selection change touches outbound %+v", o)
		}
	}

	if err := c.Call("Subscribe", map[string]any{"types": []string{service.EventCommitted}}, nil); err != nil {
		t.Fatal(err)
	}
	if ev := <-c.Events; ev.Type != service.EventSnapshot {
		t.Fatalf("first event %+v", ev)
	}
	var res service.Result
	req := service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: 1, Patch: patch}, OperationID: "contract-1", PlanHash: plan.PlanHash}
	if err := c.Call("CommitConfiguration", req, &res); err != nil || res.State != "committed" || res.Revision != 2 {
		t.Fatalf("commit %+v %v", res, err)
	}
	select {
	case ev := <-c.Events:
		if ev.Type != service.EventCommitted {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no commit event")
	}
	var again service.Result
	if err := c.Call("CommitConfiguration", req, &again); err != nil || again.Revision != 2 {
		t.Fatalf("retry %+v %v", again, err)
	}
	var op service.Result
	if err := c.Call("GetOperation", map[string]string{"operation_id": "contract-1"}, &op); err != nil || op.Revision != 2 {
		t.Fatalf("operation %+v %v", op, err)
	}
	// A stale plan hash is refused.
	req2 := service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: 2, Patch: patch}, PlanHash: plan.PlanHash}
	if err := c.Call("CommitConfiguration", req2, &res); err != nil || res.Error == nil || res.Error.Code != service.CodePlanChanged {
		t.Fatalf("stale plan hash %+v %v", res, err)
	}

	var x rt.Explanation
	if err := c.Call("ExplainRoute", rt.ExplainRequest{Destination: "www.example.cn:443"}, &x); err != nil || x.RuleID != "cn" || x.Outbound != "direct" {
		t.Fatalf("explain cn %+v %v", x, err)
	}
	if err := c.Call("ExplainRoute", rt.ExplainRequest{Destination: "example.com:443"}, &x); err != nil || x.Undetermined == "" {
		t.Fatalf("explain without resolve %+v %v", x, err)
	}
	if err := c.Call("ExplainRoute", rt.ExplainRequest{Destination: "example.com:443", Addresses: []string{"8.8.8.8"}}, &x); err != nil || x.Outbound != "alt" || strings.Join(x.Chain, ",") != "proxy" {
		t.Fatalf("explain with address %+v %v", x, err)
	}

	var revs struct {
		Active    uint64 `json:"active"`
		Revisions []any  `json:"revisions"`
	}
	if err := c.Call("ListRevisions", nil, &revs); err != nil || revs.Active != 2 || len(revs.Revisions) != 2 {
		t.Fatalf("revisions %+v %v", revs, err)
	}
	if err := c.Call("RestoreRevision", service.RestoreRequest{Revision: 1, BaseRevision: 2}, &res); err != nil || res.Revision != 3 {
		t.Fatalf("restore %+v %v", res, err)
	}

	var sec map[string]any
	if err := c.Call("SetSecret", map[string]any{"name": "outbounds/x/password", "value": "v"}, &sec); err != nil {
		t.Fatal(err)
	}
	var names struct{ Names []string }
	if err := c.Call("ListSecrets", nil, &names); err != nil || len(names.Names) != 1 {
		t.Fatalf("secrets %+v %v", names, err)
	}
	var conns struct{ Total int }
	if err := c.Call("ListConnections", nil, &conns); err != nil {
		t.Fatal(err)
	}
	var se *service.Error
	if err := c.Call("CloseConnections", nil, nil); !errors.As(err, &se) || se.Code != service.CodeBadRequest {
		t.Fatalf("close without ids: %v", err)
	}
	var st Status
	if err := c.Call("GetStatus", nil, &st); err != nil || st.Revision != 3 {
		t.Fatalf("status %+v %v", st, err)
	}
}

// TestSlowConsumer subscribes and stops reading; the server must keep
// working and tell the client how many events it lost.
func TestSlowConsumer(t *testing.T) {
	addr, svc := startServer(t)
	conn, err := Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	call := func(id uint64, method, params string) {
		b, _ := json.Marshal(Request{ID: id, Method: method, Params: json.RawMessage(params)})
		WriteFrame(conn, b)
	}
	call(1, "Hello", `{"versions":[1]}`)
	call(2, "Subscribe", `{}`)
	// Requests are asynchronous. Confirm the subscription exists before
	// flooding; otherwise fast publishers can finish before Subscribe runs.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		frame, err := ReadFrame(conn)
		if err != nil {
			t.Fatal("subscription acknowledgement", err)
		}
		var message Message
		if err = json.Unmarshal(frame, &message); err != nil {
			t.Fatal(err)
		}
		if message.ID == 2 {
			if message.Error != nil {
				t.Fatal(message.Error)
			}
			break
		}
	}
	conn.SetReadDeadline(time.Time{})
	// Flood far more events than socket buffers and the queue hold.
	payload := strings.Repeat("x", 4096)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			svc.Events().Publish("test", payload)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("publisher blocked by a slow subscriber")
	}
	// Now drain and look for a dropped count; keep publishing so some event
	// after the gap gets through to carry it.
	stopTick := make(chan struct{})
	defer close(stopTick)
	go func() {
		for {
			select {
			case <-stopTick:
				return
			case <-time.After(20 * time.Millisecond):
				svc.Events().Publish("test", "after")
			}
		}
	}()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var dropped uint64
	for i := 0; i < 6000 && dropped == 0; i++ {
		frame, err := ReadFrame(conn)
		if err != nil {
			break
		}
		var m Message
		json.Unmarshal(frame, &m)
		if m.Event != nil && m.Event.Dropped > 0 {
			dropped = m.Event.Dropped
		}
	}
	if dropped == 0 {
		t.Fatal("no dropped count reported")
	}
	t.Logf("dropped %d events", dropped)
}
