package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/secret"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func profileWith(selected string) string {
	return fmt.Sprintf(`schema-version: 1
outbounds:
  - id: alt
    type: direct
groups:
  - id: proxy
    type: select
    members: [direct, alt]
    selected: %s
rules:
  - id: final
    match: {all: true}
    outbound: proxy
`, selected)
}

func localWith(port int) string {
	return fmt.Sprintf("listeners:\n  - {id: mixed, type: mixed, listen: \"127.0.0.1:%d\"}\n", port)
}

type env struct {
	t    *testing.T
	root string
	sec  secret.Store
	fail func(string) error
}

func newEnv(t *testing.T) *env {
	root := t.TempDir()
	sec, err := secret.NewFileStore(filepath.Join(root, "secrets", "secrets.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, root: root, sec: sec}
}

func (e *env) open(initialProfile, initialLocal string) *Service {
	e.t.Helper()
	eng := generation.NewEngine(generation.EngineOptions{Backend: backendOptions(), DrainTimeout: 5 * time.Second})
	s, err := Open(Options{StateRoot: e.root, Secrets: e.sec, Engine: eng, Logger: quiet(),
		InitialProfile: []byte(initialProfile), InitialLocal: []byte(initialLocal), FailPoint: e.fail})
	if err != nil {
		eng.Close()
		e.t.Fatal(err)
	}
	return s
}

func commitProfile(t *testing.T, s *Service, base uint64, profile, op string) Result {
	t.Helper()
	res, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: base, Profile: &profile}, OperationID: op})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func selected(t *testing.T, s *Service) string {
	t.Helper()
	eff, _ := s.Engine().Effective()
	out, _, err := eff.Router.Resolve("proxy")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCommitAndConflict(t *testing.T) {
	e := newEnv(t)
	port := freePort(t)
	s := e.open(profileWith("direct"), localWith(port))
	defer s.Close()
	if s.ActiveRevision() != 1 {
		t.Fatalf("initial revision %d", s.ActiveRevision())
	}
	// Two clients edit revision 1.
	a := commitProfile(t, s, 1, profileWith("alt"), "client-a")
	if a.State != store.OpCommitted || a.Revision != 2 {
		t.Fatalf("client a: %+v", a)
	}
	b := commitProfile(t, s, 1, strings.Replace(profileWith("direct"), "alt", "alt2", -1), "client-b")
	if b.State != store.OpRejected || b.Error.Code != CodeConflict || b.Conflict == nil {
		t.Fatalf("client b: %+v", b)
	}
	found := false
	for _, ch := range b.Conflict.Changes {
		if ch.Path == "/groups/proxy/selected" && ch.From == "direct" && ch.To == "alt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("conflict diff %+v", b.Conflict.Changes)
	}
	if selected(t, s) != "alt" {
		t.Fatal("runtime does not run revision 2")
	}
}

func TestOperationIDIdempotent(t *testing.T) {
	e := newEnv(t)
	s := e.open(profileWith("direct"), localWith(freePort(t)))
	defer s.Close()
	first := commitProfile(t, s, 1, profileWith("alt"), "op-1")
	// The response was lost; the client retries the same request.
	again := commitProfile(t, s, 1, profileWith("alt"), "op-1")
	if again.Revision != first.Revision || again.State != store.OpCommitted {
		t.Fatalf("retry returned %+v, first %+v", again, first)
	}
	revs, _ := s.ListRevisions()
	if len(revs) != 2 {
		t.Fatalf("%d revisions after retry, want 2", len(revs))
	}
	// Same ID, different content.
	_, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 2, Patch: []model.Op{{Op: "set", Path: "/groups/proxy/selected", Value: []byte(`"direct"`)}}}, OperationID: "op-1"})
	var se *Error
	if !errors.As(err, &se) || se.Code != CodeOpReused {
		t.Fatalf("reused id: %v", err)
	}
	got, err := s.GetOperation("op-1")
	if err != nil || got.Revision != 2 {
		t.Fatalf("GetOperation: %+v %v", got, err)
	}
}

func TestInvalidKeepsActive(t *testing.T) {
	e := newEnv(t)
	s := e.open(profileWith("direct"), localWith(freePort(t)))
	defer s.Close()
	res := commitProfile(t, s, 1, "schema-version: 1\nrules:\n  - match: {all: true}\n    outbound: nowhere\n", "")
	if res.State != store.OpRejected || len(res.Diagnostics) == 0 || res.Diagnostics[0].Line != 4 || res.Diagnostics[0].Path != "/rules/#0/outbound" {
		t.Fatalf("dangling: %+v", res)
	}
	res = commitProfile(t, s, 1, "schema-version: 1\nrules: [\n", "")
	if res.State != store.OpRejected || res.Diagnostics[0].Code != "yaml.syntax" {
		t.Fatalf("syntax: %+v", res)
	}
	if s.ActiveRevision() != 1 || selected(t, s) != "direct" {
		t.Fatal("active revision changed")
	}
}

func TestPortInUseFailsInPrepare(t *testing.T) {
	e := newEnv(t)
	port := freePort(t)
	s := e.open(profileWith("direct"), localWith(port))
	defer s.Close()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	local := localWith(busy.Addr().(*net.TCPAddr).Port)
	res, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 1, Local: &local}})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != store.OpRejected || res.Error.Code != CodePrepare {
		t.Fatalf("busy port: %+v", res)
	}
	// The old listener still accepts.
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("old listener gone: %v", err)
	}
	c.Close()
	if s.ActiveRevision() != 1 {
		t.Fatal("revision changed")
	}
}

func TestPatchKeepsComments(t *testing.T) {
	e := newEnv(t)
	prof := "# my profile\n" + strings.Replace(profileWith("direct"), "selected: direct", "selected: direct # pick one", 1)
	s := e.open(prof, localWith(freePort(t)))
	defer s.Close()
	res, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 1,
		Patch: []model.Op{{Op: "set", Path: "/groups/proxy/selected", Value: []byte(`"alt"`)}}}})
	if err != nil || res.State != store.OpCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	cfg := s.GetConfiguration(false)
	if !strings.Contains(cfg.Profile, "# my profile") || !strings.Contains(cfg.Profile, "selected: alt # pick one") {
		t.Fatalf("profile after patch:\n%s", cfg.Profile)
	}
}

func TestMaskedReadBack(t *testing.T) {
	e := newEnv(t)
	prof := profileWith("direct") + `  - id: ss-rule
    match: {domain: ss.test}
    outbound: ss
`
	prof = strings.Replace(prof, "outbounds:\n", "outbounds:\n  - {id: ss, type: shadowsocks, server: 192.0.2.1, port: 8388, method: aes-128-gcm, password: hunter2}\n", 1)
	prof = strings.Replace(prof, "  - id: ss-rule\n    match: {domain: ss.test}\n    outbound: ss\n", "", 1)
	s := e.open(prof, localWith(freePort(t)))
	defer s.Close()
	cfg := s.GetConfiguration(false)
	if strings.Contains(cfg.Profile, "hunter2") || cfg.Masked != 1 {
		t.Fatalf("not masked:\n%s", cfg.Profile)
	}
	// Send the masked document back with another change.
	edited := strings.Replace(cfg.Profile, "selected: direct", "selected: alt", 1)
	res := commitProfile(t, s, 1, edited, "")
	if res.State != store.OpCommitted {
		t.Fatalf("%+v", res)
	}
	_, profile, _ := s.Documents()
	if !strings.Contains(string(profile), "hunter2") {
		t.Fatalf("mask overwrote the password:\n%s", profile)
	}
	if !strings.Contains(s.GetConfiguration(true).Profile, "hunter2") {
		t.Fatal("reveal does not show the password")
	}
}

func TestRestoreRevision(t *testing.T) {
	e := newEnv(t)
	s := e.open(profileWith("direct"), localWith(freePort(t)))
	defer s.Close()
	commitProfile(t, s, 1, profileWith("alt"), "")
	res, err := s.RestoreRevision(context.Background(), RestoreRequest{Revision: 1, BaseRevision: 2})
	if err != nil || res.State != store.OpCommitted || res.Revision != 3 {
		t.Fatalf("restore: %+v %v", res, err)
	}
	if selected(t, s) != "direct" {
		t.Fatal("restore not active")
	}
	revs, _ := s.ListRevisions()
	if revs[0].RestoredFrom != 1 || revs[0].Source != "restore" {
		t.Fatalf("revisions %+v", revs)
	}
}

// TestCrashPoints aborts a commit at each persistence and switch point,
// "restarts" from the same state root and checks that exactly one of the
// old or new revision is active, consistently on disk, in the runtime and
// in the operation record.
func TestCrashPoints(t *testing.T) {
	points := []struct {
		name      string
		committed bool
	}{
		{"revision-written", false},
		{"intent-written", false},
		{"activated", false},
		{"active-written", true},
		{"op-committed", true},
	}
	for _, p := range points {
		t.Run(p.name, func(t *testing.T) {
			e := newEnv(t)
			port := freePort(t)
			s := e.open(profileWith("direct"), localWith(port))
			e.fail = nil
			s.opts.FailPoint = func(point string) error {
				if point == p.name {
					return errors.New("crash")
				}
				return nil
			}
			_, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 1, Profile: ptr(profileWith("alt"))}, OperationID: "op-crash"})
			if !errors.Is(err, ErrCrashed) {
				t.Fatalf("commit: %v", err)
			}
			s.Close() // the process dies

			s2 := e.open("", "")
			defer s2.Close()
			wantRev, wantSel := uint64(1), "direct"
			if p.committed {
				wantRev, wantSel = 2, "alt"
			}
			if s2.ActiveRevision() != wantRev || selected(t, s2) != wantSel {
				t.Fatalf("after restart: revision %d selected %s, want %d %s", s2.ActiveRevision(), selected(t, s2), wantRev, wantSel)
			}
			op, err := s2.GetOperation("op-crash")
			switch {
			case p.name == "revision-written":
				// Crashed before the intent was recorded: no operation.
				if err == nil {
					t.Fatalf("operation recorded: %+v", op)
				}
			case p.committed:
				if err != nil || op.State != store.OpCommitted || op.Revision != 2 {
					t.Fatalf("operation %+v %v", op, err)
				}
			default:
				if err != nil || op.State != store.OpFailed {
					t.Fatalf("operation %+v %v", op, err)
				}
			}
			revs, _ := s2.ListRevisions()
			if len(revs) != int(wantRev) {
				t.Fatalf("%d revisions on disk, want %d", len(revs), wantRev)
			}
			// The next commit works and does not reuse a failed number.
			res := commitProfile(t, s2, wantRev, profileWith("direct")+"# next\n", "")
			if res.State != store.OpCommitted || res.Revision <= wantRev {
				t.Fatalf("next commit %+v", res)
			}
			if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err != nil {
				t.Fatalf("listener after restart: %v", err)
			} else {
				c.Close()
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestConcurrentCommits(t *testing.T) {
	e := newEnv(t)
	s := e.open(profileWith("direct"), localWith(freePort(t)))
	defer s.Close()
	const n = 8
	results := make(chan Result, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			sel := []string{"direct", "alt"}[i%2]
			p := profileWith(sel) + fmt.Sprintf("# client %d\n", i)
			res, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 1, Profile: &p}})
			if err != nil {
				t.Error(err)
			}
			results <- res
		}(i)
	}
	ok, conflicts := 0, 0
	for i := 0; i < n; i++ {
		r := <-results
		switch {
		case r.State == store.OpCommitted:
			ok++
		case r.Error != nil && r.Error.Code == CodeConflict:
			conflicts++
		}
	}
	if ok != 1 || conflicts != n-1 {
		t.Fatalf("%d committed, %d conflicts", ok, conflicts)
	}
}

func TestEvents(t *testing.T) {
	e := newEnv(t)
	s := e.open(profileWith("direct"), localWith(freePort(t)))
	defer s.Close()
	sub := s.Events().Subscribe(nil, "", 0, func() any { return "state" })
	defer sub.Close()
	if ev := <-sub.C; ev.Type != EventSnapshot {
		t.Fatalf("first event %+v", ev)
	}
	commitProfile(t, s, 1, profileWith("alt"), "")
	ev := <-sub.C
	if ev.Type != EventCommitted {
		t.Fatalf("event %+v", ev)
	}
	// Resume from the cursor: the runtime event is replayed, no snapshot.
	sub2 := s.Events().Subscribe(nil, ev.Epoch, ev.Seq, nil)
	defer sub2.Close()
	if ev2 := <-sub2.C; ev2.Type != EventRuntime || ev2.Seq != ev.Seq+1 {
		t.Fatalf("replayed %+v", ev2)
	}
	// A slow subscriber loses events and is told how many.
	slow := s.Events().Subscribe(nil, ev.Epoch, s.Events().seq, nil)
	defer slow.Close()
	for i := 0; i < subscriberSize+10; i++ {
		s.Events().Publish("test", i)
	}
	for i := 0; i < subscriberSize; i++ {
		<-slow.C
	}
	s.Events().Publish("test", "last")
	if last := <-slow.C; last.Dropped != 10 {
		t.Fatalf("dropped = %d, want 10", last.Dropped)
	}
}

func TestCandidateFile(t *testing.T) {
	e := newEnv(t)
	s := e.open(profileWith("direct"), localWith(freePort(t)))
	defer s.Close()
	dir := filepath.Join(e.root, "edit")
	c := s.NewCandidate(dir)
	c.Interval = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	path := filepath.Join(dir, "profile.yaml")
	waitFor(t, func() bool { b, _ := os.ReadFile(path); return string(b) == profileWith("direct") })

	// A broken save is reported and the active revision keeps running.
	os.WriteFile(path, []byte("schema-version: 1\nrules: [\n"), 0o600)
	waitFor(t, func() bool { _, err := os.Stat(path + ".errors"); return err == nil })
	if s.ActiveRevision() != 1 {
		t.Fatal("broken file changed the revision")
	}
	// A fixed save is committed.
	os.WriteFile(path, []byte(profileWith("alt")), 0o600)
	waitFor(t, func() bool { return s.ActiveRevision() == 2 })
	if selected(t, s) != "alt" {
		t.Fatal("file edit not active")
	}
	waitFor(t, func() bool { _, err := os.Stat(path + ".errors"); return err != nil })
	// An API commit rewrites the untouched file.
	commitProfile(t, s, 2, profileWith("direct")+"# from api\n", "")
	waitFor(t, func() bool { b, _ := os.ReadFile(path); return strings.Contains(string(b), "# from api") })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// An initial import that only lacks secrets is stored but not started;
// storing the secret and re-applying starts it.
func TestInitialWaitsForSecrets(t *testing.T) {
	e := newEnv(t)
	prof := strings.Replace(profileWith("alt"), "outbounds:\n", "outbounds:\n  - {id: ss, type: shadowsocks, server: 192.0.2.1, port: 8388, method: aes-128-gcm, password: secret://outbounds/ss/password}\n", 1)
	s := e.open(prof, localWith(freePort(t)))
	defer s.Close()
	if s.ActiveRevision() != 1 || s.StartError() == "" {
		t.Fatalf("revision %d, start error %q", s.ActiveRevision(), s.StartError())
	}
	if eff, _ := s.Engine().Effective(); eff != nil {
		t.Fatal("started without its secret")
	}
	e.sec.Set("outbounds/ss/password", "pw")
	res, err := s.Reapply(context.Background(), "secret")
	if err != nil || res.State != store.OpCommitted || res.Revision != 2 {
		t.Fatalf("reapply %+v %v", res, err)
	}
	if s.StartError() != "" || selected(t, s) != "alt" {
		t.Fatalf("not running: %q", s.StartError())
	}
	// Other errors in the import are still fatal.
	e2 := newEnv(t)
	eng := generation.NewEngine(generation.EngineOptions{Backend: backendOptions()})
	defer eng.Close()
	if _, err := Open(Options{StateRoot: e2.root, Secrets: e2.sec, Engine: eng, Logger: quiet(),
		InitialProfile: []byte("schema-version: 1\nrules:\n  - {match: {all: true}, outbound: ghost}\n")}); err == nil {
		t.Fatal("invalid import accepted")
	}
}
