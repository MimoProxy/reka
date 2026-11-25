package generation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/script"
)

func TestScriptStoreLimits(t *testing.T) {
	s := newScriptStore("", nil)
	t.Cleanup(s.close)
	value := strings.Repeat("a", scriptStoreValueMax)
	if err := s.Write("too-large", value+"a"); err == nil {
		t.Fatal("accepted a value above its limit")
	}
	if err := s.Write(strings.Repeat("k", scriptStoreKeyMax+1), ""); err == nil {
		t.Fatal("accepted a key above its limit")
	}
	for i := 0; i < scriptStoreTotalMax/scriptStoreValueMax-1; i++ {
		if err := s.Write(strconv.Itoa(i), value); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Write("full", value); err == nil {
		t.Fatal("accepted a write above the total limit")
	}
	if _, ok, err := s.Read("full"); err != nil || ok {
		t.Fatalf("failed write became visible: %v, %v", ok, err)
	}
	if err := s.Write("0", "replacement"); err != nil {
		t.Fatal(err)
	}
	if err := s.Write("full", value); err != nil {
		t.Fatal("replacement did not release capacity", err)
	}
	if err := s.Delete("full"); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.Read("0"); got != "replacement" || !ok || err != nil {
		t.Fatalf("read replacement = %q, %v, %v", got, ok, err)
	}
	if _, ok, err := s.Read("full"); err != nil || ok {
		t.Fatalf("deleted key is still visible: %v, %v", ok, err)
	}
}

func TestScriptStoreFlush(t *testing.T) {
	root := t.TempDir()
	s := newScriptStore(root, nil)
	t.Cleanup(s.close)
	for _, value := range []string{"initial", "final"} {
		if err := s.Write("shared", value); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "scripts", "store.json")
	deadline := time.Now().Add(3 * scriptStoreFlushDelay)
	for {
		if raw, err := os.ReadFile(path); err == nil {
			var disk map[string]string
			if err := json.Unmarshal(raw, &disk); err != nil || disk["shared"] != "final" {
				t.Fatalf("persisted batch = %q, %v", raw, err)
			}
			break
		} else if time.Now().After(deadline) {
			// Windows can report a sharing violation while the atomic rename
			// is in progress, so retry any read error until the deadline.
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := s.Write("shared", "close flush"); err != nil {
		t.Fatal(err)
	}
	s.close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("store permissions = %v", info.Mode().Perm())
	}
	reopened := newScriptStore(root, nil)
	t.Cleanup(reopened.close)
	if got, ok, err := reopened.Read("shared"); got != "close flush" || !ok || err != nil {
		t.Fatalf("read from disk = %q, %v, %v", got, ok, err)
	}
}

func TestScriptNotificationRate(t *testing.T) {
	notices := newScriptNotifications()
	now := time.Unix(1, 0)
	notices.now = func() time.Time { return now }
	var received int
	notices.sink = func(api.ScriptNotification) { received++ }
	for range scriptNoticeBurst + 1 {
		notices.post("script", "", script.Notification{})
	}
	if sent, dropped := notices.counts(); sent != scriptNoticeBurst || dropped != 1 || received != scriptNoticeBurst {
		t.Fatalf("per-script limit: %d sent, %d dropped, %d received", sent, dropped, received)
	}
	now = now.Add(time.Minute / scriptNoticeRate)
	notices.post("script", "", script.Notification{})
	for i := received; i < scriptNoticeGlobal; i++ {
		notices.post("script-"+strconv.Itoa(i), "", script.Notification{})
	}
	notices.post("overflow", "", script.Notification{})
	if sent, dropped := notices.counts(); sent != scriptNoticeGlobal || dropped != 2 || received != scriptNoticeGlobal {
		t.Fatalf("global limit: %d sent, %d dropped, %d received", sent, dropped, received)
	}
	now = now.Add(time.Minute)
	notices.post("overflow", "", script.Notification{})
	if sent, dropped := notices.counts(); sent != scriptNoticeGlobal+1 || dropped != 2 {
		t.Fatalf("global limit did not refill: %d sent, %d dropped", sent, dropped)
	}
}

func TestScriptNotificationPayload(t *testing.T) {
	notices := newScriptNotifications()
	now := time.Unix(2, 0)
	notices.now = func() time.Time { return now }
	var got api.ScriptNotification
	notices.sink = func(notification api.ScriptNotification) { got = notification }
	notices.post("script", "module", script.Notification{
		Title: strings.Repeat("界", scriptNoticeTitleMax), Subtitle: "subtitle",
		Body:    strings.Repeat("a", scriptNoticeBodyMax+1),
		Options: map[string]any{"open-url": "https://example.test/page"},
	})
	if got.ScriptID != "script" || got.Module != "module" || got.Subtitle != "subtitle" || !got.Time.Equal(now) {
		t.Fatalf("notification metadata = %+v", got)
	}
	if len(got.Title) > scriptNoticeTitleMax || !utf8.ValidString(got.Title) || len(got.Body) != scriptNoticeBodyMax {
		t.Fatalf("notification field sizes = %d, %d", len(got.Title), len(got.Body))
	}
	if string(got.Options) != `{"open-url":"https://example.test/page"}` {
		t.Fatalf("options = %s", got.Options)
	}
	notices.post("script", "", script.Notification{
		Options: map[string]any{"clipboard": strings.Repeat("a", script.NotificationOptionsMax)},
	})
	if len(got.Options) != 0 {
		t.Fatal("oversized options were delivered")
	}
}

func TestScriptHTTPRejectsKernelListener(t *testing.T) {
	e := NewEngine(EngineOptions{})
	t.Cleanup(e.Close)
	e.SetScriptClashAddress("127.0.0.1:12345")
	c := scriptHTTPClient{engine: e}
	g := &generation{eff: &compile.Effective{}}
	for _, address := range []string{"127.0.0.2:12345", "0.0.0.0:12345", "[::1%zone]:12345", "[::ffff:127.0.0.1]:12345", "[::]:12345", "LOCALHOST.:12345", "host.localhost:12345"} {
		if _, err := c.dial(context.Background(), g, "", "tcp", address); !errors.Is(err, errScriptLocalListener) {
			t.Fatalf("dial %s = %v", address, err)
		}
	}
}

func TestScriptHTTPExplicitPolicy(t *testing.T) {
	group := router.Group{ID: "selection", Members: []string{"first", "second"}}
	r, err := router.New(nil, router.Options{
		Outbounds: []string{"direct", "reject", "first", "second"},
		Groups:    []router.Group{group},
	})
	if err != nil {
		t.Fatal(err)
	}
	g := &generation{router: r, eff: &compile.Effective{
		Outbounds: []compile.Outbound{{ID: "first", Name: "Duplicate"}, {ID: "second", Name: "Duplicate"}},
		Groups:    []router.Group{group},
		GroupMetadata: map[string]compile.GroupMetadata{
			"selection": {Name: "Selection"},
		},
	}}
	for name, want := range map[string]string{"DIRECT": "direct", "REJECT": "reject", "first": "first", "Selection": "selection", "selection": "selection"} {
		if got, err := scriptHTTPPolicy(g, name); err != nil || got != want {
			t.Fatalf("policy %s = %s, %v", name, got, err)
		}
	}
	for _, name := range []string{"Duplicate", "unknown"} {
		if got, err := scriptHTTPPolicy(g, name); err == nil || got != "" {
			t.Fatalf("policy %s = %s, %v", name, got, err)
		}
	}
}
