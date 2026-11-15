// Command dashboard serves a small local web page for watching and
// steering a running kernel: status, groups, live connections, route
// explanations, history and events.
//
// Browsers cannot reach the control socket, so this program bridges it to
// HTTP on a loopback address. Every start generates a random token that
// the page sends with each request; requests must also name a loopback
// Host, so other web pages cannot drive the kernel through the browser.
// Secrets are never read or written through the dashboard.
//
//	go run ./tools/dashboard                       # default kernel address
//	go run ./tools/dashboard -c unix:///path/control.sock -listen 127.0.0.1:9091
package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/platform"
)

//go:embed index.html
var page []byte

type bridge struct {
	addr  string
	token string
	mu    sync.Mutex
	c     *api.Client
}

func (b *bridge) client() (*api.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.c != nil {
		return b.c, nil
	}
	c, err := api.Connect(b.addr, "dashboard")
	if err != nil {
		return nil, fmt.Errorf("cannot reach the kernel at %s: %w", b.addr, err)
	}
	b.c = c
	return c, nil
}

// call makes one API call, reconnecting once if the kernel restarted.
func (b *bridge) call(method string, params, out any) error {
	for attempt := 0; ; attempt++ {
		c, err := b.client()
		if err != nil {
			return err
		}
		err = c.Call(method, params, out)
		if errors.Is(err, api.ErrClosed) && attempt == 0 {
			b.mu.Lock()
			if b.c == c {
				b.c = nil
			}
			b.mu.Unlock()
			continue
		}
		return err
	}
}

func loopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

// guard rejects requests that do not come from this dashboard's page.
func (b *bridge) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		got := r.Header.Get("X-Reka-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(b.token)) != 1 {
			http.Error(w, "missing or wrong token; open the URL the dashboard printed", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		msg := err.Error()
		var se *api.Error
		if errors.As(err, &se) {
			msg = se.Message
		}
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
		return
	}
	json.NewEncoder(w).Encode(v)
}

func readBody(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	return json.NewDecoder(r.Body).Decode(v)
}

// groupView is one group as the page shows it.
type groupView struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Members  []string `json:"members"`
	Selected string   `json:"selected"`
	// Observed is the automatic group's current choice and its probes.
	Observed json.RawMessage `json:"observed,omitempty"`
	Settable bool            `json:"settable"`
}

func (b *bridge) state(w http.ResponseWriter, r *http.Request) {
	var st api.Status
	if err := b.call("GetStatus", nil, &st); err != nil {
		writeJSON(w, nil, err)
		return
	}
	var cfg struct {
		Revision  uint64 `json:"revision"`
		Effective *struct {
			Groups []struct {
				ID       string
				Members  []string
				Selected string
			} `json:"groups"`
			Outbounds []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"outbounds"`
			GroupMetadata map[string]struct {
				Name string `json:"name"`
			} `json:"group_metadata"`
		} `json:"effective"`
	}
	if err := b.call("GetConfiguration", map[string]bool{"reveal": false}, &cfg); err != nil {
		writeJSON(w, nil, err)
		return
	}
	var auto []json.RawMessage
	_ = b.call("GetGroupStatus", nil, &auto)
	observed := map[string]json.RawMessage{}
	autoType := map[string]string{}
	for _, a := range auto {
		var head struct{ ID, Type string }
		if json.Unmarshal(a, &head) == nil {
			observed[head.ID] = a
			autoType[head.ID] = head.Type
		}
	}
	var groups []groupView
	var outbounds any
	// Imported nodes and groups have hashed IDs; the page shows their
	// original names.
	names := map[string]string{}
	if cfg.Effective != nil {
		outbounds = cfg.Effective.Outbounds
		for _, o := range cfg.Effective.Outbounds {
			if o.Name != "" {
				names[o.ID] = o.Name
			}
		}
		for id, m := range cfg.Effective.GroupMetadata {
			if m.Name != "" {
				names[id] = m.Name
			}
		}
		for _, g := range cfg.Effective.Groups {
			v := groupView{ID: g.ID, Type: "select", Members: g.Members, Selected: g.Selected, Settable: true}
			if t, ok := autoType[g.ID]; ok {
				v.Type, v.Observed, v.Settable = t, observed[g.ID], false
			}
			if v.Selected == "" && len(v.Members) > 0 && v.Settable {
				v.Selected = v.Members[0]
			}
			groups = append(groups, v)
		}
	}
	writeJSON(w, map[string]any{"status": st, "groups": groups, "outbounds": outbounds, "names": names, "revision": cfg.Revision}, nil)
}

func (b *bridge) connections(w http.ResponseWriter, r *http.Request) {
	var out struct {
		Total       int              `json:"total"`
		Connections []api.Connection `json:"connections"`
	}
	err := b.call("ListConnections", map[string]int{"limit": 1000}, &out)
	writeJSON(w, out, err)
}

// commit plans a change and commits exactly the planned candidate.
func (b *bridge) commit(req api.ChangeRequest, message string) (api.Result, error) {
	var plan api.PlanResult
	if err := b.call("PlanConfiguration", req, &plan); err != nil {
		return api.Result{}, err
	}
	if plan.Conflict != nil {
		return api.Result{}, fmt.Errorf("the configuration changed meanwhile (now revision %d); try again", plan.Conflict.Active)
	}
	if !plan.Valid {
		return api.Result{}, fmt.Errorf("invalid change: %s", plan.Diagnostics.Errors().Error())
	}
	var res api.Result
	err := b.call("CommitConfiguration", api.CommitRequest{ChangeRequest: req, PlanHash: plan.PlanHash, Source: "dashboard", Message: message}, &res)
	if err == nil && res.State != "committed" && res.Error != nil {
		err = errors.New(res.Error.Message)
	}
	return res, err
}

func (b *bridge) selectMember(w http.ResponseWriter, r *http.Request) {
	var p struct{ Group, Member string }
	if err := readBody(r, &p); err != nil || p.Group == "" || p.Member == "" {
		http.Error(w, "need group and member", http.StatusBadRequest)
		return
	}
	var cfg api.Configuration
	if err := b.call("GetConfiguration", nil, &cfg); err != nil {
		writeJSON(w, nil, err)
		return
	}
	value, _ := json.Marshal(p.Member)
	path := model.JoinPath("/groups", p.Group, "selected")
	req := api.ChangeRequest{BaseRevision: cfg.Revision}
	if !strings.Contains(p.Group, "/") {
		req.Patch = []model.Op{{Op: "set", Path: path, Value: value}}
	} else {
		// A group from a subscription is changed through the overlay, so a
		// refresh keeps the choice.
		overlay, _, diags := model.ParseOverlay([]byte(cfg.Overlay))
		if diags.HasErrors() {
			writeJSON(w, nil, diags.Errors())
			return
		}
		encoded, _ := json.Marshal(model.Op{Op: "set", Path: path, Value: value})
		edit := model.Op{Op: "insert", Path: "/patches", Value: encoded}
		for i, op := range overlay.Patches {
			if op.Op == "set" && op.Path == path {
				edit = model.Op{Op: "set", Path: fmt.Sprintf("/patches/#%d/value", i), Value: value}
			}
		}
		req.OverlayPatch = []model.Op{edit}
	}
	res, err := b.commit(req, "select "+p.Member+" in "+p.Group)
	writeJSON(w, res, err)
}

func (b *bridge) closeConns(w http.ResponseWriter, r *http.Request) {
	var p struct {
		IDs []uint64 `json:"ids"`
		All bool     `json:"all"`
	}
	if err := readBody(r, &p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var out any
	err := b.call("CloseConnections", p, &out)
	writeJSON(w, out, err)
}

func (b *bridge) explain(w http.ResponseWriter, r *http.Request) {
	var p api.ExplainRequest
	if err := readBody(r, &p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var out any
	err := b.call("ExplainRoute", p, &out)
	writeJSON(w, out, err)
}

func (b *bridge) revisions(w http.ResponseWriter, r *http.Request) {
	var out any
	err := b.call("ListRevisions", nil, &out)
	writeJSON(w, out, err)
}

func (b *bridge) restore(w http.ResponseWriter, r *http.Request) {
	var p struct{ Revision uint64 }
	if err := readBody(r, &p); err != nil || p.Revision == 0 {
		http.Error(w, "need revision", http.StatusBadRequest)
		return
	}
	var cfg api.Configuration
	if err := b.call("GetConfiguration", nil, &cfg); err != nil {
		writeJSON(w, nil, err)
		return
	}
	var res api.Result
	err := b.call("RestoreRevision", api.RestoreRequest{Revision: p.Revision, BaseRevision: cfg.Revision}, &res)
	if err == nil && res.State != "committed" && res.Error != nil {
		err = errors.New(res.Error.Message)
	}
	writeJSON(w, res, err)
}

// events streams kernel events as newline-delimited JSON over its own
// control connection.
func (b *bridge) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	c, err := api.Connect(b.addr, "dashboard-events")
	if err != nil {
		writeJSON(w, nil, err)
		return
	}
	defer c.Close()
	if err := c.Call("Subscribe", map[string]any{}, nil); err != nil {
		writeJSON(w, nil, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-c.Events:
			if !ok {
				return
			}
			if enc.Encode(ev) != nil {
				return
			}
			flusher.Flush()
		case <-ping.C:
			if _, err := w.Write([]byte("{}\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func main() {
	root, _ := platform.DefaultStateRoot()
	addr := flag.String("c", "", "kernel control address (default: REKA_CONTROL, else the default state root's socket)")
	stateRoot := flag.String("state-root", root, "kernel state root, used to find its default control address")
	listen := flag.String("listen", "127.0.0.1:9091", "loopback address to serve the dashboard on")
	flag.Parse()
	if *addr == "" {
		*addr = os.Getenv("REKA_CONTROL")
	}
	if *addr == "" {
		*addr = api.DefaultAddress(*stateRoot)
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !loopbackHost(host) {
		log.Fatalf("-listen must be a loopback address such as 127.0.0.1:9091")
	}
	tok := make([]byte, 16)
	rand.Read(tok)
	b := &bridge{addr: *addr, token: hex.EncodeToString(tok)}
	if _, err := b.client(); err != nil {
		log.Printf("warning: %v (the page will keep retrying)", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		w.Write(page)
	})
	mux.HandleFunc("GET /api/state", b.guard(b.state))
	mux.HandleFunc("GET /api/connections", b.guard(b.connections))
	mux.HandleFunc("GET /api/revisions", b.guard(b.revisions))
	mux.HandleFunc("GET /api/events", b.guard(b.events))
	mux.HandleFunc("POST /api/select", b.guard(b.selectMember))
	mux.HandleFunc("POST /api/close", b.guard(b.closeConns))
	mux.HandleFunc("POST /api/explain", b.guard(b.explain))
	mux.HandleFunc("POST /api/restore", b.guard(b.restore))

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Reka dashboard for %s\nOpen: http://%s/#token=%s\n", *addr, ln.Addr(), b.token)
	log.Fatal(srv.Serve(ln))
}
