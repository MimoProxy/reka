package control

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/service"
	rt "github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/secret"
)

func testSession(t *testing.T, secrets secret.Store) func(*testing.T, Request) Message {
	t.Helper()
	_, call := testSessionWithObserver(t, secrets, nil)
	return call
}

func testSessionWithObserver(t *testing.T, secrets secret.Store, observe func([]byte)) (*service.Service, func(*testing.T, Request) Message) {
	t.Helper()
	engine := rt.NewEngine(rt.EngineOptions{Backend: sagernet.Options{Logger: quiet()}})
	svc, err := service.Open(service.Options{StateRoot: t.TempDir(), Secrets: secrets, Engine: engine, Logger: quiet(), InitialProfile: []byte(testProfile)})
	if err != nil {
		engine.Close()
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	var response []byte
	session := NewHandler(svc).NewSession(func(frame []byte) error {
		response = frame
		return nil
	})
	t.Cleanup(session.Close)
	call := func(t *testing.T, req Request) Message {
		t.Helper()
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("%s panicked", req.Method)
			}
		}()
		frame, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		response = nil
		session.Handle(frame)
		var msg Message
		if err := json.Unmarshal(response, &msg); err != nil || msg.ID != req.ID {
			t.Fatalf("invalid response to %s", req.Method)
		}
		if observe != nil {
			observe(response)
		}
		return msg
	}
	if hello := call(t, Request{ID: 1, Method: "Hello", Params: json.RawMessage(`{"versions":[1]}`)}); hello.Error != nil {
		t.Fatal(hello.Error)
	}
	return svc, call
}

func TestPagedRequestsAcceptNegativeBounds(t *testing.T) {
	call := testSession(t, nil)
	for _, method := range []string{"ListConnections", "GetProcessTraffic", "GetRules"} {
		t.Run(method, func(t *testing.T) {
			reply := call(t, Request{ID: 2, Method: method, Params: json.RawMessage(`{"offset":-1,"limit":-1}`)})
			if reply.Error != nil {
				t.Fatal(reply.Error)
			}
			switch method {
			case "ListConnections":
				var page struct {
					Connections []rt.Connection `json:"connections"`
					Offset      int             `json:"offset"`
				}
				if err := json.Unmarshal(reply.Result, &page); err != nil || page.Offset != 0 || page.Connections == nil {
					t.Fatalf("invalid connection page: %s (%v)", reply.Result, err)
				}
			case "GetProcessTraffic":
				var page api.ProcessTrafficPage
				if err := json.Unmarshal(reply.Result, &page); err != nil || page.Offset != 0 || page.Limit != 100 || page.Rows == nil {
					t.Fatalf("invalid process traffic page: %s (%v)", reply.Result, err)
				}
			case "GetRules":
				var page api.RulesPage
				if err := json.Unmarshal(reply.Result, &page); err != nil || len(page.Rules) != page.Total || len(page.Rules) == 0 || page.Rules[0].Index != 0 {
					t.Fatalf("invalid rules page: %s (%v)", reply.Result, err)
				}
			}
		})
	}
}

type panickingSecretStore struct{ secret.Store }

func (panickingSecretStore) List() ([]string, error) {
	panic("secret store panic")
}

func TestRequestPanicReturnsInternalError(t *testing.T) {
	call := testSession(t, panickingSecretStore{})
	var log bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	reply := call(t, Request{ID: 2, Method: "ListSecrets"})
	if reply.Error == nil || reply.Error.Code != CodeInternal || strings.Contains(reply.Error.Message, "secret store panic") {
		t.Fatalf("unexpected panic response: %+v", reply)
	}
	if !strings.Contains(log.String(), "ListSecrets") || !strings.Contains(log.String(), "secret store panic") {
		t.Fatalf("request panic was not logged: %s", &log)
	}
	if reply := call(t, Request{ID: 3, Method: "GetStatus"}); reply.Error != nil {
		t.Fatalf("session did not handle the next request: %+v", reply)
	}
}
