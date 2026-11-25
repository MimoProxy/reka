package scriptbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/MimoProxy/reka/internal/script"
)

type testStore struct {
	values map[string]string
	writes int
}

func (s *testStore) Read(key string) (string, bool, error) {
	value, ok := s.values[key]
	return value, ok, nil
}

func (s *testStore) Write(key, value string) error {
	s.writes++
	if key == "read-only" {
		return errors.New("read-only key")
	}
	s.values[key] = value
	return nil
}

func (s *testStore) Delete(key string) error {
	delete(s.values, key)
	return nil
}

type notifierFunc func(script.Notification)

func (f notifierFunc) Post(n script.Notification) { f(n) }

func TestCallServices(t *testing.T) {
	host := &fakeHost{}
	b := New(host, Options{})
	job := newJob()
	store := &testStore{values: make(map[string]string)}
	job.Limits = script.Limits{StoreValueMax: 4, LogLineMax: 4}
	var notifications []script.Notification
	var logCalls int
	job.Services = script.Services{
		Store:  store,
		Notify: notifierFunc(func(n script.Notification) { notifications = append(notifications, n) }),
		Log: func(level, message string) {
			logCalls++
			if level != "warn" || message != "OK" {
				t.Errorf("Log(%q, %q)", level, message)
			}
		},
	}
	host.start = func(run uint64, _, _, _ []byte) {
		assertCall := func(input, want string) {
			t.Helper()
			got, err := b.Call(run, []byte(input))
			if err != nil {
				t.Fatalf("Call(%s) = %v", input, err)
			}
			assertJSON(t, got, want)
		}
		assertCall(`{"op":"storeRead","key":"key"}`, `{"value":null}`)
		assertCall(`{"op":"storeWrite","key":"key","value":"yes"}`, `{"ok":true}`)
		assertCall(`{"op":"storeRead","key":"key"}`, `{"value":"yes"}`)
		assertCall(`{"op":"storeWrite","key":"key","value":"yesé"}`, `{"ok":false,"error":"persistent store value exceeds size limit"}`)
		assertCall(`{"op":"storeWrite","key":"read-only","value":""}`, `{"ok":false,"error":"read-only key"}`)
		assertCall(`{"op":"storeDelete","key":"key"}`, `{"ok":true}`)
		assertCall(`{"op":"storeRead","key":"key"}`, `{"value":null}`)
		assertCall(`{"op":"notify","title":"title","subtitle":"subtitle","body":"body","options":{"value":42}}`, `{"ok":true}`)
		oversized := strings.Repeat("a", script.NotificationOptionsMax)
		assertCall(`{"op":"notify","title":"title","subtitle":"subtitle","body":"body","options":{"value":"`+oversized+`"}}`, `{"ok":true}`)
		assertCall(`{"op":"log","level":"warn","message":"OK🙂"}`, `{"ok":true}`)
		for _, invalid := range []string{`{`, `{"op":"unknown"}`} {
			if _, err := b.Call(run, []byte(invalid)); err == nil {
				t.Errorf("Call(%q) succeeded", invalid)
			}
		}
		b.Done(run, []byte(`{"called":true}`), nil, nil)
		if _, err := b.Call(run, []byte(`{"op":"storeRead","key":"key"}`)); err == nil {
			t.Error("Call succeeded after Done")
		}
	}
	if _, err := b.Run(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if store.writes != 2 {
		t.Errorf("store writes = %d, want 2", store.writes)
	}
	if len(notifications) != 2 || notifications[0].Title != "title" || notifications[0].Subtitle != "subtitle" ||
		notifications[0].Body != "body" || notifications[0].Options["value"] != json.Number("42") ||
		notifications[1].Options != nil {
		t.Errorf("notifications = %+v", notifications)
	}
	if logCalls != 1 {
		t.Errorf("log calls = %d, want 1", logCalls)
	}
}

func TestCallWithoutServices(t *testing.T) {
	host := &fakeHost{}
	b := New(host, Options{})
	host.start = func(run uint64, _, _, _ []byte) {
		for _, tc := range []struct{ request, want string }{
			{`{"op":"storeRead","key":"key"}`, `{"value":null}`},
			{`{"op":"storeWrite","key":"key","value":"yes"}`, `{"ok":false,"error":"persistent store is unavailable"}`},
			{`{"op":"storeDelete","key":"key"}`, `{"ok":false,"error":"persistent store is unavailable"}`},
			{`{"op":"log","level":"log","message":"test"}`, `{"ok":true}`},
			{`{"op":"notify","title":"test"}`, `{"ok":true}`},
		} {
			got, err := b.Call(run, []byte(tc.request))
			if err != nil {
				t.Fatalf("Call(%s) = %v", tc.request, err)
			}
			assertJSON(t, got, tc.want)
		}
		b.Done(run, []byte(`{"called":true}`), nil, nil)
	}
	if _, err := b.Run(context.Background(), newJob()); err != nil {
		t.Fatal(err)
	}
}

func TestWriteCallResponseRetriesStoreWrite(t *testing.T) {
	host := &fakeHost{}
	b := New(host, Options{})
	job := newJob()
	store := &testStore{values: make(map[string]string)}
	job.Services.Store = store
	host.start = func(run uint64, _, _, _ []byte) {
		input := []byte(`{"op":"storeWrite","key":"key","value":"yes"}`)
		for _, output := range [][]byte{nil, make([]byte, 1)} {
			if n := b.WriteCallResponse(run, input, output); n != -int32(len(`{"ok":true}`)) || store.writes != 1 {
				t.Fatalf("WriteCallResponse = %d, writes = %d", n, store.writes)
			}
		}
		output := make([]byte, len(`{"ok":true}`))
		if n := b.WriteCallResponse(run, input, output); int(n) != len(output) || store.writes != 1 {
			t.Fatalf("WriteCallResponse = %d, writes = %d", n, store.writes)
		}
		assertJSON(t, output, `{"ok":true}`)
		if n := b.WriteCallResponse(run, input, output); int(n) != len(output) || store.writes != 2 {
			t.Fatalf("new operation returned %d, writes = %d", n, store.writes)
		}
		b.Done(run, []byte(`{"called":true}`), nil, nil)
		if n := b.WriteCallResponse(run, input, output); n != 0 || store.writes != 2 {
			t.Fatalf("late operation returned %d, writes = %d", n, store.writes)
		}
	}
	if _, err := b.Run(context.Background(), job); err != nil {
		t.Fatal(err)
	}
}

type httpClientFunc func(context.Context, *script.HTTPRequest) (*script.HTTPResponse, error)

func (f httpClientFunc) Do(ctx context.Context, request *script.HTTPRequest) (*script.HTTPResponse, error) {
	return f(ctx, request)
}

func TestHTTPCallbacksAndInFlightLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		host := &fakeHost{}
		b := New(host, Options{})
		job := newJob()
		job.Limits.MaxHTTPInFlight = 1
		requests := make(chan *script.HTTPRequest)
		release := make(chan struct{})
		httpCanceled := make(chan struct{})
		job.Services.HTTP = httpClientFunc(func(ctx context.Context, req *script.HTTPRequest) (*script.HTTPResponse, error) {
			requests <- req
			if strings.HasSuffix(req.URL, "/late") {
				<-ctx.Done()
				close(httpCanceled)
			} else {
				<-release
			}
			return &script.HTTPResponse{
				Status:  201,
				Headers: []script.HeaderField{{Name: "x", Value: "a"}, {Name: "x", Value: "b"}},
				Body:    []byte{0, 255},
			}, nil
		})
		starts := make(chan uint64)
		host.start = func(run uint64, _, _, _ []byte) { starts <- run }
		type reply struct {
			run, call  uint64
			data, body []byte
		}
		replies := make(chan reply, 1)
		host.reply = func(run, call uint64, data, body []byte) { replies <- reply{run, call, data, body} }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		finished := make(chan error, 1)
		go func() {
			_, err := b.Run(ctx, job)
			finished <- err
		}()

		run := <-starts
		input := []byte(`{"method":"POST","url":"https://example.org/","headers":[["x","a"],["x","b"]],"timeoutMs":1500,
		"policy":"DIRECT","policyDescriptor":"descriptor","insecure":true,"autoRedirect":false,"autoCookie":false,"binary":true}`)
		body := []byte{1, 0, 255}
		if b.HTTP(run, 0, []byte(`{`), nil) || !b.HTTP(run, 1, input, body) {
			t.Fatal("malformed request accepted or valid request rejected")
		}
		clear(input)
		clear(body)
		r := <-requests
		if r.Method != "POST" || r.URL != "https://example.org/" || !bytes.Equal(r.Body, []byte{1, 0, 255}) ||
			r.Timeout != 1500*time.Millisecond || r.Policy != "DIRECT" || r.PolicyDescriptor != "descriptor" ||
			!r.Insecure || r.AutoRedirect || r.AutoCookie || !r.Binary || len(r.Headers) != 2 ||
			r.Headers[0] != (script.HeaderField{Name: "x", Value: "a"}) || r.Headers[1] != (script.HeaderField{Name: "x", Value: "b"}) {
			t.Errorf("HTTP request = %+v", r)
		}
		late := []byte(`{"method":"GET","url":"https://example.org/late"}`)
		if b.HTTP(run, 2, late, nil) {
			t.Fatal("request above the in-flight limit was accepted")
		}
		close(release)
		got := <-replies
		if got.run != run || got.call != 1 || !bytes.Equal(got.body, []byte{0, 255}) {
			t.Errorf("HTTP reply = %+v", got)
		}
		assertJSON(t, got.data, `{"status":201,"headers":[["x","a"],["x","b"]]}`)
		if !b.HTTP(run, 3, late, []byte{}) {
			t.Fatal("the completed call did not free its in-flight slot")
		}
		r = <-requests
		if r.Timeout != script.DefaultHTTPRequestTimeout || !r.AutoRedirect || !r.AutoCookie || r.Body == nil || len(r.Body) != 0 {
			t.Errorf("HTTP defaults and empty body = %+v", r)
		}
		if !b.Done(run, []byte(`{"called":true}`), nil, nil) || b.HTTP(run, 4, late, nil) {
			t.Fatal("completion rejected or HTTP accepted after completion")
		}
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
		<-httpCanceled
		synctest.Wait()
		select {
		case reply := <-replies:
			t.Fatalf("late reply = %+v", reply)
		default:
		}
	})
}

func TestHTTPUnavailable(t *testing.T) {
	host := &fakeHost{}
	b := New(host, Options{})
	host.start = func(run uint64, _, _, _ []byte) {
		if !b.HTTP(run, 1, []byte(`{"method":"GET","url":"https://example.org/"}`), nil) {
			t.Error("HTTP request was rejected")
			b.Done(run, []byte(`{"called":true}`), nil, nil)
		}
	}
	host.reply = func(run, _ uint64, data, body []byte) {
		assertJSON(t, data, `{"error":"unavailable"}`)
		if body != nil {
			t.Errorf("HTTP error body = %#v, want nil", body)
		}
		if !b.Done(run, []byte(`{"called":true}`), nil, nil) {
			t.Error("Done from HTTP reply was rejected")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := b.Run(ctx, newJob()); err != nil {
		t.Fatal(err)
	}
}
