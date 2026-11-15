package core

import (
	"encoding/json"
	"testing"
	"time"
)

type blockingHost struct {
	fakeHost
	entered chan struct{}
	release chan struct{}
}

func (h *blockingHost) Seal(p []byte) ([]byte, error) {
	close(h.entered)
	<-h.release
	return h.fakeHost.Seal(p)
}
func TestStopWaitsForHostCallAndHoldsStateLock(t *testing.T) {
	root := t.TempDir()
	h := &blockingHost{entered: make(chan struct{}), release: make(chan struct{})}
	in, e := Start(Options{StateRoot: root}, h)
	if e != nil {
		t.Fatal(e)
	}
	in.Call([]byte(`{"id":1,"method":"Hello","params":{"versions":[1]}}`))
	called := make(chan struct{})
	go func() {
		defer close(called)
		in.Call([]byte(`{"id":2,"method":"SetSecret","params":{"name":"test/value","value":"fixture","apply":false}}`))
	}()
	select {
	case <-h.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("host callback not entered")
	}
	stopped := make(chan struct{})
	started := make(chan struct{})
	go func() { close(started); in.Stop(); close(stopped) }()
	<-started
	select {
	case <-stopped:
		t.Fatal("stopped before host callback completed")
	case <-time.After(30 * time.Millisecond):
	}
	if second, e := Start(Options{StateRoot: root}, &fakeHost{}); e == nil {
		second.Stop()
		t.Fatal("second instance acquired root during stop")
	}
	close(h.release)
	select {
	case <-called:
	case <-time.After(3 * time.Second):
		t.Fatal("call did not finish")
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("stop did not finish")
	}
	var response struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal(in.Call([]byte(`{"id":3,"method":"GetStatus"}`)), &response)
	if response.Error.Code != "blocked" {
		t.Fatal(response)
	}
	next, e := Start(Options{StateRoot: root}, &fakeHost{})
	if e != nil {
		t.Fatal(e)
	}
	next.Stop()
}
