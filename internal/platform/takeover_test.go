package platform

import (
	"errors"
	"io"
	"path/filepath"
	"testing"
)

type fakeTun struct{ closed *int }

func (f fakeTun) Close() error { *f.closed++; return nil }
func TestTakeoverReuseRollbackOwnership(t *testing.T) {
	starts, closes := 0, 0
	bad := false
	os := &fakeSettings{m: map[string]string{"dns": "before"}}
	h := NetworkHooks{Settings: os, SettingsFor: func(c Network, _ string) (map[string]string, error) {
		if c.Mode == "off" {
			return nil, nil
		}
		return map[string]string{"dns": "ours"}, nil
	}, StartTUN: func(TUNConfig) (io.Closer, string, error) {
		if bad {
			return nil, "", errors.New("injected start failure")
		}
		starts++
		return fakeTun{&closes}, "test", nil
	}}
	k, e := NewTakeover(filepath.Join(t.TempDir(), "state"), h)
	if e != nil {
		t.Fatal(e)
	}
	c := Network{Mode: "tun"}
	if e = k.Apply(c, ""); e != nil {
		t.Fatal(e)
	}
	if e = k.Apply(c, ""); e != nil {
		t.Fatal(e)
	}
	if starts != 1 || closes != 0 {
		t.Fatal(starts, closes)
	}
	bad = true
	next := c
	next.TUN.MTU = 1400
	if k.Apply(next, "") == nil {
		t.Fatal("start succeeded")
	}
	if k.Status().State != "Degraded" {
		t.Fatal(k.Status())
	}
	bad = false
	if e = k.Apply(Network{Mode: "off"}, ""); e != nil {
		t.Fatal(e)
	}
	if e = k.Apply(c, ""); e != nil {
		t.Fatal(e)
	}
	os.m["dns"] = "external"
	if k.Check() == nil {
		t.Fatal("missing conflict")
	}
	if e = k.Close(); e != nil {
		t.Fatal(e)
	}
	if os.m["dns"] != "external" {
		t.Fatal(os.m)
	}
}

func TestDegradedRecoveryCanExplicitlyStop(t *testing.T) {
	root := t.TempDir()
	f := &fakeSettings{m: map[string]string{"dns": "before"}}
	j := &Journal{Path: filepath.Join(root, "network", "ownership.json"), OS: f}
	if e := j.Apply("dns", "ours"); e != nil {
		t.Fatal(e)
	}
	f.fail = true
	k, e := NewTakeover(root, NetworkHooks{Settings: f})
	if e == nil || k.Status().State != "Degraded" {
		t.Fatal(e, k.Status())
	}
	f.fail = false
	if e = k.Apply(Network{Mode: "off"}, ""); e != nil {
		t.Fatal(e)
	}
	if k.Status().State != "Stopped" || f.m["dns"] != "before" {
		t.Fatal(k.Status(), f.m)
	}
}
