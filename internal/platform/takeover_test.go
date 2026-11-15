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
	k, err := NewTakeover(filepath.Join(t.TempDir(), "state"), h)
	if err != nil {
		t.Fatal(err)
	}
	c := Network{Mode: "tun"}
	if err = k.Apply(c, ""); err != nil {
		t.Fatal(err)
	}
	if err = k.Apply(c, ""); err != nil {
		t.Fatal(err)
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
	if err = k.Apply(Network{Mode: "off"}, ""); err != nil {
		t.Fatal(err)
	}
	if err = k.Apply(c, ""); err != nil {
		t.Fatal(err)
	}
	os.m["dns"] = "external"
	if k.Check() == nil {
		t.Fatal("missing conflict")
	}
	if err = k.Close(); err != nil {
		t.Fatal(err)
	}
	if os.m["dns"] != "external" {
		t.Fatal(os.m)
	}
}

func TestDegradedRecoveryCanExplicitlyStop(t *testing.T) {
	root := t.TempDir()
	f := &fakeSettings{m: map[string]string{"dns": "before"}}
	j := &Journal{Path: filepath.Join(root, "network", "ownership.json"), OS: f}
	if err := j.Apply("dns", "ours"); err != nil {
		t.Fatal(err)
	}
	f.fail = true
	k, err := NewTakeover(root, NetworkHooks{Settings: f})
	if err == nil || k.Status().State != "Degraded" {
		t.Fatal(err, k.Status())
	}
	f.fail = false
	if err = k.Apply(Network{Mode: "off"}, ""); err != nil {
		t.Fatal(err)
	}
	if k.Status().State != "Stopped" || f.m["dns"] != "before" {
		t.Fatal(k.Status(), f.m)
	}
}
