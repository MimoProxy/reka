package platform

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeSettings struct {
	m    map[string]string
	fail bool
}

func (f *fakeSettings) Read(k string) (string, error) { return f.m[k], nil }
func (f *fakeSettings) Write(k, v string) error {
	if f.fail {
		return errors.New("injected")
	}
	f.m[k] = v
	return nil
}
func TestOwnershipRecovery(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "crash", true: "external"}[external], func(t *testing.T) {
			f := &fakeSettings{m: map[string]string{"dns": "before"}}
			p := filepath.Join(t.TempDir(), "network.json")
			j := &Journal{Path: p, OS: f}
			if e := j.Apply("dns", "ours"); e != nil {
				t.Fatal(e)
			}
			if external {
				f.m["dns"] = "other"
				if j.Check() == nil {
					t.Fatal("conflict missed")
				}
			}
			recovered := &Journal{Path: p, OS: f}
			if e := recovered.Recover(); e != nil {
				t.Fatal(e)
			}
			want := "before"
			if external {
				want = "other"
			}
			if f.m["dns"] != want {
				t.Fatal(f.m)
			}
			if e := recovered.Recover(); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestJournalBeforeMutationAndFailedRestore(t *testing.T) {
	f := &fakeSettings{m: map[string]string{"dns": "old"}, fail: true}
	p := filepath.Join(t.TempDir(), "network.json")
	j := &Journal{Path: p, OS: f}
	if j.Apply("dns", "new") == nil {
		t.Fatal("expected failure")
	}
	if _, e := os.Stat(p); e != nil {
		t.Fatal(e)
	}
	f.m["dns"] = "new" // OS mutation happened, response lost
	if (&Journal{Path: p, OS: f}).Recover() == nil {
		t.Fatal("restore must fail")
	}
	f.fail = false
	if e := (&Journal{Path: p, OS: f}).Recover(); e != nil {
		t.Fatal(e)
	}
	if f.m["dns"] != "old" {
		t.Fatal(f.m)
	}
}
func TestPreexistingSettingNotOwned(t *testing.T) {
	f := &fakeSettings{m: map[string]string{"dns": "same"}}
	j := &Journal{Path: filepath.Join(t.TempDir(), "j"), OS: f}
	if e := j.Apply("dns", "same"); e != nil {
		t.Fatal(e)
	}
	if len(j.entries) != 0 {
		t.Fatal("claimed external setting")
	}
}
