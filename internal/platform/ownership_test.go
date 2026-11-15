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
			if err := j.Apply("dns", "ours"); err != nil {
				t.Fatal(err)
			}
			if external {
				f.m["dns"] = "other"
				if j.Check() == nil {
					t.Fatal("conflict missed")
				}
			}
			recovered := &Journal{Path: p, OS: f}
			if err := recovered.Recover(); err != nil {
				t.Fatal(err)
			}
			want := "before"
			if external {
				want = "other"
			}
			if f.m["dns"] != want {
				t.Fatal(f.m)
			}
			if err := recovered.Recover(); err != nil {
				t.Fatal(err)
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
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	f.m["dns"] = "new" // OS mutation happened, response lost
	if (&Journal{Path: p, OS: f}).Recover() == nil {
		t.Fatal("restore must fail")
	}
	f.fail = false
	if err := (&Journal{Path: p, OS: f}).Recover(); err != nil {
		t.Fatal(err)
	}
	if f.m["dns"] != "old" {
		t.Fatal(f.m)
	}
}
func TestPreexistingSettingNotOwned(t *testing.T) {
	f := &fakeSettings{m: map[string]string{"dns": "same"}}
	j := &Journal{Path: filepath.Join(t.TempDir(), "j"), OS: f}
	if err := j.Apply("dns", "same"); err != nil {
		t.Fatal(err)
	}
	if len(j.entries) != 0 {
		t.Fatal("claimed external setting")
	}
}
