package service

import (
	"errors"
	"os"
	"testing"

	"github.com/MimoProxy/reka/internal/config/store"
)

func TestCommitRestoresActiveRecordAfterWriteError(t *testing.T) {
	for _, tc := range []struct {
		name         string
		restoreFails bool
	}{
		{name: "restore succeeds"},
		{name: "restore fails", restoreFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv(t)
			s := env.open(profileWith("direct"), "")
			defer s.Close()
			before, err := s.store.ReadActive()
			if err != nil || before == nil {
				t.Fatalf("read original active record: %+v, %v", before, err)
			}
			var written uint64
			s.writeActive = func(st *store.Store, active store.Active) error {
				if active.Revision == before.Revision {
					if tc.restoreFails {
						return errors.New("could not restore active record")
					}
					return st.WriteActive(active)
				}
				if err := st.WriteActive(active); err != nil {
					return err
				}
				written = active.Revision
				return errors.New("could not sync active record after rename")
			}

			res := commitProfile(t, s, before.Revision, profileWith("alt"), "write-failure")
			if written == 0 || res.State != store.OpFailed || res.Degraded != tc.restoreFails {
				t.Fatalf("commit after active write error: %+v (written revision %d)", res, written)
			}
			if s.ActiveRevision() != before.Revision || selected(t, s) != "direct" {
				t.Fatal("runtime did not return to the original revision")
			}
			active, err := s.store.ReadActive()
			if err != nil || active == nil {
				t.Fatalf("read active record after rollback: %+v, %v", active, err)
			}
			if tc.restoreFails {
				if active.Revision != written {
					t.Fatalf("active record no longer points to the written revision: %+v", active)
				}
				if _, _, _, err := s.store.ReadRevision(active.Revision); err != nil {
					t.Fatalf("active record points to an unavailable revision: %v", err)
				}
				return
			}
			if *active != *before {
				t.Fatalf("original active record was not restored: got %+v, want %+v", active, before)
			}
			if _, _, _, err := s.store.ReadRevision(written); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed revision %d still present: %v", written, err)
			}
			s.Close()
			reopened := env.open("", "")
			defer reopened.Close()
			if reopened.ActiveRevision() != before.Revision || selected(t, reopened) != "direct" {
				t.Fatal("reopening did not start the restored revision")
			}
		})
	}
}
