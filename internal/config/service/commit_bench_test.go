package service

import (
	"context"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

// BenchmarkCommitSelection measures one durable commit of a selection
// change: compile, prepare, persistence and activation.
func BenchmarkCommitSelection(b *testing.B) {
	e := newEnv(b)
	s := e.open(profileWith("direct"), localWith(freePort(b)))
	defer s.Close()
	sel := []string{`"alt"`, `"direct"`}
	ctx := context.Background()
	for i := 0; b.Loop(); i++ {
		res, err := s.Commit(ctx, CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: s.ActiveRevision(),
			Patch: []model.Op{{Op: "set", Path: "/groups/proxy/selected", Value: []byte(sel[i%2])}}}})
		if err != nil || res.State != "committed" {
			b.Fatalf("%+v %v", res, err)
		}
	}
}
