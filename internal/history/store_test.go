package history

import (
	"strings"
	"testing"
	"time"
)

func TestHistoryBoundedPagesAndProfileClear(t *testing.T) {
	store := New()
	now := time.Now()
	a, b := Scope{ProfileID: "a"}, Scope{ProfileID: "b"}
	store.Record(Connections, a, now, "first record", nil)
	store.Record(Connections, b, now, "other profile", nil)
	store.Record(Connections, a, now, "latest record", nil)
	page, err := store.List(Connections, "a", ListOptions{Query: "RECORD", Limit: 1})
	if err != nil || len(page.Rows) != 1 || string(page.Rows[0].Data) != `"latest record"` || page.Next == "" {
		t.Fatal(page, err)
	}
	older, err := store.List(Connections, "a", ListOptions{Before: page.Next})
	if err != nil || len(older.Rows) != 1 || string(older.Rows[0].Data) != `"first record"` {
		t.Fatal(older, err)
	}
	if n := store.Clear(Connections, "a"); n != 2 {
		t.Fatal(n)
	}
	store.Record(Connections, a, now, "in flight before clear", nil)
	empty, _ := store.List(Connections, "a", ListOptions{})
	other, _ := store.List(Connections, "b", ListOptions{})
	if len(empty.Rows) != 0 || len(other.Rows) != 1 {
		t.Fatal(empty, other)
	}
	payload := strings.Repeat("x", 2048)
	for range maxRows + 2 {
		store.Record(Connections, b, now, payload, nil)
	}
	budget := store.buckets[Connections]
	if budget.count >= maxRows || budget.bytes > totalBytes/3 {
		t.Fatalf("retention count=%d bytes=%d", budget.count, budget.bytes)
	}
	expired, err := store.List(Connections, "b", ListOptions{Before: page.Next})
	if err != nil || !expired.Expired {
		t.Fatal(expired, err)
	}
}
