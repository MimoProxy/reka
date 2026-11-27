package sagernet

import (
	"testing"

	D "github.com/miekg/dns"
)

func TestPlainDNSReadSize(t *testing.T) {
	q := new(D.Msg)
	q.SetQuestion("example.com.", D.TypeA)
	if got := plainDNSReadSize(q); got != plainDNSMinReadSize {
		t.Fatalf("without EDNS0 = %d, want %d", got, plainDNSMinReadSize)
	}
	q.SetEdns0(1232, false)
	if got := plainDNSReadSize(q); got != plainDNSMinReadSize {
		t.Fatalf("EDNS0 1232 = %d, want %d", got, plainDNSMinReadSize)
	}
	q.IsEdns0().SetUDPSize(4096)
	if got := plainDNSReadSize(q); got != 4096 {
		t.Fatalf("EDNS0 4096 = %d, want 4096", got)
	}
}
