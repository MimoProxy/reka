package httprewrite

import (
	"errors"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestHostnamesMatch(t *testing.T) {
	entries := []string{
		"-pinned.example.com", "*.example.com", "-api.example.com", "api.example.com:8443",
		"-a?b.test:0", "*.test:0", "all.example.org:0", "[2001:DB8::1]:8443", "[::1]",
		"192.0.2.10:443", "?x.alt", "x*star.alt", "-blocked.alt:0", "blocked.alt:8443",
	}
	hostnames, err := NewHostnames(entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host string
		port uint16
		want bool
	}{
		{"PINNED.EXAMPLE.COM", 443, false},
		{"api.example.com", 443, true},
		{"api.example.com", 8443, true},
		{"api.example.com", 80, false},
		{"A.B.Example.Com", 443, true},
		{"example.com", 443, false},
		{"abc.test", 443, true},
		{"a.b.test", 80, false},
		{"a界b.test", 80, false},
		{"a..b.test", 80, true},
		{"all.example.org", 65535, true},
		{"2001:0db8:0000::1", 8443, true},
		{"2001:db8::1", 443, false},
		{"[::1]", 443, true},
		{"192.0.2.10", 443, true},
		{"192.0.2.10", 8443, false},
		{"Qx.alt", 443, true},
		{"x.alt", 443, false},
		{"xx.alt", 443, true},
		{"xstar.alt", 443, true},
		{"x.deep.star.alt", 443, true},
		{"blocked.alt", 8443, false},
		{"", 443, false},
	} {
		if got := hostnames.Match(tc.host, tc.port); got != tc.want {
			t.Errorf("Match(%q, %d) = %t, want %t", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestHostnamesValidateEntries(t *testing.T) {
	entries := []string{"*.valid.test", "", "-", "with space.test", "path/test", "a:65536", "a:-1", "a:+1", "a:", "[::1", "[::1]x", "[1.2.3.4]", "::1", "[fe80::1%eth0]"}
	_, err := NewHostnames(entries)
	var invalid HostnameErrors
	if !errors.As(err, &invalid) || len(invalid) != len(entries)-1 {
		t.Fatalf("NewHostnames returned %v, want one error per invalid entry", err)
	}
	for i, entry := range invalid {
		if entry.Index != i+1 || entry.Err == nil {
			t.Errorf("invalid entry = %+v, want nonempty error at index %d", entry, i+1)
		}
	}
}

func TestHostnamesIPv6GlobUsesOriginalSpelling(t *testing.T) {
	hostnames, err := NewHostnames([]string{"-*.0.2.1:0", "[::ffff:192.0.2.1]:0", "plain.test"})
	if err != nil {
		t.Fatal(err)
	}
	if hostnames.Match("::ffff:192.0.2.1", 8443) {
		t.Fatal("wildcard suffix did not match the dotted IPv6 spelling")
	}
	if !hostnames.Match("::ffff:c000:201", 8443) {
		t.Fatal("equivalent IPv6 literal should match without the dotted wildcard")
	}
	if hostnames.Match("[plain.test]", 443) {
		t.Fatal("bracketed DNS label should not match a hostname")
	}
}

func TestHostnamesMatchLinearScan(t *testing.T) {
	type linearEntry struct {
		regexp  *regexp.Regexp
		port    uint16
		exclude bool
	}
	patterns := []string{"a.test", "A.test", "b.test", "*.test", "*.x.test", "a*test", "?*.test", "a.?.test", "a??.test", "a**.test", "*.*.test", "*b*f.test", "x.test", "*.a.x.test"}
	hosts := []string{"a.test", "A.test", "b.test", "aＢ.test", "a.b.test", "a.x.test", "b.a.x.test", "a..test", "abc.test", "x.test", ".test", "abf.test", "bbf.test", "out.invalid"}
	ports := []uint16{0, 80, 443, 8443}
	rng := rand.New(rand.NewPCG(51, 104))
	for range 100 {
		var entries []string
		var linear []linearEntry
		for range 16 {
			pattern := patterns[rng.IntN(len(patterns))]
			quoted := regexp.QuoteMeta(strings.ToLower(pattern))
			glob := strings.NewReplacer(`\*`, `.*`, `\?`, `.`).Replace(quoted)
			port := ports[rng.IntN(len(ports))]
			entry := pattern + ":" + strconv.Itoa(int(port))
			exclude := rng.IntN(2) == 0
			if exclude {
				entry = "-" + entry
			}
			entries = append(entries, entry)
			linear = append(linear, linearEntry{regexp.MustCompile(`(?s)\A` + glob + `\z`), port, exclude})
		}
		indexed, err := NewHostnames(entries)
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range hosts {
			for _, port := range ports {
				var want bool
				for _, entry := range linear {
					if (entry.port == 0 || entry.port == port) && entry.regexp.MatchString(strings.ToLower(host)) {
						want = !entry.exclude
						break
					}
				}
				if got := indexed.Match(host, port); got != want {
					t.Fatalf("Match(%q, %d) with %q = %t, linear match = %t", host, port, entries, got, want)
				}
			}
		}
	}
}
