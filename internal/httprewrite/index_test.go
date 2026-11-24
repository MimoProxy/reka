package httprewrite

import (
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"testing"
)

func TestRuleIndexMatchesLinearScan(t *testing.T) {
	patterns := []string{
		`^https?://example\.com/`,
		`/path`,
		`^https://other\.com/`,
		`^https?:\/\/example\.com\/path`,
		`^http://example\.com`,
		`^http://example\.com$`,
		`^https://example\.com\?`,
		`^https://example\.com:`,
		`^https://example\.com(?:/|evil)`,
		`^https://EXAMPLE\.COM/`,
		`^https://(?i:example\.com)/`,
		`^https://(?i:kelvin\.test)/`,
		`^https://[a-z]+\.com/`,
		`^https://example\.com/|/path`,
		`^https://\[::1\]`,
		`(?m)^https://example\.com/`,
		`^https://example\.com(?m:$)`,
		`\Ahttps://example\.com\z`,
		`^$`,
		`^https://\[::1\]:443/`,
		`^https://example\.com?/`,
	}
	urls := []string{
		`https://example.com/path`,
		`https://exAMPLE.com/path`,
		`https://EXAMPLE.COM/`,
		`http://example.com/path`,
		`https://example.com`,
		`http://example.com`,
		`http://example.competitor/path`,
		`https://example.comevil`,
		`https://example.com:8443/path`,
		`https://example.com:443@other.com/path`,
		`https://example.com:invalid/path`,
		`https://example.com?param=path`,
		`https://example.co/path`,
		`http://example.com#fragment`,
		`https://other.com/path`,
		`https://Kelvin.test/path`,
		`https://[::1]:443/path`,
		`https://user@EXAMPLE.COM/path`,
		"prefix\nhttps://example.com/path",
		"https://example.com\ntrailing text",
		`/path`,
		``,
	}

	var index ruleIndex
	compiled := make([]*regexp.Regexp, len(patterns))
	lazy := make([]*lazyRegexp, len(patterns))
	for i, pattern := range patterns {
		re, parsed, err := newLazyRegexp(pattern)
		if err != nil {
			t.Fatal(err)
		}
		lazy[i] = re
		index.add(i, parsed)
		compiled[i] = regexp.MustCompile(pattern)
	}
	if want := []int{0, 3, 5, 6, 7, 9, 17}; !slices.Equal(index.byHost["example.com"], want) {
		t.Fatalf("example.com indexed rules = %v, want %v", index.byHost["example.com"], want)
	}
	if want := []int{19}; !slices.Equal(index.byHost["[::1]"], want) {
		t.Fatalf("[::1] indexed rules = %v, want %v", index.byHost["[::1]"], want)
	}
	for _, url := range urls {
		t.Run(url, func(t *testing.T) {
			var want, got []int
			for i, re := range compiled {
				if re.MatchString(url) {
					want = append(want, i)
				}
			}
			index.each(url, func(i int) bool {
				// The literal prefilter must not change the result.
				if lazy[i].MatchString(url) {
					got = append(got, i)
				}
				return true
			})
			if !slices.Equal(got, want) {
				t.Fatalf("indexed matches = %v, linear matches = %v", got, want)
			}
		})
	}
}

func TestLazyRegexpCompilesOnDemand(t *testing.T) {
	re, _, err := newLazyRegexp(`a(b)c`)
	if err != nil {
		t.Fatal(err)
	}
	if re.regexp != nil {
		t.Fatal("regexp was compiled during validation")
	}
	compiled := re.get()
	if !compiled.MatchString("abc") || re.get() != compiled {
		t.Fatal("regexp was not compiled and cached")
	}
}

func TestIndexedRequestKeepsOtherHostsUncompiled(t *testing.T) {
	set, err := New(Spec{HTTPRewrites: []HTTPRewrite{
		{ID: "other", Match: `^https://other\.test/`, Action: "reject"},
		{ID: "used", Match: `^https://used\.test/`, Action: "reject"},
	}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range set.http {
		if rule.match.regexp != nil {
			t.Fatalf("rule %q was compiled during validation", rule.id)
		}
	}
	result := set.Request(Request{URL: "https://used.test/path"})
	if !slices.Equal(result.MatchedIDs, []string{"used"}) {
		t.Fatalf("matched IDs = %v, want [used]", result.MatchedIDs)
	}
	if set.http[0].match.regexp != nil || set.http[1].match.regexp == nil {
		t.Fatal("expected only the matched hostname's regexp to compile")
	}
}

func BenchmarkIndexedRequest(b *testing.B) {
	const count = 5000
	spec := Spec{HTTPRewrites: make([]HTTPRewrite, count)}
	for i := range spec.HTTPRewrites {
		spec.HTTPRewrites[i] = HTTPRewrite{
			ID:     fmt.Sprintf("ad-%d", i),
			Match:  fmt.Sprintf(`^https?://ad-%d\.example\.com/`, i),
			Action: "reject",
		}
	}
	req := Request{URL: fmt.Sprintf("https://ad-%d.example.com/path", count-1), Method: "GET"}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	set, err := New(spec, Options{})
	if err != nil {
		b.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(spec)

	b.ReportAllocs()
	for b.Loop() {
		result := set.Request(req)
		if len(result.MatchedIDs) != 1 {
			b.Fatal("the indexed rule did not match")
		}
	}
	b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "new-heap-B")
}

func TestRequiredLiteral(t *testing.T) {
	for pattern, want := range map[string]string{
		`^https?:\/\/(www.)?officesoftcn\.com\/`:          "officesoftcn.com/",
		`^https?://api\.(pinduoduo|yangkeduo)\.com/api/x`: ".com/api/x",
		`/path`:                       "/path",
		`^https://(?i:example\.com)/`: "https://",
		`a|bcdef`:                     "",
		`^ab(c)`:                      "",
		`(?i)^https://example\.com/`:  "",
	} {
		_, parsed, err := newLazyRegexp(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := requiredLiteral(parsed); got != want {
			t.Errorf("requiredLiteral(%q) = %q, want %q", pattern, got, want)
		}
	}
}
