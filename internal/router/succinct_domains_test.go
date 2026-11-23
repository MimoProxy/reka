package router

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/sagernet/sing/common/domain"
)

// The builder writes sing's serialized matcher directly. If a sing upgrade
// changes that format, this comparison fails instead of matching silently
// going wrong.
func TestDomainMatcherMatchesSingBuilder(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	label := func() string {
		const letters = "abcdefghijklmnopqrstuvwxyz0123456789-"
		b := make([]byte, 1+rng.IntN(8))
		for i := range b {
			b[i] = letters[rng.IntN(len(letters)-1)]
		}
		return string(b)
	}
	var names, suffixes, keys []string
	for i := range 2000 {
		name := fmt.Sprintf("%s.%s.test", label(), label())
		if i%3 == 0 {
			suffixes = append(suffixes, name)
			keys = append(keys, reversedDomainKey(name, "\n"))
		} else {
			names = append(names, name)
			keys = append(keys, reversedDomainKey(name, ""))
		}
	}
	ours, _, err := buildDomainMatcher(keys)
	if err != nil {
		t.Fatal(err)
	}
	var got, want bytes.Buffer
	if err := ours.Write(&got); err != nil {
		t.Fatal(err)
	}
	if err := domain.NewMatcher(names, suffixes, false).Write(&want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatal("the domain matcher no longer matches sing's serialized format")
	}
}
