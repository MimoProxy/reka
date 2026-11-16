package policy

import (
	"context"
	"testing"
)

func TestExpectedStatusRanges(t *testing.T) {
	for _, tc := range []struct {
		rule string
		code int
		want bool
	}{{"", 204, true}, {"", 500, false}, {"*", 500, true}, {"204", 200, false}, {"204", 204, true}, {"200-299/302,401-403", 402, true}, {"[299-200]", 204, true}, {"200-299", 300, false}, {"65535", 65535, true}} {
		ctx := context.WithValue(context.Background(), expectedStatusKey{}, tc.rule)
		if ExpectedStatusAllows(ctx, tc.code) != tc.want {
			t.Fatal(tc)
		}
	}
	for _, rule := range []string{"204-", "65536", "-1", "200-299-400", "xxx"} {
		if _, err := ParseExpectedStatus(rule); err == nil {
			t.Fatal("invalid range accepted", rule)
		}
	}
}
