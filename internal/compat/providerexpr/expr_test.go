package providerexpr

import "testing"

func TestOrderedOverridesAndNoExternalAccess(t *testing.T) {
	mapping := map[string]any{"name": " hk ", "port": 443, "udp": false, "secret": "removed"}
	for _, text := range []string{`.name |= (trim | upcase)`, `.name = "prefix-" + .name`, `.udp = true | del(.secret)`, `.port += 1`} {
		expr, err := NewOverrideExpr(text)
		if err != nil {
			t.Fatal(err)
		}
		if err = expr.Apply(mapping); err != nil {
			t.Fatal(err)
		}
	}
	if mapping["name"] != "prefix-HK" || mapping["udp"] != true || mapping["secret"] != nil {
		t.Fatal(mapping)
	}
	for _, text := range []string{`.password = env(SECRET)`, `.password = load("/etc/passwd")`, `. = [1,2]`} {
		expr, err := NewOverrideExpr(text)
		if err == nil {
			err = expr.Apply(map[string]any{})
		}
		if err == nil {
			t.Fatal("external or invalid-root expression accepted")
		}
	}
}

func TestOverrideAllocationBudget(t *testing.T) {
	for _, text := range []string{`.a[999999999] = true`, `.s = ("x" * 1000) * 1000000`} {
		expr, err := NewOverrideExpr(text)
		if err != nil {
			t.Fatal(err)
		}
		if err = expr.Apply(map[string]any{}); err == nil {
			t.Fatal("unbounded allocation accepted")
		}
	}
}
