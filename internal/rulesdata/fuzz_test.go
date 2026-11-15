package rulesdata

import "testing"

func FuzzRuleResources(f *testing.F) {
	for _, s := range []string{"payload: ['+.example.test']", "example.test\n", "DOMAIN,example.test", "IP-CIDR,192.0.2.0/24", ""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			t.Skip()
		}
		for _, format := range []string{"text", "yaml", "mrs"} {
			for _, kind := range []string{"domain", "ipcidr", "classical"} {
				_, _ = Decode(kind, format, "", b)
			}
		}
		_, _ = Decode("geoip", "dat", "cn", b)
		_, _ = Decode("geosite", "dat", "cn", b)
	})
}
