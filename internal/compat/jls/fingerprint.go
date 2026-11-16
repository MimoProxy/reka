// Fingerprint presets follow the pinned reference; see ORIGIN.md.
package jls

import (
	utls "github.com/metacubex/utls"
	"math/rand/v2"
	"sync"
)

var randomFingerprint = sync.OnceValue(func() utls.ClientHelloID {
	n := rand.IntN(12)
	switch {
	case n < 6:
		return utls.HelloChrome_Auto
	case n < 9:
		return utls.HelloSafari_Auto
	case n < 11:
		return utls.HelloIOS_Auto
	default:
		return utls.HelloFirefox_Auto
	}
})

func getFingerprint(name string) (utls.ClientHelloID, bool) {
	if name == "random" {
		return randomFingerprint(), true
	}
	v, ok := fingerprints[name]
	return v, ok
}

var fingerprints = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"ios":     utls.HelloIOS_Auto,
	"android": utls.HelloAndroid_11_OkHttp,
	"edge":    utls.HelloEdge_Auto,
	"360":     utls.Hello360_Auto,
	"qq":      utls.HelloQQ_Auto,
	"random":  {},

	// classical fingerprints without X25519MLKEM768
	"chrome120":  utls.HelloChrome_120,
	"firefox120": utls.HelloFirefox_120,
	"safari16":   utls.HelloSafari_16_0,

	// deprecated fingerprints should not be used
	"chrome_psk":                 utls.HelloChrome_100_PSK,
	"chrome_psk_shuffle":         utls.HelloChrome_106_Shuffle,
	"chrome_padding_psk_shuffle": utls.HelloChrome_114_Padding_PSK_Shuf,
	"chrome_pq":                  utls.HelloChrome_115_PQ,
	"chrome_pq_psk":              utls.HelloChrome_115_PQ_PSK,
	"randomized":                 utls.HelloRandomized,
}

func init() {
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomized := utls.HelloRandomized
	randomized.Seed, _ = utls.NewPRNGSeed()
	randomized.Weights = &weights
	fingerprints["randomized"] = randomized
}
