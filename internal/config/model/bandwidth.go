package model

import (
	"errors"
	"math"
	"regexp"
	"strconv"
)

var bandwidthPattern = regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`)

// BandwidthBytes follows the pinned Clash integer/unit grammar. Unitless
// values mean Mbps; lowercase b means bits, uppercase B means bytes. Reject
// invalid input and arithmetic overflow instead of accidentally disabling a
// configured rate. This is a configuration conversion, not a rate limiter.
func BandwidthBytes(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	if _, err := strconv.ParseUint(value, 10, 64); err == nil {
		value += " Mbps"
	}
	parts := bandwidthPattern.FindStringSubmatch(value)
	if parts == nil {
		return 0, errors.New("expected an integer bandwidth or K/M/G/T bps/Bps")
	}
	n, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, errors.New("bandwidth exceeds uint64")
	}
	factor := uint64(1)
	for i := 0; i < map[string]int{"K": 1, "M": 2, "G": 3, "T": 4}[parts[2]]; i++ {
		factor *= 1000
	}
	if n > math.MaxUint64/factor {
		return 0, errors.New("bandwidth overflows uint64")
	}
	n *= factor
	if parts[3] == "b" {
		n /= 8
	}
	return n, nil
}
