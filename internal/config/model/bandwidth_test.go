package model

import (
	"fmt"
	"math"
	"testing"
)

func TestBandwidthReferenceUnitsAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		value string
		bytes uint64
	}{{"", 0}, {"0", 0}, {"100", 12500000}, {"100 Mbps", 12500000}, {"2MBps", 2000000}, {"524288bps", 65536}, {"65536 Bps", 65536}, {"2 Gbps", 250000000}, {"1TBps", 1000000000000}} {
		got, err := BandwidthBytes(tc.value)
		if err != nil || got != tc.bytes {
			t.Fatal(tc.value, got, err)
		}
	}
	for _, value := range []string{"-1", "1.5 Mbps", "100 mbps", "10 MiBps", "18446744073709551616Bps", "18446744073709551615TBps"} {
		if _, err := BandwidthBytes(value); err == nil {
			t.Fatal("invalid or overflowing rate accepted", value)
		}
	}
}

func TestBandwidthUint64DocumentBoundsAndJSONRoundTrip(t *testing.T) {
	for _, input := range []string{
		fmt.Sprintf("schema-version: 1\noutbounds: [{id: node, type: direct, multiplex: {brutal: {up-bps: %d}}}]", uint64(math.MaxUint64)),
		fmt.Sprintf(`{"schema-version":1,"outbounds":[{"id":"node","type":"direct","multiplex":{"brutal":{"up-bps":%d}}}]}`, uint64(math.MaxUint64)),
	} {
		p, _, ds := ParseProfile([]byte(input))
		if ds.HasErrors() || p.Outbounds[0].Multiplex.Brutal.UpBPS != math.MaxUint64 {
			t.Fatal(ds)
		}
	}
	for _, value := range []string{"-1", "18446744073709551616", "1.5"} {
		_, _, ds := ParseProfile([]byte("schema-version: 1\noutbounds: [{id: node, type: direct, multiplex: {brutal: {up-bps: " + value + "}}}]"))
		if !ds.HasErrors() {
			t.Fatal("invalid uint64 rate accepted", value)
		}
	}
}
