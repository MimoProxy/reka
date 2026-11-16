package main

import (
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/metacubex/mihomo/common/utils"
	"testing"
)

func TestBandwidthMatchesPinnedReference(t *testing.T) {
	for _, value := range []string{"", "0", "+10", "0500", "10 Mbps", "500 Kbps", "750001 bps", "2MBps", "65536Bps", "1 Gbps", "1TBps", "18446744073709551615Bps"} {
		native, err := model.BandwidthBytes(value)
		if reference := utils.StringToBps(value); err != nil || native != reference {
			t.Fatal(value, native, reference, err)
		}
	}
}
