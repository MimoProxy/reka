//go:build ios

package sagernet

import "testing"

func TestMITMHTTP2IOSLimits(t *testing.T) {
	config := mitmHTTP2Config()
	if config.MaxConcurrentStreams != 32 || !config.StrictMaxConcurrentRequests ||
		config.MaxReadFrameSize != 16<<10 || config.MaxReceiveBufferPerConnection != 256<<10 ||
		config.MaxReceiveBufferPerStream != 64<<10 || config.MaxDecoderHeaderTableSize != 4096 ||
		config.MaxEncoderHeaderTableSize != 4096 {
		t.Errorf("unexpected HTTP/2 limits: %+v", config)
	}
	if mitmBodyBufferBytes != 4<<20 {
		t.Errorf("MITM body budget = %d, want 4 MiB", mitmBodyBufferBytes)
	}
}
