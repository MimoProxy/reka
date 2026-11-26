package compile

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
)

func (c *compiler) mieru(base string, raw *model.Protocol, out *Outbound) {
	fail := func(field, message string) {
		c.errorf(model.DocProfile, base+"/"+field, "outbound.mieru", "%s", message)
	}
	if out.Username == "" && !c.hasErrorAt(base+"/username") {
		fail("username", "Mieru username is required")
	} else if len(out.Username) > constant.MaxUserNameLen {
		fail("username", fmt.Sprintf("Mieru username exceeds %d bytes", constant.MaxUserNameLen))
	}
	// Mieru's ValidateClientConfigSingleProfile limits the password to 64 bytes.
	if out.Password == "" && !c.hasErrorAt(base+"/password") {
		fail("password", "Mieru password is required")
	} else if len(out.Password) > 64 {
		fail("password", "Mieru password exceeds 64 bytes")
	}
	if _, present := c.ppos[base+"/multiplex"]; present {
		fail("multiplex", "Mieru manages its own streams. Use protocol/multiplexing.")
	}
	if d := out.Dialer; d != nil {
		if d.TFO {
			fail("dialer/tfo", "Mieru does not support TCP Fast Open")
		}
		if d.MPTCP {
			fail("dialer/mptcp", "Mieru does not support multipath TCP")
		}
	}

	p := model.Protocol{}
	if raw != nil {
		p = *raw
	}
	out.Protocol = &p
	if p.Transport != "TCP" && p.Transport != "UDP" {
		fail("protocol/transport", "Mieru transport must be TCP or UDP")
	}
	if _, present := c.ppos[base+"/protocol/server-ports"]; present {
		if _, hasPort := c.ppos[base+"/port"]; hasPort {
			fail("protocol/server-ports", "Mieru port and protocol/server-ports are mutually exclusive")
		} else if len(p.ServerPorts) != 1 {
			fail("protocol/server-ports", "Mieru requires exactly one port range")
		} else if normalized, err := mieruPortRange(p.ServerPorts[0]); err != nil {
			fail("protocol/server-ports", err.Error())
		} else {
			p.ServerPorts = []string{normalized}
		}
	}
	if _, ok := appctlpb.MultiplexingLevel_value[p.Multiplexing]; p.Multiplexing != "" && !ok {
		fail("protocol/multiplexing", "Mieru multiplexing level must be MULTIPLEXING_DEFAULT, MULTIPLEXING_OFF, MULTIPLEXING_LOW, MULTIPLEXING_MIDDLE or MULTIPLEXING_HIGH")
	}
	if _, ok := appctlpb.HandshakeMode_value[p.HandshakeMode]; p.HandshakeMode != "" && !ok {
		fail("protocol/handshake-mode", "Mieru handshake mode must be HANDSHAKE_DEFAULT, HANDSHAKE_STANDARD or HANDSHAKE_NO_WAIT")
	}
	if p.TrafficPattern != "" {
		pattern, err := trafficpattern.Decode(p.TrafficPattern)
		if err != nil {
			fail("protocol/traffic-pattern", "cannot decode Mieru traffic pattern: "+err.Error())
		} else if err := trafficpattern.Validate(pattern); err != nil {
			fail("protocol/traffic-pattern", "invalid Mieru traffic pattern: "+err.Error())
		}
	}
}

// Accept the native start:end notation and Mieru's start-end spelling.
func mieruPortRange(value string) (string, error) {
	first, last, found := strings.Cut(strings.Replace(value, ":", "-", 1), "-")
	if !found {
		return "", fmt.Errorf("Mieru port range must have a start and an end")
	}
	begin, beginErr := strconv.ParseUint(first, 10, 16)
	end, endErr := strconv.ParseUint(last, 10, 16)
	if beginErr != nil || endErr != nil || begin == 0 || end == 0 {
		return "", fmt.Errorf("Mieru port range endpoints must be integers between 1 and 65535")
	}
	if begin > end {
		return "", fmt.Errorf("Mieru port range start must be less than or equal to its end")
	}
	return fmt.Sprintf("%d-%d", begin, end), nil
}
