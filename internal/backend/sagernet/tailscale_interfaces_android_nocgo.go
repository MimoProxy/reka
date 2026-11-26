//go:build with_gvisor && android && !cgo

package sagernet

import (
	"errors"

	"github.com/sagernet/sing-box/adapter"
)

func installTailscaleInterfaceGetter(*adapter.Scope) error {
	return errors.New("Tailscale on Android requires the native network interface enumerator")
}
