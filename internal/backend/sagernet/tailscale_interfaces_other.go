//go:build with_gvisor && !android

package sagernet

import "github.com/sagernet/sing-box/adapter"

func installTailscaleInterfaceGetter(*adapter.Scope) error { return nil }
