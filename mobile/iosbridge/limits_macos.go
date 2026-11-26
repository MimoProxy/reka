//go:build darwin && !ios && cgo && with_gvisor

package main

import (
	"math"

	"github.com/MimoProxy/reka/mobile/scriptbridge"
)

// A macOS system extension has no Network Extension memory limit, so the
// Go runtime keeps its defaults and no memory guard runs, as sing-box's
// libbox applies its Network Extension limits only on iOS.
const guardExtensionMemory = false

func tuneExtensionRuntime() {}

// Scripts run without footprint checks: a nil Footprint disables them.
var scriptOptions = scriptbridge.Options{SkipAbove: math.MaxUint64, DiscardAbove: math.MaxUint64}
