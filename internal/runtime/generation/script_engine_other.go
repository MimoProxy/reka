//go:build !ios

package generation

import (
	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/internal/script/gojaengine"
)

// Use the script host's default concurrency outside the Packet Tunnel budget.
const platformScriptConcurrency = 0

const (
	backgroundScriptConcurrency = 2  // Matches Surge's two JavaScriptCore sessions.
	scriptRunCapacity           = 64 // Reka desktop history limit.
)

func platformScriptEngine(factory func() script.Engine) script.Engine {
	if factory != nil {
		return factory()
	}
	return gojaengine.New()
}
