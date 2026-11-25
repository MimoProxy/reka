//go:build with_gvisor

package packettunnel

import (
	"sync/atomic"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/script"
)

type scriptHostRegistration struct {
	factory func() script.Engine
	notify  func(api.ScriptNotification)
}

var scriptHost atomic.Pointer[scriptHostRegistration]

// SetScriptHost registers the script engine and its notification sink for
// subsequent packet tunnel sessions. A nil factory clears the registration.
func SetScriptHost(factory func() script.Engine, notify func(api.ScriptNotification)) {
	if factory == nil {
		scriptHost.Store(nil)
		return
	}
	scriptHost.Store(&scriptHostRegistration{factory: factory, notify: notify})
}
