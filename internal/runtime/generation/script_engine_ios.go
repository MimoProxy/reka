package generation

import "github.com/MimoProxy/reka/internal/script"

// Reka limits the Packet Tunnel to one script at a time. JavaScriptCore
// execution cannot be interrupted and a single run measured about 10 MiB on iOS.
const platformScriptConcurrency = 1

func platformScriptEngine(factory func() script.Engine) script.Engine {
	if factory == nil {
		return nil
	}
	return factory()
}
