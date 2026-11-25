package moduleacquire

import (
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
)

// Some module hosts only serve modules and scripts to the client their
// format targets and answer other user agents with an HTML error page. A
// generic product name is rejected, so the request names the client with a
// version and platform tokens like the real apps send. Scripts already run
// with a Surge-compatible $environment for the same reason.
var moduleUserAgents = map[string]string{
	model.ModuleFormatSurge: "Surge iOS/3000",
	model.ModuleFormatLoon:  "Loon/900 CFNetwork/1568.300.101 Darwin/24.2.0",
	model.ModuleFormatStash: "Stash/2.4 Clash/1.9.0",
}

// moduleUserAgent returns the user agent for a module of format, or for the
// format its location implies before the body is known.
func moduleUserAgent(format, location string) string {
	if format == "" {
		format = module.DetectFormat(location, nil)
	}
	agent, ok := moduleUserAgents[format]
	if !ok {
		agent = moduleUserAgents[model.ModuleFormatSurge]
	}
	return agent
}
