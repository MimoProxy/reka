//go:build !ios

package generation

import (
	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/internal/script/gojaengine"
)

func platformScriptEngine(factory func() script.Engine) script.Engine {
	if factory != nil {
		return factory()
	}
	return gojaengine.New()
}
