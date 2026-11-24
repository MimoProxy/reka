//go:build !ios || !cgo

package generation

import RD "github.com/MimoProxy/reka/internal/dns"

func (e *Engine) systemDNSExchange() RD.SystemExchangeFunc { return nil }
