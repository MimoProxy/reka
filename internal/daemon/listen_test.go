package daemon

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/MimoProxy/reka/internal/testnet"
)

// startListening starts a kernel from options(address), where address is
// a free loopback port for its listener, and returns both. A port another
// process took first is retried on a new port. The refused first start is
// recorded in its state root, so options must give every call a fresh one.
func startListening(t *testing.T, options func(address string) Options) (*Kernel, string) {
	t.Helper()
	var k *Kernel
	address := testnet.RetryAddr(t, func(listen netip.AddrPort) (err error) {
		if k, err = Start(options(listen.String())); err != nil {
			return err
		}
		if message := k.Service.StartError(); testnet.InUse(errors.New(message)) {
			k.Close()
			return errors.New(message)
		}
		return nil
	})
	return k, address.String()
}
