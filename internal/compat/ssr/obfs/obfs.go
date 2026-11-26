package obfs

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
)

// Until the peer replies, these obfuscators queue application writes for the final handshake flight.
const maxPending = 1 << 20

var (
	errPendingFull                         = errors.New("SSR obfs handshake pending data exceeds 1 MiB")
	errTLS12TicketAuthIncorrectMagicNumber = errors.New("tls1.2_ticket_auth incorrect magic number")
	errTLS12TicketAuthHMACError            = errors.New("tls1.2_ticket_auth hmac verifying failed")
)

type authData struct {
	clientID [32]byte
}

type Obfs interface {
	StreamConn(net.Conn) net.Conn
}

type obfsCreator func(b *Base) Obfs

var obfsList = make(map[string]struct {
	overhead int
	new      obfsCreator
})

func register(name string, c obfsCreator, o int) {
	obfsList[name] = struct {
		overhead int
		new      obfsCreator
	}{overhead: o, new: c}
}

func Validate(name string) error {
	if _, ok := obfsList[name]; ok {
		return nil
	}
	return fmt.Errorf("unsupported SSR obfs (supported: %s)", strings.Join(slices.Sorted(maps.Keys(obfsList)), ", "))
}

func PickObfs(name string, b *Base) (Obfs, int, error) {
	if err := Validate(name); err != nil {
		return nil, 0, err
	}
	choice := obfsList[name]
	return choice.new(b), choice.overhead, nil
}
