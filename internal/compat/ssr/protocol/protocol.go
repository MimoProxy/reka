package protocol

import (
	"errors"
	"fmt"
	"maps"
	randv2 "math/rand/v2"
	"net"
	"slices"
	"strings"
)

var (
	errAuthSHA1V4CRC32Error   = errors.New("auth_sha1_v4 decode data wrong crc32")
	errAuthSHA1V4LengthError  = errors.New("auth_sha1_v4 decode data wrong length")
	errAuthSHA1V4Adler32Error = errors.New("auth_sha1_v4 decode data wrong adler32")
	errAuthAES128MACError     = errors.New("auth_aes128 decode data wrong mac")
	errAuthAES128LengthError  = errors.New("auth_aes128 decode data wrong length")
	errAuthAES128ChksumError  = errors.New("auth_aes128 decode data wrong checksum")
	errAuthChainLengthError   = errors.New("auth_chain decode data wrong length")
	errAuthChainChksumError   = errors.New("auth_chain decode data wrong checksum")
)

type Protocol interface {
	StreamConn(net.Conn, []byte) net.Conn
	PacketConn(net.PacketConn) net.PacketConn
}

type protocolCreator func(b *Base) Protocol

var protocolList = make(map[string]struct {
	overhead int
	new      protocolCreator
})

func register(name string, c protocolCreator, o int) {
	protocolList[name] = struct {
		overhead int
		new      protocolCreator
	}{overhead: o, new: c}
}

func Validate(name string) error {
	if _, ok := protocolList[name]; ok {
		return nil
	}
	return fmt.Errorf("unsupported SSR protocol (supported: %s)", strings.Join(slices.Sorted(maps.Keys(protocolList)), ", "))
}

func PickProtocol(name string, b *Base) (Protocol, error) {
	if err := Validate(name); err != nil {
		return nil, err
	}
	choice := protocolList[name]
	settings := *b
	settings.Overhead += choice.overhead
	return choice.new(&settings), nil
}

func getHeadSize(b []byte, defaultValue int) int {
	if len(b) < 2 {
		return defaultValue
	}
	headType := b[0] & 7
	switch headType {
	case 1:
		return 7
	case 4:
		return 19
	case 3:
		return 4 + int(b[1])
	}
	return defaultValue
}

func getDataLength(b []byte) int {
	bLength := len(b)
	dataLength := getHeadSize(b, 30) + randv2.IntN(32)
	if bLength < dataLength {
		return bLength
	}
	return dataLength
}
