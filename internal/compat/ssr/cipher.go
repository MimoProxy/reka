package ssr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/compat/ssr/tools"
	"golang.org/x/crypto/chacha20"
)

type cipherSizes struct {
	key, iv int
}

var methods = map[string]cipherSizes{
	"none": {16, 0}, "dummy": {16, 0},
	"rc4-md5":     {16, 16},
	"aes-128-ctr": {16, 16}, "aes-192-ctr": {24, 16}, "aes-256-ctr": {32, 16},
	"aes-128-cfb": {16, 16}, "aes-192-cfb": {24, 16}, "aes-256-cfb": {32, 16},
	"chacha20": {32, 8}, "chacha20-ietf": {32, 12}, "xchacha20": {32, 24},
}

func ValidateMethod(name string) error {
	name = strings.ToLower(name)
	if _, ok := methods[name]; ok {
		return nil
	}
	supported := strings.Join(slices.Sorted(maps.Keys(methods)), ", ")
	switch {
	case name == "":
		return fmt.Errorf("SSR stream cipher method is required (supported: %s)", supported)
	case strings.HasPrefix(name, "aead_"), strings.HasPrefix(name, "2022-"),
		strings.HasSuffix(name, "-gcm"), strings.HasSuffix(name, "-ccm"), strings.HasSuffix(name, "-poly1305"):
		return fmt.Errorf("SSR requires a stream cipher and cannot use AEAD (supported: %s)", supported)
	default:
		return fmt.Errorf("unsupported SSR stream cipher (supported: %s)", supported)
	}
}

type streamMethod struct {
	name   string
	key    []byte
	ivSize int
	block  cipher.Block
}

func newMethod(name, password string) (*streamMethod, error) {
	if err := ValidateMethod(name); err != nil {
		return nil, err
	}
	name = strings.ToLower(name)
	size := methods[name]
	m := &streamMethod{name: name, key: tools.KDF(password, size.key), ivSize: size.iv}
	if strings.HasPrefix(name, "aes-") {
		var err error
		m.block, err = aes.NewCipher(m.key)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

const chachaLimit = uint64(1) << 38

var errCounterLimit = errors.New("SSR ChaCha20 stream counter exhausted")

type keyStream struct {
	stream    cipher.Stream
	remaining uint64
}

func (m *streamMethod) stream(iv []byte, decrypt bool) (*keyStream, error) {
	if len(iv) != m.ivSize {
		return nil, errors.New("invalid SSR cipher IV length")
	}
	s := &keyStream{remaining: ^uint64(0)}
	var err error
	switch {
	case m.ivSize == 0:
		// The dummy method still derives a key for SSR authentication.
	case m.name == "rc4-md5":
		hash := md5.New()
		hash.Write(m.key)
		hash.Write(iv)
		s.stream, err = rc4.NewCipher(hash.Sum(nil))
	case strings.HasSuffix(m.name, "-ctr"):
		s.stream = cipher.NewCTR(m.block, iv)
	case strings.HasSuffix(m.name, "-cfb"):
		if decrypt {
			s.stream = cipher.NewCFBDecrypter(m.block, iv)
		} else {
			s.stream = cipher.NewCFBEncrypter(m.block, iv)
		}
	default:
		if m.name == "chacha20" {
			nonce := make([]byte, chacha20.NonceSize)
			copy(nonce[4:], iv)
			iv = nonce
		}
		s.stream, err = chacha20.NewUnauthenticatedCipher(m.key, iv)
		s.remaining = chachaLimit
	}
	return s, err
}

func (s *keyStream) xor(dst, src []byte) error {
	if uint64(len(src)) > s.remaining {
		return errCounterLimit
	}
	if s.stream == nil {
		copy(dst, src)
	} else {
		s.stream.XORKeyStream(dst, src)
	}
	s.remaining -= uint64(len(src))
	return nil
}
