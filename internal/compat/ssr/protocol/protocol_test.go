package protocol

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/MimoProxy/reka/internal/compat/ssr/tools"
)

func TestAuthenticationParameters(t *testing.T) {
	md5Key := md5.Sum([]byte("key"))
	sha1Key := sha1.Sum([]byte("key"))
	base := &Base{Param: "64:key:ignored", Key: make([]byte, 16)}
	for _, test := range []struct {
		name string
		want []byte
	}{
		{"auth_aes128_md5", md5Key[:]}, {"auth_aes128_sha1", sha1Key[:]}, {"auth_chain_a", []byte("key")}, {"auth_chain_b", []byte("key")},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, err := PickProtocol(test.name, base)
			if err != nil {
				t.Fatal(err)
			}
			var account *userData
			switch p := p.(type) {
			case *authAES128:
				account = p.userData
			case *authChainA:
				account = p.userData
			case *authChainB:
				account = p.userData
			default:
				t.Fatalf("unexpected protocol %T", p)
			}
			if binary.LittleEndian.Uint32(account.userID[:]) != 64 || !bytes.Equal(account.userKey, test.want) {
				t.Fatal("incorrect authentication account")
			}
		})
	}
	for _, param := range []string{"", "missing-separator", "-1:key", "4294967296:key"} {
		if got := newUserData(&Base{Param: param, Key: base.Key}, nil); !bytes.Equal(got.userKey, base.Key) {
			t.Fatal("expected fallback to the main key")
		}
	}
}

func TestAuthenticationConnectionIDs(t *testing.T) {
	var a authData
	const count = 64
	ids := make(chan uint32, count)
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() { ids <- a.next().connectionID })
	}
	wg.Wait()
	close(ids)
	seen := make(map[uint32]bool)
	for id := range ids {
		if seen[id] {
			t.Fatal("duplicate connection ID")
		}
		seen[id] = true
	}
}

func TestAuthChainPreservesCallerPayload(t *testing.T) {
	base := &Base{Key: tools.KDF("secret", 16), Param: "1:key"}
	payload := []byte("application data")
	for _, name := range []string{"auth_chain_a", "auth_chain_b"} {
		p, err := PickProtocol(name, base)
		if err != nil {
			t.Fatal(err)
		}
		codec := p.StreamConn(nil, nil).(*streamConn).codec
		for range 2 {
			var encoded bytes.Buffer
			if err := codec.Encode(&encoded, payload); err != nil {
				t.Fatal(err)
			}
		}
		packets := p.PacketConn(nil).(*packetConn).codec
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				var encoded bytes.Buffer
				if err := packets.EncodePacket(&encoded, payload); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if string(payload) != "application data" {
			t.Fatal("caller payload changed")
		}
	}
}

func TestAuthenticatedPaddingBounds(t *testing.T) {
	a := newAuthAES128MD5(&Base{Key: tools.KDF("secret", 16)}).(*authAES128)
	for _, padding := range []byte{0, 40, 255} {
		record := make([]byte, 12)
		binary.LittleEndian.PutUint16(record, uint16(len(record)))
		macKey := append(bytes.Clone(a.userKey), 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(macKey[len(a.userKey):], a.recvID)
		copy(record[2:4], a.hmac(macKey, record[:2]))
		record[4] = padding
		binary.LittleEndian.PutUint16(record[5:7], 100)
		copy(record[8:], a.hmac(macKey, record[:8]))
		var dst bytes.Buffer
		if err := a.Decode(&dst, bytes.NewBuffer(record)); err != errAuthAES128LengthError {
			t.Fatalf("padding %d: %v", padding, err)
		}
	}
}
