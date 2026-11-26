package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	randv2 "math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/compat/ssr/tools"
)

type Base struct {
	Key      []byte
	Overhead int
	Param    string
}

type userData struct {
	userKey []byte
	userID  [4]byte
}

// The optional account takes the first two colon-separated fields, as in mihomo.
func newUserData(b *Base, digest func([]byte) []byte) *userData {
	u := new(userData)
	fields := strings.SplitN(b.Param, ":", 3)
	if len(fields) >= 2 {
		if id, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
			binary.LittleEndian.PutUint32(u.userID[:], uint32(id))
			u.userKey = []byte(fields[1])
			if digest != nil {
				u.userKey = digest(u.userKey)
			}
		}
	}
	if len(u.userKey) == 0 {
		u.userKey = b.Key
		rand.Read(u.userID[:])
	}
	return u
}

type authData struct {
	clientID     [4]byte
	connectionID uint32
	mutex        sync.Mutex
}

func (a *authData) next() *authData {
	r := &authData{}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.connectionID > 0xff000000 || a.connectionID == 0 {
		rand.Read(a.clientID[:])
		a.connectionID = randv2.Uint32() & 0xffffff
	}
	a.connectionID++
	copy(r.clientID[:], a.clientID[:])
	r.connectionID = a.connectionID
	return r
}

func (a *authData) putAuthData(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint32(time.Now().Unix()))
	buf.Write(a.clientID[:])
	binary.Write(buf, binary.LittleEndian, a.connectionID)
}

func (a *authData) putEncryptedData(b *bytes.Buffer, userKey []byte, paddings [2]int, salt string) error {
	encrypt := make([]byte, 16)
	binary.LittleEndian.PutUint32(encrypt, uint32(time.Now().Unix()))
	copy(encrypt[4:], a.clientID[:])
	binary.LittleEndian.PutUint32(encrypt[8:], a.connectionID)
	binary.LittleEndian.PutUint16(encrypt[12:], uint16(paddings[0]))
	binary.LittleEndian.PutUint16(encrypt[14:], uint16(paddings[1]))

	cipherKey := tools.KDF(base64.StdEncoding.EncodeToString(userKey)+salt, 16)
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return err
	}
	var iv [aes.BlockSize]byte
	cbcCipher := cipher.NewCBCEncrypter(block, iv[:])

	cbcCipher.CryptBlocks(encrypt, encrypt)

	b.Write(encrypt)
	return nil
}
