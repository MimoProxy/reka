package protocol

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"net"

	"github.com/MimoProxy/reka/internal/compat/ssr/tools"
)

func init() {
	register("auth_chain_a", newAuthChainA, 4)
}

type randDataLengthMethod func(int, []byte, *tools.XorShift128Plus) int

type authChainA struct {
	*Base
	*authData
	*userData
	iv             []byte
	salt           string
	hasSentHeader  bool
	lastClientHash []byte
	lastServerHash []byte
	encrypter      cipher.Stream
	decrypter      cipher.Stream
	randomClient   tools.XorShift128Plus
	randomServer   tools.XorShift128Plus
	randDataLength randDataLengthMethod
	packID         uint32
	recvID         uint32
}

func newAuthChainA(b *Base) Protocol {
	a := &authChainA{
		Base:     b,
		authData: &authData{},
		userData: newUserData(b, nil),
		salt:     "auth_chain_a",
	}
	return a
}

func (a *authChainA) StreamConn(c net.Conn, iv []byte) net.Conn {
	p := &authChainA{
		Base:     a.Base,
		authData: a.next(),
		userData: a.userData,
		salt:     a.salt,
		packID:   1,
		recvID:   1,
	}
	p.iv = iv
	p.randDataLength = p.getRandLength
	return &streamConn{Conn: c, codec: p}
}

func (a *authChainA) PacketConn(c net.PacketConn) net.PacketConn {
	p := &authChainA{
		Base:     a.Base,
		salt:     a.salt,
		userData: a.userData,
	}
	return &packetConn{PacketConn: c, codec: p}
}

func (a *authChainA) Decode(dst, src *bytes.Buffer) error {
	if len(a.lastServerHash) < 16 {
		return errAuthChainLengthError
	}
	for src.Len() >= 4 {
		macKey := make([]byte, len(a.userKey)+4)
		copy(macKey, a.userKey)
		binary.LittleEndian.PutUint32(macKey[len(a.userKey):], a.recvID)

		dataLength := int(binary.LittleEndian.Uint16(src.Bytes()[:2]) ^ binary.LittleEndian.Uint16(a.lastServerHash[14:16]))
		randDataLength := a.randDataLength(dataLength, a.lastServerHash, &a.randomServer)
		length := dataLength + randDataLength

		if length >= 4096 || randDataLength < 0 || (a.recvID == 1 && dataLength < 2) {
			src.Reset()
			return errAuthChainLengthError
		}

		if 4+length > src.Len() {
			break
		}

		serverHash := tools.HmacMD5(macKey, src.Bytes()[:length+2])
		if !hmac.Equal(serverHash[:2], src.Bytes()[length+2:length+4]) {
			src.Reset()
			return errAuthChainChksumError
		}
		a.lastServerHash = serverHash

		pos := 2
		if dataLength > 0 && randDataLength > 0 {
			pos += getRandStartPos(randDataLength, &a.randomServer)
		}

		wantedData := src.Bytes()[pos : pos+dataLength]
		a.decrypter.XORKeyStream(wantedData, wantedData)
		if a.recvID == 1 {
			dst.Write(wantedData[2:])
		} else {
			dst.Write(wantedData)
		}
		a.recvID++
		src.Next(length + 4)
	}
	return nil
}

func (a *authChainA) Encode(buf *bytes.Buffer, b []byte) error {
	if !a.hasSentHeader {
		dataLength := getDataLength(b)
		if err := a.packAuthData(buf, b[:dataLength]); err != nil {
			return err
		}
		b = b[dataLength:]
		a.hasSentHeader = true
	}
	for len(b) > 2800 {
		a.packData(buf, b[:2800])
		b = b[2800:]
	}
	if len(b) > 0 {
		a.packData(buf, b)
	}
	return nil
}

func (a *authChainA) DecodePacket(b []byte) ([]byte, error) {
	if len(b) < 9 {
		return nil, errAuthChainLengthError
	}
	if !hmac.Equal(tools.HmacMD5(a.userKey, b[:len(b)-1])[:1], b[len(b)-1:]) {
		return nil, errAuthChainChksumError
	}
	md5Data := tools.HmacMD5(a.Key, b[len(b)-8:len(b)-1])

	randDataLength := udpGetRandLength(md5Data)
	if randDataLength > len(b)-8 {
		return nil, errAuthChainLengthError
	}

	key := tools.KDF(base64.StdEncoding.EncodeToString(a.userKey)+base64.StdEncoding.EncodeToString(md5Data), 16)
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	wantedData := b[:len(b)-8-randDataLength]
	rc4Cipher.XORKeyStream(wantedData, wantedData)
	return wantedData, nil
}

func (a *authChainA) EncodePacket(buf *bytes.Buffer, b []byte) error {
	authData := make([]byte, 3)
	rand.Read(authData)

	md5Data := tools.HmacMD5(a.Key, authData)

	randDataLength := udpGetRandLength(md5Data)

	key := tools.KDF(base64.StdEncoding.EncodeToString(a.userKey)+base64.StdEncoding.EncodeToString(md5Data), 16)
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return err
	}
	buf.Write(b)
	rc4Cipher.XORKeyStream(buf.Bytes(), buf.Bytes())
	tools.AppendRandBytes(buf, randDataLength)
	buf.Write(authData)
	binary.Write(buf, binary.LittleEndian, binary.LittleEndian.Uint32(a.userID[:])^binary.LittleEndian.Uint32(md5Data[:4]))
	buf.Write(tools.HmacMD5(a.userKey, buf.Bytes())[:1])
	return nil
}

func (a *authChainA) packAuthData(poolBuf *bytes.Buffer, data []byte) error {
	/*
		dataLength := len(data)
		12:	checkHead(4) and hmac of checkHead(8)
		4:	uint32 LittleEndian uid (uid = userID ^ last client hash)
		16:	encrypted data of authdata(12), uint16 LittleEndian overhead(2) and uint16 LittleEndian number zero(2)
		4:	last server hash(4)
		packedAuthDataLength := 12 + 4 + 16 + 4 + dataLength
	*/

	macKey := make([]byte, len(a.iv)+len(a.Key))
	copy(macKey, a.iv)
	copy(macKey[len(a.iv):], a.Key)

	// check head
	tools.AppendRandBytes(poolBuf, 4)
	a.lastClientHash = tools.HmacMD5(macKey, poolBuf.Bytes())
	a.initRC4Cipher()
	poolBuf.Write(a.lastClientHash[:8])
	// uid
	binary.Write(poolBuf, binary.LittleEndian, binary.LittleEndian.Uint32(a.userID[:])^binary.LittleEndian.Uint32(a.lastClientHash[8:12]))
	// encrypted data
	err := a.putEncryptedData(poolBuf, a.userKey, [2]int{a.Overhead, 0}, a.salt)
	if err != nil {
		return err
	}
	// last server hash
	a.lastServerHash = tools.HmacMD5(a.userKey, poolBuf.Bytes()[12:])
	poolBuf.Write(a.lastServerHash[:4])
	// packed data
	a.packData(poolBuf, data)
	return nil
}

func (a *authChainA) packData(poolBuf *bytes.Buffer, data []byte) {
	encrypted := make([]byte, len(data))
	a.encrypter.XORKeyStream(encrypted, data)

	macKey := make([]byte, len(a.userKey)+4)
	copy(macKey, a.userKey)
	binary.LittleEndian.PutUint32(macKey[len(a.userKey):], a.packID)
	a.packID++

	length := uint16(len(data)) ^ binary.LittleEndian.Uint16(a.lastClientHash[14:16])

	originalLength := poolBuf.Len()
	binary.Write(poolBuf, binary.LittleEndian, length)
	a.putMixedRandDataAndData(poolBuf, encrypted)
	a.lastClientHash = tools.HmacMD5(macKey, poolBuf.Bytes()[originalLength:])
	poolBuf.Write(a.lastClientHash[:2])
}

func (a *authChainA) putMixedRandDataAndData(poolBuf *bytes.Buffer, data []byte) {
	randDataLength := a.randDataLength(len(data), a.lastClientHash, &a.randomClient)
	if len(data) == 0 {
		tools.AppendRandBytes(poolBuf, randDataLength)
		return
	}
	if randDataLength > 0 {
		startPos := getRandStartPos(randDataLength, &a.randomClient)
		tools.AppendRandBytes(poolBuf, startPos)
		poolBuf.Write(data)
		tools.AppendRandBytes(poolBuf, randDataLength-startPos)
		return
	}
	poolBuf.Write(data)
}

func getRandStartPos(length int, random *tools.XorShift128Plus) int {
	if length == 0 {
		return 0
	}
	return int(int64(random.Next()%8589934609) % int64(length))
}

func (a *authChainA) getRandLength(length int, lastHash []byte, random *tools.XorShift128Plus) int {
	if length > 1440 {
		return 0
	}
	random.InitFromBinAndLength(lastHash, length)
	if length > 1300 {
		return int(random.Next() % 31)
	}
	if length > 900 {
		return int(random.Next() % 127)
	}
	if length > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

func (a *authChainA) initRC4Cipher() {
	key := tools.KDF(base64.StdEncoding.EncodeToString(a.userKey)+base64.StdEncoding.EncodeToString(a.lastClientHash), 16)
	a.encrypter, _ = rc4.NewCipher(key)
	a.decrypter, _ = rc4.NewCipher(key)
}

func udpGetRandLength(lastHash []byte) int {
	var random tools.XorShift128Plus
	random.InitFromBin(lastHash)
	return int(random.Next() % 127)
}
