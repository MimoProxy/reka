package tools

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
)

func HmacMD5(key, data []byte) []byte {
	hmacMD5 := hmac.New(md5.New, key)
	hmacMD5.Write(data)
	return hmacMD5.Sum(nil)
}

func HmacSHA1(key, data []byte) []byte {
	hmacSHA1 := hmac.New(sha1.New, key)
	hmacSHA1.Write(data)
	return hmacSHA1.Sum(nil)
}

func MD5Sum(b []byte) []byte {
	h := md5.New()
	h.Write(b)
	return h.Sum(nil)
}

func SHA1Sum(b []byte) []byte {
	h := sha1.New()
	h.Write(b)
	return h.Sum(nil)
}

// KDF derives a legacy Shadowsocks stream key from its password.
func KDF(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
