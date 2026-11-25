package gojaengine

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"

	"github.com/dop251/goja"
	nodeurl "github.com/dop251/goja_nodejs/url"
)

func (s *session) installWebAPIs() {
	vm := s.vm
	module := vm.NewObject()
	exports := vm.NewObject()
	s.set(module, "exports", exports)
	nodeurl.Require(vm, module)
	s.global("URL", exports.Get("URL"))
	s.global("URLSearchParams", exports.Get("URLSearchParams"))

	encoder := vm.ToValue(func(call goja.ConstructorCall) *goja.Object {
		s.set(call.This, "encoding", "utf-8")
		return nil
	}).ToObject(vm)
	s.set(encoder.Get("prototype").ToObject(vm), "encode", func(call goja.FunctionCall) goja.Value {
		v := call.Argument(0)
		if goja.IsUndefined(v) {
			return s.uint8Array(nil)
		}
		return s.uint8Array([]byte(v.ToString().String()))
	})
	s.global("TextEncoder", encoder)

	decoder := vm.ToValue(func(call goja.ConstructorCall) *goja.Object {
		if label := call.Argument(0); !goja.IsUndefined(label) {
			encoding := strings.ToLower(strings.TrimSpace(label.ToString().String()))
			if encoding != "utf-8" && encoding != "utf8" {
				err, newErr := s.primitives.rangeError(nil, vm.ToValue("unsupported text encoding"))
				if newErr != nil {
					panic(newErr)
				}
				panic(err)
			}
		}
		s.set(call.This, "encoding", "utf-8")
		return nil
	}).ToObject(vm)
	s.set(decoder.Get("prototype").ToObject(vm), "decode", func(call goja.FunctionCall) goja.Value {
		v := call.Argument(0)
		if goja.IsUndefined(v) {
			return vm.ToValue("")
		}
		data, ok := s.bytes(v)
		if !ok {
			panic(vm.NewTypeError("TextDecoder.decode requires an ArrayBuffer or view"))
		}
		return vm.ToValue(strings.TrimPrefix(decodeUTF8(data), "\uFEFF"))
	})
	s.global("TextDecoder", decoder)

	s.global("atob", func(call goja.FunctionCall) goja.Value {
		encoded := strings.Map(func(r rune) rune {
			if strings.ContainsRune(" \t\n\r\f", r) {
				return -1
			}
			return r
		}, call.Argument(0).ToString().String())
		encoding := base64.RawStdEncoding
		if len(encoded)%4 == 0 {
			encoding = base64.StdEncoding
		}
		data, err := encoding.DecodeString(encoded)
		if err != nil {
			panic(vm.NewTypeError("invalid base64 data"))
		}
		chars := make([]uint16, len(data))
		for i, c := range data {
			chars[i] = uint16(c)
		}
		return goja.StringFromUTF16(chars)
	})
	s.global("btoa", func(call goja.FunctionCall) goja.Value {
		text := call.Argument(0).ToString().(goja.String)
		data := make([]byte, text.Length())
		for i := range data {
			value := text.CharAt(i)
			if value > 255 {
				panic(vm.NewTypeError("btoa requires Latin-1 characters"))
			}
			data[i] = byte(value)
		}
		return vm.ToValue(base64.StdEncoding.EncodeToString(data))
	})
}

func decodeUTF8(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	var text strings.Builder
	text.Grow(len(data))
	for len(data) != 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			size = invalidUTF8Prefix(data)
		}
		text.WriteRune(r)
		data = data[size:]
	}
	return text.String()
}

// An unfinished UTF-8 sequence produces one replacement character for the
// valid prefix. The first invalid continuation starts a new sequence.
func invalidUTF8Prefix(data []byte) int {
	lead := data[0]
	if len(data) < 2 || lead < 0xc2 || lead > 0xf4 {
		return 1
	}
	minSecond, maxSecond := byte(0x80), byte(0xbf)
	switch lead {
	case 0xe0:
		minSecond = 0xa0
	case 0xed:
		maxSecond = 0x9f
	case 0xf0:
		minSecond = 0x90
	case 0xf4:
		maxSecond = 0x8f
	}
	if data[1] < minSecond || data[1] > maxSecond {
		return 1
	}
	size := 2
	for size < len(data) && size < utf8.UTFMax && data[size]&0xc0 == 0x80 {
		size++
	}
	return size
}
