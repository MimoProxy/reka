package control

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }
func TestFrameShortWrite(t *testing.T) {
	if e := WriteFrame(shortWriter{}, []byte("hello")); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal(e)
	}
}
func FuzzFrames(f *testing.F) {
	var b bytes.Buffer
	_ = WriteFrame(&b, []byte(`{"id":1,"method":"Hello"}`))
	f.Add(b.Bytes())
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			t.Skip()
		}
		p, e := ReadFrame(bytes.NewReader(b))
		if e != nil {
			return
		}
		var out bytes.Buffer
		if e = WriteFrame(&out, p); e != nil {
			t.Fatal(e)
		}
		again, e := ReadFrame(&out)
		if e != nil || !bytes.Equal(p, again) {
			t.Fatal("frame changed")
		}
	})
}
