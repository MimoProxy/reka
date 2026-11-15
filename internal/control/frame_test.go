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
	if err := WriteFrame(shortWriter{}, []byte("hello")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
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
		p, err := ReadFrame(bytes.NewReader(b))
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err = WriteFrame(&out, p); err != nil {
			t.Fatal(err)
		}
		again, err := ReadFrame(&out)
		if err != nil || !bytes.Equal(p, again) {
			t.Fatal("frame changed")
		}
	})
}
