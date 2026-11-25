package sagernet

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"testing"
	"testing/iotest"

	"golang.org/x/net/http2"
)

func TestMITMH2ClientConnCapsSettings(t *testing.T) {
	const (
		frameSizeLimit = 16384
		largeFrameSize = 1 << 20
	)
	var input, expected bytes.Buffer
	inputFrames := http2.NewFramer(&input, nil)
	expectedFrames := http2.NewFramer(&expected, nil)
	mustWrite := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	writeSettings := func(value, want uint32, other ...http2.Setting) {
		t.Helper()
		mustWrite(inputFrames.WriteSettings(append(other, http2.Setting{ID: http2.SettingMaxFrameSize, Val: value})...))
		mustWrite(expectedFrames.WriteSettings(append(other, http2.Setting{ID: http2.SettingMaxFrameSize, Val: want})...))
	}
	writeUnchanged := func(frameType http2.FrameType, flags http2.Flags, streamID uint32, payload []byte) {
		t.Helper()
		mustWrite(inputFrames.WriteRawFrame(frameType, flags, streamID, payload))
		mustWrite(expectedFrames.WriteRawFrame(frameType, flags, streamID, payload))
	}

	writeSettings(largeFrameSize, frameSizeLimit,
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: largeFrameSize},
		http2.Setting{ID: 0xAB, Val: largeFrameSize})
	writeUnchanged(http2.FrameData, http2.FlagDataEndStream, 1, input.Bytes())
	writeUnchanged(http2.FrameHeaders, http2.FlagHeadersEndHeaders, 3, []byte{0x88})
	writeUnchanged(http2.FrameSettings, http2.FlagSettingsAck, 0, nil)
	writeSettings(largeFrameSize*2, frameSizeLimit)
	writeSettings(frameSizeLimit, frameSizeLimit)
	writeSettings(frameSizeLimit-1, frameSizeLimit-1)

	// Leave invalid SETTINGS frames intact for net/http to handle.
	setting := binary.BigEndian.AppendUint16(nil, uint16(http2.SettingMaxFrameSize))
	setting = binary.BigEndian.AppendUint32(setting, largeFrameSize)
	writeUnchanged(http2.FrameSettings, http2.FlagSettingsAck, 0, setting)
	writeUnchanged(http2.FrameSettings, 0, 0, append(setting, 0))
	oversizedPayload := make([]byte, (frameSizeLimit/len(setting)+1)*len(setting))
	copy(oversizedPayload, setting)
	writeUnchanged(http2.FrameSettings, 0, 0, oversizedPayload)
	writeSettings(largeFrameSize, frameSizeLimit)

	readAndCompare := func(t *testing.T, source io.Reader, bufferSize int) {
		t.Helper()
		var reader mitmH2ServerFrameReader
		result := make([]byte, 0, input.Len())
		buffer := make([]byte, bufferSize)
		for {
			n, err := reader.read(source, buffer)
			result = append(result, buffer[:n]...)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				t.Fatal("read made no progress")
			}
		}
		if len(result) != expected.Len() {
			t.Fatalf("read %d bytes, want %d", len(result), expected.Len())
		}
		for i, want := range expected.Bytes() {
			if got := result[i]; got != want {
				t.Fatalf("byte %d = %02x, want %02x", i, got, want)
			}
		}
	}
	t.Run("one byte", func(t *testing.T) {
		readAndCompare(t, iotest.OneByteReader(bytes.NewReader(input.Bytes())), 1)
	})
	t.Run("random fragments", func(t *testing.T) {
		reader := &mitmH2FragmentReader{
			Reader: bytes.NewReader(input.Bytes()),
			random: rand.New(rand.NewPCG(42, 93)),
		}
		readAndCompare(t, reader, 13)
	})
}

type mitmH2FragmentReader struct {
	io.Reader
	random *rand.Rand
}

func (r *mitmH2FragmentReader) Read(p []byte) (int, error) {
	return r.Reader.Read(p[:min(len(p), r.random.IntN(17)+1)])
}
