package sagernet

import (
	"encoding/binary"
	"io"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// RFC 9113 defines 16 KiB as the initial and smallest legal maximum frame
// size. Sending frames this small is valid even if the peer accepts more.
const mitmH2MaxFrameSize = 16 * 1024

// mitmH2ClientConn caps the peer's frame size setting to bound net/http's
// request body write buffer. The embedded connection provides the
// ConnectionState method net/http uses to activate HTTP/2 after a custom
// TLS dial.
type mitmH2ClientConn struct {
	mitmTLSConn
	readMu sync.Mutex
	frames mitmH2ServerFrameReader
}

func (c *mitmH2ClientConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.frames.read(c.mitmTLSConn, p)
}

// Close mirrors net/http's HTTP/2 client, which closes the socket under a
// *tls.Conn if the TLS close alert blocks on an unresponsive peer. It only
// recognizes *tls.Conn, so the wrapper repeats that here.
func (c *mitmH2ClientConn) Close() error {
	force := time.AfterFunc(mitmH2ForceCloseDelay, func() { _ = c.NetConn().Close() })
	defer force.Stop()
	return c.mitmTLSConn.Close()
}

// Match the delay in net/http's HTTP/2 client closeConn.
const mitmH2ForceCloseDelay = 250 * time.Millisecond

type mitmH2ServerFrameReader struct {
	header           [9]byte
	pending          []byte
	payloadRemaining int
}

func (r *mitmH2ServerFrameReader) read(source io.Reader, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		if r.payloadRemaining > 0 {
			n, err := source.Read(p[:min(len(p), r.payloadRemaining)])
			r.payloadRemaining -= n
			return n, err
		}

		// The server's connection preface is a SETTINGS frame.
		if _, err := io.ReadFull(source, r.header[:]); err != nil {
			return 0, err
		}
		length := int(r.header[0])<<16 | int(r.header[1])<<8 | int(r.header[2])
		const settingSize = 6
		if http2.FrameType(r.header[3]) == http2.FrameSettings &&
			http2.Flags(r.header[4])&http2.FlagSettingsAck == 0 &&
			length > 0 && length <= mitmH2MaxFrameSize && length%settingSize == 0 {
			frame := make([]byte, len(r.header)+length)
			copy(frame, r.header[:])
			payload := frame[len(r.header):]
			if _, err := io.ReadFull(source, payload); err != nil {
				return 0, err
			}
			for i := 0; i < len(payload); i += settingSize {
				value := payload[i+2 : i+settingSize]
				if binary.BigEndian.Uint16(payload[i:]) == uint16(http2.SettingMaxFrameSize) &&
					binary.BigEndian.Uint32(value) > mitmH2MaxFrameSize {
					binary.BigEndian.PutUint32(value, mitmH2MaxFrameSize)
				}
			}
			r.pending = frame
		} else {
			r.pending = r.header[:]
			r.payloadRemaining = length
		}
	}
	n := copy(p, r.pending)
	if n == len(r.pending) {
		r.pending = nil
	} else {
		r.pending = r.pending[n:]
	}
	return n, nil
}
