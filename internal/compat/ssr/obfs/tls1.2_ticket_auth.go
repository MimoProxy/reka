package obfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"io"
	randv2 "math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/compat/ssr/tools"
	"github.com/sagernet/sing/common/buf"
)

func init() {
	register("tls1.2_ticket_auth", newTLS12Ticket, 5)
	register("tls1.2_ticket_fastauth", newTLS12Ticket, 5)
}

type tls12Ticket struct {
	*Base
	*authData
}

func newTLS12Ticket(b *Base) Obfs {
	r := &tls12Ticket{Base: b, authData: &authData{}}
	rand.Read(r.clientID[:])
	return r
}

type tls12TicketConn struct {
	net.Conn
	closed atomic.Bool
	*tls12Ticket
	pendingErr                        error
	readMu, writeMu                   sync.Mutex
	sentHello, established            bool // writeMu
	receivedHello                     bool // readMu
	handshakeOffset, handshakeRecords int
	sawChangeCipherSpec               bool
	decoded                           bytes.Buffer
	underDecoded                      bytes.Buffer
	sendBuf                           bytes.Buffer
}

func (t *tls12Ticket) StreamConn(c net.Conn) net.Conn {
	return &tls12TicketConn{Conn: c, tls12Ticket: t}
}

func (c *tls12TicketConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *tls12TicketConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if c.decoded.Len() > 0 {
		return c.decoded.Read(b)
	}
	if c.pendingErr != nil {
		err := c.pendingErr
		c.pendingErr = nil
		return 0, err
	}
	raw := buf.Get(32 * 1024)
	defer buf.Put(raw)
	for {
		n, err := c.Conn.Read(raw)
		if n > 0 {
			c.underDecoded.Write(raw[:n])
			if decodeErr := c.decode(); decodeErr != nil {
				c.Close()
				if c.decoded.Len() > 0 {
					c.pendingErr = decodeErr
					return c.decoded.Read(b)
				}
				return 0, decodeErr
			}
			if c.decoded.Len() > 0 {
				if err == io.EOF && c.underDecoded.Len() > 0 {
					err = io.ErrUnexpectedEOF
				}
				c.pendingErr = err
				return c.decoded.Read(b)
			}
		}
		if err == io.EOF && c.underDecoded.Len() > 0 {
			return 0, io.ErrUnexpectedEOF
		}
		if err != nil {
			return 0, err
		}
	}
}

// The server authenticates the complete handshake flight, which may span reads
// or share a read with application data. Check the MAC at TLS record boundaries.
func (c *tls12TicketConn) decode() error {
	if !c.receivedHello {
		flight := c.underDecoded.Bytes()
		for len(flight)-c.handshakeOffset >= 5 {
			header := flight[c.handshakeOffset:]
			if header[1] != 3 || header[2] != 3 || (header[0] != 0x16 && header[0] != 0x14) {
				return errTLS12TicketAuthIncorrectMagicNumber
			}
			end := c.handshakeOffset + 5 + int(binary.BigEndian.Uint16(header[3:5]))
			if end > 65535 || c.handshakeRecords >= 16 {
				return errTLS12TicketAuthHMACError
			}
			if len(flight) < end {
				return nil
			}
			c.handshakeOffset = end
			c.handshakeRecords++
			if end >= 76 {
				if !hmac.Equal(flight[33:43], c.hmacSHA1(flight[11:33])) {
					return errTLS12TicketAuthHMACError
				}
				if hmac.Equal(flight[end-10:end], c.hmacSHA1(flight[:end-10])) {
					if err := c.finishHandshake(); err != nil {
						return err
					}
					c.receivedHello = true
					c.underDecoded.Next(end)
					break
				}
			}
			if c.sawChangeCipherSpec {
				return errTLS12TicketAuthHMACError
			}
			c.sawChangeCipherSpec = header[0] == 0x14
		}
		if !c.receivedHello {
			return nil
		}
	}
	for c.underDecoded.Len() >= 5 {
		record := c.underDecoded.Bytes()
		if !bytes.Equal(record[:3], []byte{0x17, 3, 3}) {
			return errTLS12TicketAuthIncorrectMagicNumber
		}
		size := int(binary.BigEndian.Uint16(record[3:5]))
		if len(record) < size+5 {
			break
		}
		c.underDecoded.Next(5)
		c.decoded.Write(c.underDecoded.Next(size))
	}
	return nil
}

func (c *tls12TicketConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	if c.established {
		var encoded bytes.Buffer
		packRecords(&encoded, b)
		if _, err := encoded.WriteTo(c.Conn); err != nil {
			c.Close()
			return 0, err
		}
		return len(b), nil
	}

	if len(b) > maxPending-c.sendBuf.Len() {
		c.Close()
		return 0, errPendingFull
	}
	packRecords(&c.sendBuf, b)
	if c.sendBuf.Len() > maxPending {
		c.Close()
		return 0, errPendingFull
	}
	if !c.sentHello {
		data := new(bytes.Buffer)
		data.Write([]byte{3, 3})
		c.packAuthData(data)
		data.WriteByte(0x20)
		data.Write(c.clientID[:])
		data.Write([]byte{0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a})
		data.Write([]byte{0x1, 0x0})

		ext := new(bytes.Buffer)
		host := c.getHost()
		ext.Write([]byte{0xff, 0x01, 0x00, 0x01, 0x00})
		packSNIData(ext, host)
		ext.Write([]byte{0, 0x17, 0, 0})
		c.packTicketBuf(ext)
		ext.Write([]byte{0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03})
		ext.Write([]byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00})
		ext.Write([]byte{0x00, 0x12, 0x00, 0x00})
		ext.Write([]byte{0x75, 0x50, 0x00, 0x00})
		ext.Write([]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00})
		ext.Write([]byte{0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18})

		binary.Write(data, binary.BigEndian, uint16(ext.Len()))
		data.ReadFrom(ext)

		ret := new(bytes.Buffer)
		ret.Write([]byte{0x16, 3, 1})
		binary.Write(ret, binary.BigEndian, uint16(data.Len()+4))
		ret.Write([]byte{1, 0})
		binary.Write(ret, binary.BigEndian, uint16(data.Len()))
		ret.ReadFrom(data)

		if _, err := ret.WriteTo(c.Conn); err != nil {
			c.Close()
			return 0, err
		}
		c.sentHello = true
	}
	return len(b), nil
}

func (c *tls12TicketConn) finishHandshake() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var encoded bytes.Buffer
	encoded.Write([]byte{0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20})
	tools.AppendRandBytes(&encoded, 22)
	encoded.Write(c.hmacSHA1(encoded.Bytes()))
	encoded.ReadFrom(&c.sendBuf)
	if _, err := encoded.WriteTo(c.Conn); err != nil {
		c.Close()
		return err
	}
	c.established = true
	return nil
}

func packRecords(buf *bytes.Buffer, data []byte) {
	for len(data) > 2048 {
		size := min(randv2.IntN(4096)+100, len(data))
		packData(buf, data[:size])
		data = data[size:]
	}
	if len(data) > 0 {
		packData(buf, data)
	}
}

func packData(buf *bytes.Buffer, data []byte) {
	buf.Write([]byte{0x17, 3, 3})
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)
}

func (t *tls12Ticket) packAuthData(buf *bytes.Buffer) {
	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	tools.AppendRandBytes(buf, 18)
	buf.Write(t.hmacSHA1(buf.Bytes()[buf.Len()-22:])[:10])
}

func packSNIData(buf *bytes.Buffer, u string) {
	len := uint16(len(u))
	buf.Write([]byte{0, 0})
	binary.Write(buf, binary.BigEndian, len+5)
	binary.Write(buf, binary.BigEndian, len+3)
	buf.WriteByte(0)
	binary.Write(buf, binary.BigEndian, len)
	buf.WriteString(u)
}

func (c *tls12TicketConn) packTicketBuf(buf *bytes.Buffer) {
	length := 16 * (randv2.IntN(17) + 8)
	buf.Write([]byte{0, 0x23})
	binary.Write(buf, binary.BigEndian, uint16(length))
	tools.AppendRandBytes(buf, length)
}

func (t *tls12Ticket) hmacSHA1(data []byte) []byte {
	key := make([]byte, len(t.Key)+32)
	copy(key, t.Key)
	copy(key[len(t.Key):], t.clientID[:])

	sha1Data := tools.HmacSHA1(key, data)
	return sha1Data[:10]
}

func (t *tls12Ticket) getHost() string {
	host := t.Param
	if len(host) == 0 {
		host = t.Host
	}
	if len(host) > 0 && host[len(host)-1] >= '0' && host[len(host)-1] <= '9' {
		host = ""
	}
	hosts := strings.Split(host, ",")
	host = hosts[randv2.IntN(len(hosts))]
	return host
}
