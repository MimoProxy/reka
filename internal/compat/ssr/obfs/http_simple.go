package obfs

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	randv2 "math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing/common/buf"
)

func init() {
	register("http_simple", newHTTPSimple, 0)
}

type httpObfs struct {
	*Base
	post bool
}

func newHTTPSimple(b *Base) Obfs {
	return &httpObfs{Base: b}
}

type httpConn struct {
	net.Conn
	*httpObfs
	readMu, writeMu sync.Mutex
	hasSentHeader   bool
	hasRecvHeader   bool
	pendingErr      error
	pending         bytes.Buffer
}

func (h *httpObfs) StreamConn(c net.Conn) net.Conn {
	return &httpConn{Conn: c, httpObfs: h}
}

func (c *httpConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if !c.hasRecvHeader {
		raw := buf.Get(4096)
		defer buf.Put(raw)
		for {
			offset := max(0, c.pending.Len()-3)
			n, err := c.Conn.Read(raw)
			c.pending.Write(raw[:n])
			if index := bytes.Index(c.pending.Bytes()[offset:], []byte("\r\n\r\n")); index >= 0 {
				c.pending.Next(offset + index + 4)
				c.hasRecvHeader = true
				c.pendingErr = err
				if c.pending.Len() == 0 {
					c.pending = bytes.Buffer{}
				}
				break
			}
			if c.pending.Len() > 32*1024 {
				c.Conn.Close()
				return 0, errors.New("SSR HTTP response header too long")
			}
			if err == io.EOF {
				return 0, io.ErrUnexpectedEOF
			}
			if err != nil {
				return 0, err
			}
		}
	}
	if c.pending.Len() > 0 {
		n, _ := c.pending.Read(b)
		if c.pending.Len() == 0 {
			c.pending = bytes.Buffer{}
		}
		return n, nil
	}
	if c.pendingErr != nil {
		err := c.pendingErr
		c.pendingErr = nil
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *httpConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.hasSentHeader {
		return c.Conn.Write(b)
	}
	// 30: head length
	headLength := c.IVSize + 30

	bLength := len(b)
	headDataLength := bLength
	if bLength-headLength > 64 {
		headDataLength = headLength + randv2.IntN(65)
	}
	headData := b[:headDataLength]
	b = b[headDataLength:]

	var body string
	host := c.Host
	if len(c.Param) > 0 {
		pos := strings.Index(c.Param, "#")
		if pos != -1 {
			body = strings.ReplaceAll(c.Param[pos+1:], "\n", "\r\n")
			body = strings.ReplaceAll(body, "\\n", "\r\n")
			host = c.Param[:pos]
		} else {
			host = c.Param
		}
	}
	hosts := strings.Split(host, ",")
	host = hosts[randv2.IntN(len(hosts))]

	buf := new(bytes.Buffer)
	if c.post {
		buf.WriteString("POST /")
	} else {
		buf.WriteString("GET /")
	}
	packURLEncodedHeadData(buf, headData)
	buf.WriteString(" HTTP/1.1\r\nHost: " + host)
	if c.Port != 80 {
		buf.WriteString(":" + strconv.Itoa(c.Port))
	}
	buf.WriteString("\r\n")
	if len(body) > 0 {
		buf.WriteString(body + "\r\n\r\n")
	} else {
		buf.WriteString("User-Agent: ")
		buf.WriteString(userAgent[randv2.IntN(len(userAgent))])
		buf.WriteString("\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n")
		if c.post {
			packBoundary(buf)
		}
		buf.WriteString("DNT: 1\r\nConnection: keep-alive\r\n\r\n")
	}
	buf.Write(b)
	_, err := buf.WriteTo(c.Conn)
	if err != nil {
		return 0, err
	}
	c.hasSentHeader = true
	return bLength, nil
}

func packURLEncodedHeadData(buf *bytes.Buffer, data []byte) {
	dataLength := len(data)
	for i := 0; i < dataLength; i++ {
		buf.WriteRune('%')
		buf.WriteString(hex.EncodeToString(data[i : i+1]))
	}
}

func packBoundary(buf *bytes.Buffer) {
	buf.WriteString("Content-Type: multipart/form-data; boundary=")
	set := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for i := 0; i < 32; i++ {
		buf.WriteByte(set[randv2.IntN(62)])
	}
	buf.WriteString("\r\n")
}

var userAgent = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/533.2 (KHTML, like Gecko) Chrome/5.0.342.1 Safari/533.2",
}
