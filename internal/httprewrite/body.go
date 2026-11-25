package httprewrite

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/adler32"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/itchyny/gojq"
)

// Reka limits each jq evaluation to one second.
const jqTimeout = time.Second

func (s *Set) rewriteBody(phase rewritePhase, url string, header *editedHeader, body []byte, ids *[]string) []byte {
	maxSize := s.opts.MaxBodySize
	if body == nil || int64(len(body)) > maxSize {
		return body
	}

	var original, updated []byte
	s.bodyIndex[phase].each(url, func(i int) bool {
		r := &s.body[phase][i]
		if !r.match.MatchString(url) {
			return true
		}
		if original == nil {
			decoded, err := DecodeBody(body, header.value, maxSize)
			if err != nil {
				return false
			}
			original = decoded
			updated = original
		}
		*ids = append(*ids, r.id)
		var next []byte
		if r.jq != nil {
			next = runJQ(r.jq, updated)
		} else if utf8.Valid(updated) {
			next = r.replaceBody(updated, maxSize)
		}
		if next != nil && int64(len(next)) <= maxSize {
			updated = next
		}
		return true
	})
	if bytes.Equal(original, updated) {
		return body
	}

	h := header.writable()
	deleteHeader(h, "Content-Encoding")
	deleteHeader(h, "Transfer-Encoding")
	replaceHeader(h, "Content-Length", []string{strconv.Itoa(len(updated))})
	return updated
}

func (r *bodyRule) replaceBody(body []byte, maxSize int64) []byte {
	for _, pair := range r.replace {
		re := pair.pattern.get()
		if !re.Match(body) {
			continue
		}
		if !replacementFits(re, body, pair.value, maxSize) {
			return nil
		}
		body = re.ReplaceAll(body, []byte(pair.value))
	}
	if body == nil {
		return []byte{}
	}
	return body
}

func replacementFits(re *regexp.Regexp, body []byte, template string, limit int64) bool {
	size := int64(len(body))
	available := limit - size
	// A match can insert literals and copies of its own bytes. There are at
	// most size+1 matches, and their total length is at most size.
	if template == "" || size <= (math.MaxInt64-1)/2 && int64(len(template)) <= available/(size*2+1) {
		return true
	}
	literals, refs, totalRefs := replacementSize(template, re.NumSubexp())
	var matches, removed int64
	re.ReplaceAllFunc(body, func(match []byte) []byte {
		matches++
		removed += int64(len(match))
		return nil
	})
	available += removed
	if matches > 0 && literals > available/matches {
		return false
	}
	available -= literals * matches
	if removed == 0 || totalRefs <= available/removed {
		return true
	}

	// A pass with only one capture per substitution cannot grow the input.
	// Measure each distinct capture only when the cheaper bounds couldn't
	// establish that the expanded template fits.
	unmatched := size - removed
	for group, count := range refs {
		if count == 0 {
			continue
		}
		length := removed
		if group != 0 {
			ref := "${" + strconv.Itoa(group) + "}"
			length = int64(len(re.ReplaceAll(body, []byte(ref)))) - unmatched
		}
		if length != 0 && count > available/length {
			return false
		}
		available -= length * count
	}
	return true
}

// replacementSize counts literal bytes and capture references in a template
// already processed by normalizeTemplate.
func replacementSize(template string, maxCapture int) (literals int64, refs [100]int64, totalRefs int64) {
	for {
		before, after, found := strings.Cut(template, "$")
		literals += int64(len(before))
		if !found {
			return
		}
		if after[0] == '$' {
			literals++
			template = after[1:]
			continue
		}
		end := strings.IndexByte(after, '}')
		group, _ := strconv.Atoi(after[1:end])
		if group <= maxCapture {
			refs[group]++
			totalRefs++
		}
		template = after[end+1:]
	}
}

func runJQ(code *gojq.Code, body []byte) []byte {
	if !utf8.Valid(body) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	// gojq handles json.Number directly, including integers larger than int64.
	dec.UseNumber()
	var input any
	if err := dec.Decode(&input); err != nil || len(bytes.Trim(body[dec.InputOffset():], " \t\r\n")) != 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), jqTimeout)
	defer cancel()
	value, ok := code.RunWithContext(ctx, input).Next()
	if !ok {
		return nil
	}
	if _, failed := value.(error); failed {
		return nil
	}

	var output bytes.Buffer
	enc := json.NewEncoder(&output)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil
	}
	data := output.Bytes()
	return data[:len(data)-1] // Encoder appends a newline.
}

// ErrDecodedBodyTooLarge reports a body that exceeded its size budget.
var ErrDecodedBodyTooLarge = errors.New("decoded HTTP body exceeds the size limit")

var errBodyEncoding = errors.New("unsupported or invalid HTTP body encoding")

// DecodeBody decodes identity, gzip, deflate, or br within the supplied size
// budget. Identity data shares the input slice.
func DecodeBody(body []byte, header http.Header, maxSize int64) ([]byte, error) {
	values, _ := headerValues(header, "Content-Encoding")
	if len(values) > 1 {
		return nil, errBodyEncoding
	}
	encoding := ""
	if len(values) == 1 {
		encoding = strings.ToLower(strings.TrimSpace(values[0]))
	}
	switch encoding {
	case "", "identity":
		if int64(len(body)) > maxSize {
			return nil, ErrDecodedBodyTooLarge
		}
		return body, nil
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, errBodyEncoding
		}
		return readBody(r, maxSize)
	case "deflate":
		return inflateBody(body, maxSize)
	case "br":
		// The decoder sizes its ring buffer to the output of a short final
		// stream, so small bodies do not allocate the full window.
		return readBody(io.NopCloser(brotli.NewReader(bytes.NewReader(body))), maxSize)
	default:
		return nil, errBodyEncoding
	}
}

func inflateBody(body []byte, maxSize int64) ([]byte, error) {
	// HTTP deflate uses a zlib wrapper. Also accept bare DEFLATE from senders
	// that omit the wrapper. This uses flate for the compressed stream.
	if len(body) >= 6 && body[0]&0x0f == 8 && body[0]>>4 <= 7 && binary.BigEndian.Uint16(body[:2])%31 == 0 {
		if body[1]&0x20 != 0 {
			return nil, errBodyEncoding // Preset dictionaries are unavailable.
		}
		checksum := binary.BigEndian.Uint32(body[len(body)-4:])
		stream := bytes.NewReader(body[2 : len(body)-4])
		data, err := readBody(flate.NewReader(stream), maxSize)
		if err != nil {
			return nil, err
		}
		if stream.Len() != 0 || adler32.Checksum(data) != checksum {
			return nil, errBodyEncoding
		}
		return data, nil
	}
	return readBody(flate.NewReader(bytes.NewReader(body)), maxSize)
}

func readBody(reader io.ReadCloser, maxSize int64) ([]byte, error) {
	defer reader.Close()
	var input io.Reader = reader
	if maxSize < math.MaxInt64 {
		input = io.LimitReader(reader, maxSize+1)
	}
	body, err := io.ReadAll(input)
	if int64(len(body)) > maxSize {
		return nil, ErrDecodedBodyTooLarge
	}
	if err != nil {
		return nil, errBodyEncoding
	}
	return body, nil
}
