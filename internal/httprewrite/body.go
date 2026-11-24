package httprewrite

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"hash/adler32"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
			decoded, ok := decodeBody(body, header, maxSize)
			if !ok {
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

func decodeBody(body []byte, header *editedHeader, maxSize int64) ([]byte, bool) {
	values, _ := headerValues(header.value, "Content-Encoding")
	if len(values) > 1 {
		return nil, false
	}
	encoding := ""
	if len(values) == 1 {
		encoding = strings.ToLower(strings.TrimSpace(values[0]))
	}
	switch encoding {
	case "", "identity":
		return body, true
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		return readBody(r, maxSize)
	case "deflate":
		return inflateBody(body, maxSize)
	default:
		return nil, false
	}
}

func inflateBody(body []byte, maxSize int64) ([]byte, bool) {
	// HTTP deflate uses a zlib wrapper. Also accept bare DEFLATE from senders
	// that omit the wrapper. This uses flate for the compressed stream.
	if len(body) >= 6 && body[0]&0x0f == 8 && body[0]>>4 <= 7 && binary.BigEndian.Uint16(body[:2])%31 == 0 {
		if body[1]&0x20 != 0 {
			return nil, false // Preset dictionaries are unavailable.
		}
		checksum := binary.BigEndian.Uint32(body[len(body)-4:])
		stream := bytes.NewReader(body[2 : len(body)-4])
		data, ok := readBody(flate.NewReader(stream), maxSize)
		if !ok || stream.Len() != 0 || adler32.Checksum(data) != checksum {
			return nil, false
		}
		return data, true
	}
	return readBody(flate.NewReader(bytes.NewReader(body)), maxSize)
}

func readBody(reader io.ReadCloser, maxSize int64) ([]byte, bool) {
	defer reader.Close()
	var input io.Reader = reader
	if maxSize < math.MaxInt64 {
		input = io.LimitReader(reader, maxSize+1)
	}
	body, err := io.ReadAll(input)
	return body, err == nil && int64(len(body)) <= maxSize
}
