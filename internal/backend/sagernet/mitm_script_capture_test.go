package sagernet

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/script"
)

func TestCaptureScript(t *testing.T) {
	url := "https://example.test/next"
	input := &script.Input{
		Request:  script.Request{Method: "POST", URL: "https://example.test/", Headers: []script.HeaderField{{Name: "host", Value: "example.test"}}, Body: []byte("hello")},
		Response: &script.Response{Status: 200, Body: []byte{0xff, 0x00, 0x01}},
	}
	result := &script.Result{Action: script.ActionModify, URL: &url, HeadersSet: true, Body: []byte("changed"), BodySet: true}
	c := captureScript(input, result)
	if c.Request.Method != "POST" || c.Request.Body.Text != "hello" || c.Request.Body.Size != 5 || len(c.Request.Headers) != 1 {
		t.Errorf("request = %+v", c.Request)
	}
	if c.Response.Status != 200 || c.Response.Body.Base64 != base64.StdEncoding.EncodeToString([]byte{0xff, 0x00, 0x01}) {
		t.Errorf("binary response = %+v", c.Response.Body)
	}
	if out := c.Output; out.Action != "modify" || out.URL != url || !out.HeadersSet || len(out.Headers) != 0 || out.Body.Text != "changed" {
		t.Errorf("output = %+v", out)
	}
	if captureScript(input, nil).Output != nil {
		t.Error("a run without a result has output")
	}
	if b := captureBody(nil, false); b != nil {
		t.Errorf("missing body = %+v", b)
	}
	if b := captureBody([]byte{}, true); b == nil || b.Size != 0 || b.Text != "" {
		t.Errorf("empty body = %+v", b)
	}
}

func TestCaptureBodyKeepsCharacters(t *testing.T) {
	// A three-byte character straddles the preview limit.
	text := strings.Repeat("a", scriptCaptureBodyBytes-1) + "中" + "tail"
	b := captureBody([]byte(text), true)
	if !b.Truncated || b.Size != len(text) || b.Base64 != "" || b.Text != strings.Repeat("a", scriptCaptureBodyBytes-1) {
		t.Errorf("text preview: truncated %v, size %d, %d text bytes, base64 %v", b.Truncated, b.Size, len(b.Text), b.Base64 != "")
	}
	binary := append([]byte{0xff}, make([]byte, scriptCaptureBodyBytes)...)
	if b := captureBody(binary, true); !b.Truncated || b.Text != "" || len(b.Base64) != base64.StdEncoding.EncodedLen(scriptCaptureBodyBytes) {
		t.Errorf("binary preview = %d base64 bytes", len(b.Base64))
	}
}
