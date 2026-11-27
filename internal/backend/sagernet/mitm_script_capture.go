package sagernet

import (
	"encoding/base64"
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/script"
)

// A capture keeps the start of each body so one run's input and output stay
// well inside the history's 64 KiB detail limit even as base64.
const (
	scriptCaptureBodyBytes   = 12 << 10
	scriptCaptureHeaders     = 64
	scriptCaptureHeaderBytes = 1024
)

func captureScript(input *script.Input, result *script.Result) *api.ScriptCapture {
	if input == nil {
		return nil
	}
	c := &api.ScriptCapture{Request: api.ScriptMessage{
		Method: input.Request.Method, URL: input.Request.URL,
		Headers: captureHeaders(input.Request.Headers), Body: captureBody(input.Request.Body, input.Request.Body != nil),
	}}
	if r := input.Response; r != nil {
		c.Response = captureResponse(r)
	}
	if result == nil {
		return c
	}
	out := &api.ScriptOutput{Action: captureAction(result.Action), Status: result.Status}
	if result.URL != nil {
		out.URL = *result.URL
	}
	if result.HeadersSet {
		out.HeadersSet, out.Headers = true, captureHeaders(result.Headers)
	}
	out.Body = captureBody(result.Body, result.BodySet)
	if result.Response != nil {
		out.Response = captureResponse(result.Response)
	}
	c.Output = out
	return c
}

func captureResponse(r *script.Response) *api.ScriptMessage {
	return &api.ScriptMessage{Status: r.Status, Headers: captureHeaders(r.Headers), Body: captureBody(r.Body, r.Body != nil)}
}

func captureAction(action script.Action) string {
	switch action {
	case script.ActionModify:
		return "modify"
	case script.ActionRespond:
		return "respond"
	case script.ActionAbort:
		return "abort"
	default:
		return "pass"
	}
}

func captureHeaders(fields []script.HeaderField) []api.ScriptHeader {
	if len(fields) == 0 {
		return nil
	}
	headers := make([]api.ScriptHeader, 0, min(len(fields), scriptCaptureHeaders))
	for _, field := range fields[:min(len(fields), scriptCaptureHeaders)] {
		headers = append(headers, api.ScriptHeader{
			Name: history.Text(field.Name, scriptCaptureHeaderBytes), Value: history.Text(field.Value, scriptCaptureHeaderBytes),
		})
	}
	return headers
}

func captureBody(body []byte, present bool) *api.ScriptBody {
	if !present {
		return nil
	}
	b := &api.ScriptBody{Size: len(body)}
	preview := body
	if len(preview) > scriptCaptureBodyBytes {
		preview, b.Truncated = preview[:scriptCaptureBodyBytes], true
		// A cut inside a character leaves up to three bytes of it at the end.
		text := preview
		for cut := 0; cut < utf8.UTFMax-1 && !utf8.Valid(text); cut++ {
			text = text[:len(text)-1]
		}
		if utf8.Valid(text) {
			preview = text
		}
	}
	if utf8.Valid(preview) {
		b.Text = string(preview)
	} else {
		b.Base64 = base64.StdEncoding.EncodeToString(preview)
	}
	return b
}
