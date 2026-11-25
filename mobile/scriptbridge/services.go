package scriptbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/script"
)

type callRequest struct {
	Op       string          `json:"op"`
	Key      string          `json:"key"`
	Value    string          `json:"value"`
	Title    string          `json:"title"`
	Subtitle string          `json:"subtitle"`
	Body     string          `json:"body"`
	Options  json.RawMessage `json:"options"`
	Level    string          `json:"level"`
	Message  string          `json:"message"`
}

type readResult struct {
	Value *string `json:"value"`
}

type callResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type pendingCallReply struct {
	key  [sha256.Size]byte
	data []byte
}

// Call runs a synchronous service operation for a live run.
func (b *Bridge) Call(run uint64, request []byte) ([]byte, error) {
	b.mu.Lock()
	r := b.liveRunLocked(run)
	b.mu.Unlock()
	if r == nil {
		return nil, errors.New("script run is unavailable")
	}
	return r.call(request)
}

// WriteCallResponse writes a service result or returns the negative required
// capacity. Serialize each request and its retries in the caller. Immediately
// retry with the same input to reuse the cached result without calling the
// service again. Errors return zero.
func (b *Bridge) WriteCallResponse(run uint64, input, output []byte) int32 {
	key := sha256.Sum256(input)
	b.mu.Lock()
	r := b.liveRunLocked(run)
	if r == nil {
		b.mu.Unlock()
		return 0
	}
	pending := r.callReply
	r.callReply = pendingCallReply{}
	b.mu.Unlock()

	response := pending.data
	if response == nil || key != pending.key {
		var err error
		response, err = r.call(input)
		if err != nil {
			return 0
		}
	}
	if len(response) > math.MaxInt32 {
		return 0
	}
	if len(response) > len(output) {
		b.mu.Lock()
		if b.liveRunLocked(run) != nil {
			r.callReply = pendingCallReply{key, response}
		}
		b.mu.Unlock()
		return -int32(len(response))
	}
	return int32(copy(output, response))
}

func (r *runState) call(input []byte) ([]byte, error) {
	var req callRequest
	if err := json.Unmarshal(input, &req); err != nil {
		return nil, fmt.Errorf("invalid script service request: %w", err)
	}
	services, limits := r.job.Services, r.job.Limits
	switch req.Op {
	case "storeRead":
		var result readResult
		if services.Store != nil {
			if value, ok, err := services.Store.Read(req.Key); ok && err == nil {
				result.Value = &value
			}
		}
		return json.Marshal(result)
	case "storeWrite", "storeDelete":
		return json.Marshal(req.updateStore(services.Store, limits.StoreValueMax))
	case "notify":
		if services.Notify != nil {
			services.Notify.Post(req.notification())
		}
	case "log":
		if services.Log != nil {
			services.Log(req.Level, truncateLog(req.Message, limits.LogLineMax))
		}
	default:
		return nil, errors.New("unknown script service operation")
	}
	return json.Marshal(callResult{OK: true})
}

func (req callRequest) updateStore(store script.Store, limit int) callResult {
	if store == nil {
		return callResult{Error: "persistent store is unavailable"}
	}
	var err error
	switch {
	case req.Op == "storeDelete":
		err = store.Delete(req.Key)
	case len(req.Value) > limit:
		return callResult{Error: "persistent store value exceeds size limit"}
	default:
		err = store.Write(req.Key, req.Value)
	}
	if err != nil {
		return callResult{Error: err.Error()}
	}
	return callResult{OK: true}
}

func (req callRequest) notification() script.Notification {
	n := script.Notification{Title: req.Title, Subtitle: req.Subtitle, Body: req.Body}
	if len(req.Options) > 0 && len(req.Options) <= script.NotificationOptionsMax {
		d := json.NewDecoder(bytes.NewReader(req.Options))
		d.UseNumber()
		if err := d.Decode(&n.Options); err != nil {
			n.Options = nil
		}
	}
	return n
}

func truncateLog(message string, limit int) string {
	if len(message) <= limit {
		return message
	}
	for limit > 0 && !utf8.RuneStart(message[limit]) {
		limit--
	}
	return message[:limit]
}

type httpRequest struct {
	Method           string      `json:"method"`
	URL              string      `json:"url"`
	Headers          headerPairs `json:"headers"`
	TimeoutMS        float64     `json:"timeoutMs"`
	Policy           string      `json:"policy"`
	PolicyDescriptor string      `json:"policyDescriptor"`
	Insecure         bool        `json:"insecure"`
	AutoRedirect     bool        `json:"autoRedirect"`
	AutoCookie       bool        `json:"autoCookie"`
	Binary           bool        `json:"binary"`
}

type httpResponse struct {
	Status  int         `json:"status"`
	Headers headerPairs `json:"headers"`
}

type httpError struct {
	Error string `json:"error"`
}

// HTTP starts an asynchronous HTTP client request. The caller can release
// request and body as soon as HTTP returns.
func (b *Bridge) HTTP(run, call uint64, request, body []byte) bool {
	w := &httpRequest{AutoRedirect: true, AutoCookie: true}
	if err := json.Unmarshal(request, &w); err != nil || w == nil {
		return false
	}
	b.mu.Lock()
	r := b.liveRunLocked(run)
	if r == nil || r.httpPending >= r.job.Limits.MaxHTTPInFlight {
		b.mu.Unlock()
		return false
	}
	r.httpPending++
	b.mu.Unlock()

	req := &script.HTTPRequest{
		Method: w.Method, URL: w.URL, Headers: w.Headers.decode(), Body: bytes.Clone(body),
		Timeout: httpTimeout(w.TimeoutMS), Policy: w.Policy, PolicyDescriptor: w.PolicyDescriptor,
		Insecure: w.Insecure, AutoRedirect: w.AutoRedirect, AutoCookie: w.AutoCookie, Binary: w.Binary,
	}
	go b.runHTTP(r.ctx, r.job.Services.HTTP, run, call, req)
	return true
}

func httpTimeout(ms float64) time.Duration {
	nanos := ms * float64(time.Millisecond)
	switch {
	case nanos >= float64(math.MaxInt64):
		return time.Duration(math.MaxInt64)
	case nanos >= 1:
		return time.Duration(nanos)
	default:
		return script.DefaultHTTPRequestTimeout
	}
}

func (b *Bridge) runHTTP(ctx context.Context, client script.HTTPClient, run, call uint64, req *script.HTTPRequest) {
	if ctx.Err() != nil {
		return
	}
	var resp *script.HTTPResponse
	var err error
	if client == nil {
		err = errors.New("unavailable")
	} else {
		resp, err = client.Do(ctx, req)
		if resp == nil && err == nil {
			err = errors.New("HTTP client returned no response")
		}
	}
	var data, body []byte
	if err == nil {
		data, _ = json.Marshal(httpResponse{Status: resp.Status, Headers: encodeHeaders(resp.Headers)})
		body = resp.Body
	} else {
		data, _ = json.Marshal(httpError{Error: err.Error()})
	}

	b.mu.Lock()
	r := b.liveRunLocked(run)
	if r != nil {
		r.httpPending--
	}
	b.mu.Unlock()
	// A result claims delivery only while its run is live. The host can
	// retire the run concurrently with a reply already being handed off.
	if r != nil {
		b.host.Reply(run, call, data, body)
	}
}
