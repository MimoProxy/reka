package gojaengine

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/script"
	"github.com/dop251/goja"
)

type httpResult struct {
	id       uint64
	response *script.HTTPResponse
	err      error
	binary   bool
}

func (s *session) installServices() {
	s.installHTTPClient()
	s.installStore()
	s.installNotification()
	s.installUtils()
	s.installConsole()
}

func (s *session) installHTTPClient() {
	client := s.vm.NewObject()
	for _, method := range []string{"get", "post", "put", "delete", "head", "options", "patch"} {
		s.set(client, method, func(call goja.FunctionCall) goja.Value {
			callback, ok := goja.AssertFunction(call.Argument(1))
			if !ok {
				panic(s.vm.NewTypeError("$httpClient requires a callback"))
			}
			if s.httpPending < s.job.Limits.MaxHTTPInFlight {
				req := s.httpRequest(strings.ToUpper(method), call.Argument(0))
				// Getters on the options can start other requests during conversion.
				if s.httpPending < s.job.Limits.MaxHTTPInFlight {
					s.startHTTP(req, callback)
					return goja.Undefined()
				}
			}
			s.call(callback, s.vm.ToValue("too many pending HTTP requests"), goja.Null(), goja.Null())
			return goja.Undefined()
		})
	}
	s.set(s.vm.GlobalObject(), "$httpClient", client)
}

func (s *session) httpRequest(method string, options goja.Value) *script.HTTPRequest {
	req := &script.HTTPRequest{
		Method:       method,
		Timeout:      script.DefaultHTTPRequestTimeout,
		AutoRedirect: true,
		AutoCookie:   true,
	}
	opts, ok := options.(*goja.Object)
	if !ok {
		if _, ok := options.(goja.String); !ok {
			panic(s.vm.NewTypeError("$httpClient options must be a URL string or an object"))
		}
		req.URL = options.String()
		return req
	}

	req.URL = optionalString(opts.Get("url"))
	req.Headers = s.readHeaders(opts.Get("headers"))
	req.Policy = optionalString(opts.Get("policy"))
	req.PolicyDescriptor = optionalString(opts.Get("policy-descriptor"))
	req.Insecure = optionalBool(opts.Get("insecure"), false)
	req.AutoRedirect = optionalBool(opts.Get("auto-redirect"), true)
	req.AutoCookie = optionalBool(opts.Get("auto-cookie"), true)
	req.Binary = optionalBool(opts.Get("binary-mode"), false)
	if v := opts.Get("timeout"); !absent(v) {
		nanos := v.ToFloat() * float64(time.Second)
		switch {
		case nanos >= float64(math.MaxInt64):
			req.Timeout = time.Duration(math.MaxInt64)
		case nanos >= 0:
			req.Timeout = time.Duration(nanos)
		}
	}
	if body := opts.Get("body"); !absent(body) {
		if data, ok := s.bytes(body); ok {
			// The script can keep modifying the original view while HTTP runs.
			req.Body = bytes.Clone(data)
		} else if _, ok := body.(*goja.Object); ok {
			if text, ok := s.jsonString(body); ok {
				req.Body = []byte(text)
				req.Headers = withJSONContentType(req.Headers)
			}
		} else {
			req.Body = []byte(body.String())
		}
	}
	return req
}

func withJSONContentType(headers []script.HeaderField) []script.HeaderField {
	for _, field := range headers {
		if strings.EqualFold(field.Name, "Content-Type") {
			return headers
		}
	}
	return append(headers, script.HeaderField{Name: "Content-Type", Value: "application/json"})
}

func (s *session) startHTTP(req *script.HTTPRequest, callback goja.Callable) {
	if s.httpCallbacks == nil {
		s.httpCallbacks = make(map[uint64]goja.Callable)
	}
	s.nextHTTPID++
	s.httpCallbacks[s.nextHTTPID] = callback
	s.httpPending++
	go runHTTPRequest(s.ctx, s.job.Services.HTTP, req, s.httpResults, s.nextHTTPID)
}

// The worker carries only Go data so a late response cannot access or retain the runtime.
func runHTTPRequest(ctx context.Context, client script.HTTPClient, req *script.HTTPRequest, results chan<- httpResult, id uint64) {
	result := httpResult{id: id, binary: req.Binary}
	if client == nil {
		result.err = errors.New("unavailable")
	} else {
		result.response, result.err = client.Do(ctx, req)
		if result.response == nil && result.err == nil {
			result.err = errors.New("HTTP client returned no response")
		}
	}
	select {
	case <-ctx.Done():
	case results <- result:
	}
}

func (s *session) deliverHTTP(result httpResult) {
	callback := s.httpCallbacks[result.id]
	delete(s.httpCallbacks, result.id)
	if result.err != nil {
		s.call(callback, s.vm.ToValue(result.err.Error()), goja.Null(), goja.Null())
		return
	}
	response := s.vm.NewObject()
	s.set(response, "status", result.response.Status)
	s.set(response, "statusCode", result.response.Status)
	s.set(response, "headers", s.headers(result.response.Headers, false))
	var data goja.Value
	if result.binary {
		data = s.uint8Array(bytes.Clone(result.response.Body))
	} else {
		data = s.vm.ToValue(string(result.response.Body))
	}
	s.call(callback, goja.Null(), response, data)
}

const (
	storePathPrefix = "script-path:"
	storeKeyPrefix  = "script-key:"
)

func (s *session) storeKey(v goja.Value) string {
	if absent(v) {
		return storePathPrefix + s.job.Script.Path
	}
	key := v.String()
	// Escape reserved prefixes so explicit keys cannot collide with path keys.
	if strings.HasPrefix(key, storePathPrefix) || strings.HasPrefix(key, storeKeyPrefix) {
		return storeKeyPrefix + key
	}
	return key
}

func (s *session) installStore() {
	store := s.job.Services.Store
	obj := s.vm.NewObject()
	s.set(obj, "read", func(call goja.FunctionCall) goja.Value {
		if store != nil {
			value, ok, err := store.Read(s.storeKey(call.Argument(0)))
			if ok && err == nil {
				return s.vm.ToValue(value)
			}
		}
		return goja.Null()
	})
	s.set(obj, "write", func(call goja.FunctionCall) goja.Value {
		if store == nil {
			return s.vm.ToValue(false)
		}
		data := call.Argument(0)
		key := s.storeKey(call.Argument(1))
		if goja.IsNull(data) {
			return s.vm.ToValue(store.Delete(key) == nil)
		}
		var value string
		if v, ok := data.(goja.String); ok {
			value = v.String()
		} else {
			text, ok := s.tryJSONString(data)
			if !ok {
				return s.vm.ToValue(false)
			}
			value = text
		}
		if len(value) > s.job.Limits.StoreValueMax {
			return s.vm.ToValue(false)
		}
		return s.vm.ToValue(store.Write(key, value) == nil)
	})
	s.set(s.vm.GlobalObject(), "$persistentStore", obj)
}

func (s *session) installNotification() {
	obj := s.vm.NewObject()
	s.set(obj, "post", func(call goja.FunctionCall) goja.Value {
		if notifier := s.job.Services.Notify; notifier != nil {
			n := script.Notification{
				Title:    optionalString(call.Argument(0)),
				Subtitle: optionalString(call.Argument(1)),
				Body:     optionalString(call.Argument(2)),
			}
			// Use JSON data so options cannot retain script objects or the runtime.
			if v, ok := call.Argument(3).(*goja.Object); ok {
				if text, ok := s.tryJSONString(v); ok && len(text) <= script.NotificationOptionsMax {
					decoder := json.NewDecoder(strings.NewReader(text))
					decoder.UseNumber()
					if err := decoder.Decode(&n.Options); err != nil {
						n.Options = nil
					}
				}
			}
			notifier.Post(n)
		}
		return goja.Undefined()
	})
	s.set(s.vm.GlobalObject(), "$notification", obj)
}

func (s *session) installUtils() {
	utils := s.vm.NewObject()
	geo := s.job.Services.GeoIP
	s.set(utils, "geoip", func(call goja.FunctionCall) goja.Value {
		if geo != nil {
			if country := geo.Country(call.Argument(0).String()); country != "" {
				return s.vm.ToValue(country)
			}
		}
		return goja.Null()
	})
	s.set(utils, "ipasn", func(call goja.FunctionCall) goja.Value {
		if geo != nil {
			if asn, ok := geo.ASN(call.Argument(0).String()); ok {
				return s.vm.ToValue(asn)
			}
		}
		return goja.Null()
	})
	s.set(utils, "ipaso", func(call goja.FunctionCall) goja.Value {
		if geo != nil {
			if org := geo.ASOrg(call.Argument(0).String()); org != "" {
				return s.vm.ToValue(org)
			}
		}
		return goja.Null()
	})
	s.set(utils, "ungzip", func(call goja.FunctionCall) goja.Value {
		data, ok := s.bytes(call.Argument(0))
		if !ok {
			return goja.Null()
		}
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return goja.Null()
		}
		defer reader.Close()
		limit := s.job.Limits.UngzipMax
		readLimit := limit
		if readLimit < math.MaxInt64 {
			readLimit++
		}
		out, err := io.ReadAll(io.LimitReader(contextReader{s.ctx, reader}, readLimit))
		if err != nil || int64(len(out)) > limit {
			return goja.Null()
		}
		return s.uint8Array(out)
	})
	s.set(utils, "gzip", func(call goja.FunctionCall) goja.Value {
		value := call.Argument(0)
		data, ok := s.bytes(value)
		if !ok {
			str, ok := value.(goja.String)
			if !ok {
				return goja.Null()
			}
			data = []byte(str.String())
		}
		var out bytes.Buffer
		writer := gzip.NewWriter(&out)
		_, writeErr := io.Copy(writer, contextReader{s.ctx, bytes.NewReader(data)})
		if closeErr := writer.Close(); writeErr != nil || closeErr != nil {
			return goja.Null()
		}
		return s.uint8Array(out.Bytes())
	})
	s.set(s.vm.GlobalObject(), "$utils", utils)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (s *session) installConsole() {
	console := s.vm.NewObject()
	log := s.job.Services.Log
	for _, level := range []string{"log", "info", "warn", "error", "debug"} {
		s.set(console, level, func(call goja.FunctionCall) goja.Value {
			// With logging disabled, do not access or stringify any arguments.
			if log == nil {
				return goja.Undefined()
			}
			log(level, s.logLine(call.Arguments))
			return goja.Undefined()
		})
	}
	s.set(s.vm.GlobalObject(), "console", console)
}

func (s *session) logLine(args []goja.Value) string {
	var line strings.Builder
	limit := s.job.Limits.LogLineMax
	for i, arg := range args {
		if line.Len() == limit {
			break
		}
		if i != 0 {
			line.WriteByte(' ')
		}
		var text string
		var ok bool
		if _, obj := arg.(*goja.Object); obj {
			text, ok = s.tryJSONString(arg)
		}
		if !ok {
			text = s.call(s.primitives.stringValue, arg).String()
		}
		if left := limit - line.Len(); len(text) > left {
			for left > 0 && !utf8.RuneStart(text[left]) {
				left--
			}
			line.WriteString(text[:left])
			break
		}
		line.WriteString(text)
	}
	return line.String()
}

func (s *session) tryJSONString(v goja.Value) (str string, ok bool) {
	// Uncatchable interruptions still propagate out of the runtime.
	err := s.vm.Try(func() { str, ok = s.jsonString(v) })
	return str, err == nil && ok
}

func optionalString(v goja.Value) string {
	if absent(v) {
		return ""
	}
	return v.String()
}

func optionalBool(v goja.Value, fallback bool) bool {
	if absent(v) {
		return fallback
	}
	return v.ToBoolean()
}
