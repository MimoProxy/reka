package sagernet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/script"
	"golang.org/x/net/http/httpguts"
)

// MITMScript is one matched script from the generation pinned by the route.
// MaxSize has already been capped by the caller's hard body limit.
type MITMScript struct {
	ID           string
	RequiresBody bool
	MaxSize      int
	// Run reports the host's execution duration. It is nil on unsupported platforms.
	Run func(context.Context, *script.Input) (script.Result, error)
}

func (m *MITMScript) bodyLimit() int {
	if m == nil || m.Run == nil || !m.RequiresBody {
		return 0
	}
	return m.MaxSize
}

func (s *mitmHTTPHandler) matchScript(kind script.Kind, rawURL string) *MITMScript {
	if s.route.MatchScript == nil {
		return nil
	}
	return s.route.MatchScript(kind, rawURL)
}

type mitmScriptInput struct {
	id       uint64
	request  *http.Request
	response *httprewrite.Response
	// responseH2 reports that the upstream response arrived over HTTP/2.
	responseH2 bool
	// teTrailers reports that the client sent "TE: trailers". It is a hop
	// header, so request carries it only once it is restored for the origin.
	teTrailers bool
}

// runScript returns whether the hit exceeded the body limit. The caller
// combines that result with any rewrite passthrough for the same direction.
func (s *mitmHTTPHandler) runScript(ctx context.Context, match *MITMScript, input mitmScriptInput, buffer mitmBufferedBody, stats *mitmRequestStats, apply func(script.Result) error) bool {
	if match == nil {
		return false
	}
	phase := "request"
	if input.response != nil {
		phase = "response"
	}
	run := api.MITMScriptRun{ID: match.ID, Phase: phase}
	if match.Run == nil {
		run.Result = "unsupported"
		s.recordScript(stats, run, false)
		return false
	}
	start := time.Now()
	job, err := input.scriptInput(match, buffer)
	var result script.Result
	var executed bool
	if err == nil {
		result, err = match.Run(ctx, job)
		// Coarse clocks, as on Windows, can report a zero duration for a run
		// that reached the engine, so classify by outcome as well.
		executed = !errors.Is(err, script.ErrLowMemory) &&
			(err == nil || result.Duration > 0 || mitmScriptReachedEngine(err))
		if err == nil {
			err = apply(result)
		}
	}
	run.DurationMS = time.Since(start).Milliseconds()
	run.Result, run.Error = mitmScriptOutcome(result.Action, err)
	s.recordScript(stats, run, executed)
	return run.Result == "oversize"
}

func (s *mitmHTTPHandler) recordScript(stats *mitmRequestStats, run api.MITMScriptRun, executed bool) {
	stats.scripts = append(stats.scripts, run)
	if s.route.OnScript != nil {
		s.route.OnScript(run, executed)
	}
}

func (s *mitmHTTPHandler) recordScriptInputError(stats *mitmRequestStats, match *MITMScript, phase string) {
	if match == nil {
		return
	}
	run := api.MITMScriptRun{ID: match.ID, Phase: phase, Result: "unsupported"}
	if match.Run != nil {
		run.Result, run.Error = "failed", "could not read HTTP body"
	}
	s.recordScript(stats, run, false)
}

func (v mitmScriptInput) scriptInput(match *MITMScript, buffer mitmBufferedBody) (*script.Input, error) {
	var body []byte
	if match.RequiresBody {
		if buffer.exceeds(match.MaxSize) {
			return nil, script.ErrBodyTooLarge
		}
		if buffer.data != nil {
			header := v.request.Header
			if v.response != nil {
				header = v.response.Header
			}
			var err error
			body, err = httprewrite.DecodeBody(buffer.data, header, int64(match.MaxSize))
			if err != nil {
				return nil, err
			}
		}
	}
	req := v.request
	requestH2 := req.ProtoMajor == 2
	headers := mitmScriptHeaders(req.Header, requestH2)
	if v.teTrailers && len(req.Header.Values("TE")) == 0 {
		headers = append(headers, mitmScriptHeader("Te", "trailers", requestH2))
	}
	input := &script.Input{Request: script.Request{
		ID: strconv.FormatUint(v.id, 10), Method: req.Method, URL: req.URL.String(),
		Headers: append(headers, mitmScriptHeader("Host", req.Host, requestH2)),
	}}
	if v.response == nil {
		input.Request.Body = body
	} else {
		// The app reads the response over its own connection, so an HTTP/2
		// client sees lowercase names even when the origin answered over
		// HTTP/1.1, which mitmUpstream prefers. Surge reaches such origins
		// over HTTP/2, and scripts written for it read names such as
		// headers["bili-status-code"] in lowercase.
		h2 := v.responseH2 || requestH2
		input.Response = &script.Response{Status: v.response.StatusCode, Headers: mitmScriptHeaders(v.response.Header, h2), Body: body}
	}
	return input, nil
}

func mitmScriptOutcome(action script.Action, err error) (result, message string) {
	if err == nil {
		switch action {
		case script.ActionModify:
			return "modified", ""
		case script.ActionRespond:
			return "responded", ""
		case script.ActionAbort:
			return "aborted", ""
		default:
			return "passed", ""
		}
	}
	switch {
	case errors.Is(err, script.ErrTimeout):
		return "timeout", ""
	case errors.Is(err, script.ErrBodyTooLarge), errors.Is(err, httprewrite.ErrDecodedBodyTooLarge):
		return "oversize", ""
	case errors.Is(err, script.ErrCircuitOpen):
		return "circuit-open", ""
	case errors.Is(err, script.ErrBusy):
		return "busy", ""
	case errors.Is(err, script.ErrLowMemory), errors.Is(err, script.ErrMemoryExceeded):
		return "low-memory", ""
	}
	var scriptErr *script.ScriptError
	if errors.As(err, &scriptErr) {
		return "failed", script.NewScriptError("", scriptErr.Message).Message
	}
	return "failed", script.NewScriptError("", err.Error()).Message
}

func mitmScriptReachedEngine(err error) bool {
	var scriptErr *script.ScriptError
	return errors.Is(err, script.ErrTimeout) || errors.Is(err, script.ErrNoDone) ||
		errors.Is(err, script.ErrMemoryExceeded) || errors.As(err, &scriptErr)
}

// mitmScriptHeaders spells HTTP/2 field names in lowercase, as they are on
// the wire and as Surge passes them to scripts. Scripts written for Surge
// read names such as headers["user-agent"] directly. HTTP/1 names keep the
// canonical form net/http stores.
func mitmScriptHeaders(header http.Header, h2 bool) []script.HeaderField {
	fields := make([]script.HeaderField, 0, len(header))
	for _, name := range slices.Sorted(maps.Keys(header)) {
		for _, value := range header[name] {
			fields = append(fields, mitmScriptHeader(name, value, h2))
		}
	}
	return fields
}

func mitmScriptHeader(name, value string, h2 bool) script.HeaderField {
	if h2 {
		name = strings.ToLower(name)
	}
	return script.HeaderField{Name: name, Value: value}
}

func readMITMScriptHeaders(fields []script.HeaderField) (http.Header, error) {
	header := make(http.Header, len(fields))
	for _, field := range fields {
		if !httpguts.ValidHeaderFieldName(field.Name) || !httpguts.ValidHeaderFieldValue(field.Value) {
			return nil, errors.New("invalid script HTTP header")
		}
		header.Add(field.Name, field.Value)
	}
	return header, nil
}

func applyMITMRequestScript(request *http.Request, result script.Result, allowHTTP, upgrade bool) (destination Destination, reroute bool, err error) {
	target, host, header := request.URL, request.Host, request.Header
	if result.URL != nil {
		target, destination, err = mitmUpstreamTarget(*result.URL, allowHTTP)
		if err != nil {
			return Destination{}, false, errors.New("invalid script HTTP request URL")
		}
		reroute = !sameMITMOrigin(target, request.URL)
		if host == request.URL.Host {
			host = target.Host
		}
	}
	if result.HeadersSet {
		header, err = readMITMScriptHeaders(result.Headers)
		if err != nil {
			return Destination{}, false, err
		}
		host = target.Host
		if replacement := header.Get("Host"); replacement != "" && replacement != request.URL.Host {
			host = replacement
		}
		if !httpguts.ValidHostHeader(host) {
			return Destination{}, false, errors.New("invalid script HTTP request authority")
		}
		header.Del("Host")
		stripMITMRequestHopHeaders(header, upgrade)
		if !result.BodySet {
			preserveMITMBodyHeaders(header, request.Header, request.ContentLength)
		}
	}
	request.URL, request.Host, request.Header = target, host, header
	if result.BodySet {
		setMITMRequestBody(request, result.Body)
		replaceMITMBodyHeaders(header, len(result.Body))
	}
	return destination, reroute, nil
}

func applyMITMResponseScript(response httprewrite.Response, contentLength int64, result script.Result) (httprewrite.Response, error) {
	if result.Status != 0 && !validMITMScriptStatus(result.Status) {
		return response, errors.New("invalid script HTTP response status")
	}
	if result.HeadersSet {
		header, err := readMITMScriptHeaders(result.Headers)
		if err != nil {
			return response, err
		}
		stripHTTPHopHeaders(header)
		if !result.BodySet {
			preserveMITMBodyHeaders(header, response.Header, contentLength)
		}
		response.Header = header
	}
	if result.Status != 0 {
		response.StatusCode = result.Status
	}
	if result.BodySet {
		if !result.HeadersSet {
			response.Header = response.Header.Clone()
		}
		if response.Header == nil {
			response.Header = make(http.Header)
		}
		response.Body = result.Body
		if response.Body == nil {
			response.Body = []byte{}
		}
		replaceMITMBodyHeaders(response.Header, len(response.Body))
	}
	return response, nil
}

func mitmScriptResponse(response *script.Response) (*httprewrite.Response, error) {
	if response == nil || !validMITMScriptStatus(response.Status) {
		return nil, errors.New("invalid script HTTP response status")
	}
	header, err := readMITMScriptHeaders(response.Headers)
	if err != nil {
		return nil, err
	}
	stripHTTPHopHeaders(header)
	header.Set("Content-Length", strconv.Itoa(len(response.Body)))
	return &httprewrite.Response{StatusCode: response.Status, Header: header, Body: response.Body}, nil
}

func validMITMScriptStatus(status int) bool { return status >= http.StatusOK && status <= 599 }

func preserveMITMBodyHeaders(header, original http.Header, length int64) {
	header.Del("Content-Encoding")
	if values := original.Values("Content-Encoding"); len(values) != 0 {
		header["Content-Encoding"] = values
	}
	header.Del("Content-Length")
	if length > 0 || length == 0 && original.Get("Content-Length") != "" {
		header.Set("Content-Length", strconv.FormatInt(length, 10))
	}
}

func replaceMITMBodyHeaders(header http.Header, length int) {
	header.Del("Content-Encoding")
	header.Del("Transfer-Encoding")
	header.Set("Content-Length", strconv.Itoa(length))
}

func setMITMRequestBody(request *http.Request, data []byte) {
	request.ContentLength = int64(len(data))
	request.TransferEncoding = nil
	empty := len(data) == 0 && len(request.Trailer) == 0
	request.GetBody = func() (io.ReadCloser, error) {
		if empty {
			return http.NoBody, nil
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	request.Body, _ = request.GetBody()
}

func appendMITMScriptStats(stats []api.MITMScriptStats, runs []api.MITMScriptRun) []api.MITMScriptStats {
	for _, run := range runs {
		i := slices.IndexFunc(stats, func(entry api.MITMScriptStats) bool { return entry.ID == run.ID })
		if i >= 0 {
			stats[i].Count++
			stats[i].LastResult = run.Result
		} else if len(stats) < maxConnectionEvents {
			stats = append(stats, api.MITMScriptStats{ID: run.ID, Count: 1, LastResult: run.Result})
		}
	}
	return stats
}
