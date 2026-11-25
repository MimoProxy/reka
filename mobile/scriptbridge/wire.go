package scriptbridge

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MimoProxy/reka/internal/script"
)

type headerPairs [][2]string

func encodeHeaders(fields []script.HeaderField) headerPairs {
	pairs := make(headerPairs, len(fields))
	for i, field := range fields {
		pairs[i] = [2]string{field.Name, field.Value}
	}
	return pairs
}

func (pairs headerPairs) decode() []script.HeaderField {
	if pairs == nil {
		return nil
	}
	fields := make([]script.HeaderField, len(pairs))
	for i, pair := range pairs {
		fields[i] = script.HeaderField{Name: pair[0], Value: pair[1]}
	}
	return fields
}

type requestInput struct {
	ID      string      `json:"id"`
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers headerPairs `json:"headers"`
	HasBody bool        `json:"hasBody"`
}

type responseInput struct {
	Status  int         `json:"status"`
	Headers headerPairs `json:"headers"`
	HasBody bool        `json:"hasBody"`
}

type environment struct {
	System       string `json:"system"`
	SurgeVersion string `json:"surgeVersion"`
	SurgeBuild   string `json:"surgeBuild"`
	Language     string `json:"language"`
	DeviceModel  string `json:"deviceModel"`
}

type runLimits struct {
	MaxTimers       int   `json:"maxTimers"`
	MaxHTTPInFlight int   `json:"maxHTTPInFlight"`
	LogLineMax      int   `json:"logLineMax"`
	StoreValueMax   int   `json:"storeValueMax"`
	UngzipMax       int64 `json:"ungzipMax"`
}

type jobInput struct {
	Key        string         `json:"key"`
	Name       string         `json:"name"`
	Path       string         `json:"path"`
	Kind       script.Kind    `json:"kind"`
	Dialect    script.Dialect `json:"dialect"`
	Engine     string         `json:"engine"`
	BinaryBody bool           `json:"binaryBody"`
	FullHeader bool           `json:"fullHeader"`
	Argument   any            `json:"argument"`
	TimeoutMS  int64          `json:"timeoutMs"`
	SourceSize int            `json:"sourceSize"`
	Request    requestInput   `json:"request"`
	Response   *responseInput `json:"response,omitempty"`
	Env        environment    `json:"env"`
	Limits     runLimits      `json:"limits"`
}

func marshalJob(job *script.Job) (metadata, responseBody []byte, err error) {
	spec, input := job.Script, job.Input
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = script.DefaultTimeout
	}
	var argument any = spec.Argument
	if spec.ArgumentObject {
		argument, err = script.ParseArgumentObject(spec.Argument)
		if err != nil {
			return nil, nil, err
		}
	}
	request := input.Request
	env, limits := job.Env, job.Limits
	w := jobInput{
		Key: spec.CacheKey(), Name: spec.Name, Path: spec.Path, Kind: spec.Kind,
		Dialect: spec.Dialect, Engine: spec.Engine, BinaryBody: spec.BinaryBody,
		FullHeader: spec.FullHeader, Argument: argument,
		TimeoutMS: max(1, timeout.Milliseconds()), SourceSize: len(spec.Source),
		Request: requestInput{
			ID: request.ID, Method: request.Method, URL: request.URL,
			Headers: encodeHeaders(request.Headers), HasBody: request.Body != nil,
		},
		Env: environment{
			System: env.System, SurgeVersion: env.SurgeVersion, SurgeBuild: env.SurgeBuild,
			Language: env.Language, DeviceModel: env.DeviceModel,
		},
		Limits: runLimits{
			MaxTimers: limits.MaxTimers, MaxHTTPInFlight: limits.MaxHTTPInFlight,
			LogLineMax: limits.LogLineMax, StoreValueMax: limits.StoreValueMax, UngzipMax: limits.UngzipMax,
		},
	}
	if res := input.Response; spec.Kind == script.KindHTTPResponse && res != nil {
		w.Response = &responseInput{Status: res.Status, Headers: encodeHeaders(res.Headers), HasBody: res.Body != nil}
		responseBody = res.Body
	}
	metadata, err = json.Marshal(w)
	return
}

type doneResponse struct {
	Status  int         `json:"status"`
	Headers headerPairs `json:"headers"`
	BodySet bool        `json:"bodySet"`
}

type doneError struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

type doneOutput struct {
	Called     bool          `json:"called"`
	HasValue   bool          `json:"hasValue"`
	URL        *string       `json:"url"`
	Status     *int          `json:"status"`
	Headers    headerPairs   `json:"headers"`
	HeadersSet bool          `json:"headersSet"`
	BodySet    bool          `json:"bodySet"`
	Response   *doneResponse `json:"response"`
	Abort      bool          `json:"abort"`
	Error      *doneError    `json:"error"`
}

func (result completion) decode() (script.Done, error) {
	var w *doneOutput
	if err := json.Unmarshal(result.data, &w); err != nil {
		return script.Done{}, fmt.Errorf("invalid script completion: %w", err)
	}
	if w == nil {
		return script.Done{}, errors.New("invalid script completion: expected an object")
	}
	if w.Error != nil {
		return script.Done{}, w.Error.asError()
	}
	done := script.Done{
		Called: w.Called, HasValue: w.HasValue, URL: w.URL, Status: w.Status,
		Headers: w.Headers.decode(), HeadersSet: w.HeadersSet, BodySet: w.BodySet, Abort: w.Abort,
	}
	if w.BodySet {
		done.Body = explicitBody(result.body)
	}
	if w.Response != nil {
		done.Response = &script.Response{Status: w.Response.Status, Headers: w.Response.Headers.decode()}
		if w.Response.BodySet {
			done.Response.Body = explicitBody(result.responseBody)
		}
	}
	return done, nil
}

func explicitBody(body []byte) []byte {
	if body == nil {
		return []byte{}
	}
	return body
}

func (e *doneError) asError() error {
	switch e.Kind {
	case "exception":
		return script.NewScriptError(e.Name, e.Message)
	case "timeout":
		return script.ErrTimeout
	case "nodone":
		return script.ErrNoDone
	case "memory":
		return script.ErrMemoryExceeded
	default:
		if e.Message != "" {
			return errors.New(e.Message)
		}
		return errors.New("script host returned an error")
	}
}
