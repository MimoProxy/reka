// Package gojaengine implements the Surge script engine using goja.
package gojaengine

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/MimoProxy/reka/internal/script"
	"github.com/dop251/goja"
	"github.com/dop251/goja/parser"
)

// Engine runs each session in a fresh goja runtime and shares compiled programs.
type Engine struct {
	cache programCache
}

var _ script.Engine = (*Engine)(nil)

// New returns a goja engine.
func New() *Engine { return &Engine{} }

// Check compiles a script to validate its syntax without executing it.
func Check(name, source string) error {
	_, err := compile(name, source)
	return err
}

// Purge releases the cached compiled programs.
func (e *Engine) Purge() { e.cache.purge() }

// Run executes a script session on the calling goroutine.
func (e *Engine) Run(ctx context.Context, job *script.Job) (script.Done, error) {
	start := time.Now()
	normalized := *job
	normalized.Limits = job.Limits.WithDefaults()
	job = &normalized
	program, err := e.cache.get(ctx, job.Script, job.Limits)
	if ctx.Err() != nil {
		return script.Done{}, contextError(ctx)
	}
	if err != nil {
		return script.Done{}, script.NewScriptError(job.Script.Name, err.Error())
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	vm := goja.New()
	vm.SetParserOptions(parser.WithDisableSourceMaps)
	s := session{
		vm:          vm,
		job:         job,
		ctx:         ctx,
		httpResults: make(chan httpResult, job.Limits.MaxHTTPInFlight),
	}
	interrupted := make(chan struct{})
	stopInterrupt := context.AfterFunc(ctx, func() {
		vm.Interrupt(ctx.Err())
		close(interrupted)
	})
	defer func() {
		if !stopInterrupt() {
			<-interrupted
		}
	}()

	err = s.execute(program, start)
	if s.done.Called {
		return s.done, nil
	}
	if ctx.Err() != nil {
		return script.Done{}, contextError(ctx)
	}
	return script.Done{}, err
}

func contextError(ctx context.Context) error {
	if ctx.Err() == context.DeadlineExceeded {
		return script.ErrTimeout
	}
	return ctx.Err()
}

type session struct {
	vm  *goja.Runtime
	job *script.Job
	ctx context.Context

	startedDone bool
	done        script.Done
	rejections  map[*goja.Promise]struct{}
	primitives  primitives

	nextTimerID int64
	timers      map[int64]sessionTimer

	nextHTTPID    uint64
	httpPending   int
	httpCallbacks map[uint64]goja.Callable
	httpResults   chan httpResult
}

// sessionDone unwinds native callbacks as well as JavaScript frames. It is
// outside the VM's exception types, so a script cannot catch it.
type sessionDone struct{}

func (s *session) execute(program *goja.Program, start time.Time) (err error) {
	defer func() {
		switch recovered := recover(); ex := recovered.(type) {
		case nil, sessionDone:
		case *goja.Exception:
			err = s.exception(ex.Value())
		case *goja.StackOverflowError:
			err = script.NewScriptError(s.job.Script.Name, "maximum call stack size exceeded")
		case *goja.InterruptedError:
			err = contextError(s.ctx)
		default:
			panic(recovered)
		}
	}()

	s.capturePrimitives()
	s.installGlobals(start)
	s.installServices()
	s.installWebAPIs()
	s.installTimers()
	s.vm.SetPromiseRejectionTracker(s.trackRejection)
	if _, err := s.vm.RunProgram(program); err != nil {
		panic(err)
	}
	// goja drains Promise jobs each time execution leaves the runtime. Only
	// timers and HTTP results need to be delivered between these turns.
	for s.ctx.Err() == nil {
		if len(s.timers) == 0 && s.httpPending == 0 {
			// Like JavaScriptCore, an unhandled rejection does not end a
			// session that can still call $done; it explains one that cannot.
			for p := range s.rejections {
				return s.exception(p.Result())
			}
			return script.ErrNoDone
		}
		s.waitForEvent()
	}
	return contextError(s.ctx)
}

func (s *session) trackRejection(p *goja.Promise, op goja.PromiseRejectionOperation) {
	if op == goja.PromiseRejectionHandle {
		delete(s.rejections, p)
		return
	}
	if s.rejections == nil {
		s.rejections = make(map[*goja.Promise]struct{})
	}
	s.rejections[p] = struct{}{}
}

func (s *session) exception(value goja.Value) error {
	// Formatting a thrown object can run user-defined conversion hooks.
	s.startedDone = true
	message := "uncaught JavaScript exception"
	if s.ctx.Err() == nil {
		if text, err := s.primitives.stringValue(goja.Undefined(), value); err == nil {
			message = text.String()
		}
	}
	return script.NewScriptError(s.job.Script.Name, message)
}

func (s *session) call(fn goja.Callable, args ...goja.Value) goja.Value {
	return callWithThis(fn, goja.Undefined(), args...)
}

func callWithThis(fn goja.Callable, this goja.Value, args ...goja.Value) goja.Value {
	v, err := fn(this, args...)
	if err != nil {
		panic(err)
	}
	return v
}

func (s *session) installGlobals(start time.Time) {
	spec, in := s.job.Script, s.job.Input
	req := s.vm.NewObject()
	s.set(req, "id", in.Request.ID)
	s.set(req, "method", in.Request.Method)
	s.set(req, "url", in.Request.URL)
	s.set(req, "headers", s.headers(in.Request.Headers, spec.FullHeader))
	if spec.Kind == script.KindHTTPRequest && in.Request.Body != nil {
		s.set(req, "body", s.inputBody(in.Request.Body))
	}
	s.global("$request", req)
	if spec.Kind == script.KindHTTPResponse {
		resp := s.vm.NewObject()
		s.set(resp, "status", in.Response.Status)
		s.set(resp, "headers", s.headers(in.Response.Headers, spec.FullHeader))
		if in.Response.Body != nil {
			s.set(resp, "body", s.inputBody(in.Response.Body))
		}
		s.global("$response", resp)
	}
	if spec.Argument != nil {
		s.global("$argument", *spec.Argument)
	}
	env := s.job.Env
	s.global("$environment", map[string]string{
		"system":        env.System,
		"surge-version": env.SurgeVersion,
		"surge-build":   env.SurgeBuild,
		"language":      env.Language,
		"device-model":  env.DeviceModel,
	})
	s.global("$script", map[string]any{
		"name":           spec.Name,
		"type":           string(spec.Kind),
		"startTime":      start.Unix(),
		"sessionID":      rand.Text(),
		"binaryBodyMode": spec.BinaryBody,
	})
	s.global("$done", func(call goja.FunctionCall) goja.Value {
		if s.startedDone {
			return goja.Undefined()
		}
		s.startedDone = true
		done := s.readDone(call.Argument(0))
		if s.ctx.Err() == nil {
			s.done = done
		}
		panic(sessionDone{})
	})
}

func (s *session) set(o *goja.Object, name string, v any) {
	if err := o.Set(name, v); err != nil {
		panic(err)
	}
}

func (s *session) global(name string, v any) {
	if err := s.vm.Set(name, v); err != nil {
		panic(err)
	}
}
