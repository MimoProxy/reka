//go:build ios && cgo && with_gvisor

package main

/*
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef const void *RekaScriptInput;
typedef void (*RekaScriptStart)(uint64_t, const void *, size_t, void *, size_t, void *, size_t);
typedef void (*RekaScriptCancel)(uint64_t);
typedef void (*RekaScriptReply)(uint64_t, uint64_t, const void *, size_t, void *, size_t);
typedef void (*RekaScriptPurge)(void);
typedef void (*RekaScriptNotify)(const void *, size_t);

static inline void rekaScriptStart(RekaScriptStart start, uint64_t run, const void *job,
	size_t jobLength, void *requestBody, size_t requestLength, void *responseBody, size_t responseLength) {
	start(run, job, jobLength, requestBody, requestLength, responseBody, responseLength);
}
static inline void rekaScriptCancel(RekaScriptCancel cancel, uint64_t run) {
	cancel(run);
}
static inline void rekaScriptReply(RekaScriptReply reply, uint64_t run, uint64_t call,
	const void *response, size_t length, void *body, size_t bodyLength) {
	reply(run, call, response, length, body, bodyLength);
}
static inline void rekaScriptPurge(RekaScriptPurge purge) {
	purge();
}
static inline void rekaScriptNotify(RekaScriptNotify notify, const void *notification, size_t length) {
	notify(notification, length);
}
*/
import "C"

import (
	"encoding/json"
	"math"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/mobile/packettunnel"
	"github.com/MimoProxy/reka/mobile/scriptbridge"
	"github.com/sagernet/sing/common/memory"
)

// Reka defines these script footprint thresholds for its iOS extension.
const (
	// Reka allows some fluctuation above its 25 MiB steady extension budget.
	// A measured JSC run with a 512 KiB body used up to about 10 MiB, so skip
	// new runs as the process approaches the 35 MiB peak budget.
	scriptSkipAbove = 28 << 20
	// Reka discards results and purges host caches above its 35 MiB peak
	// budget, 10 MiB below the sing-box-compatible connection reset.
	scriptDiscardAbove = 35 << 20
)

type scriptCallbacks struct {
	start  C.RekaScriptStart
	cancel C.RekaScriptCancel
	reply  C.RekaScriptReply
	purge  C.RekaScriptPurge
	notify C.RekaScriptNotify
}

var (
	scriptRegistrationMu sync.Mutex
	scriptHostCallbacks  atomic.Pointer[scriptCallbacks]
	processScriptBridge  = scriptbridge.New(iosScriptHost{}, scriptbridge.Options{
		Footprint: memory.Total, SkipAbove: scriptSkipAbove, DiscardAbove: scriptDiscardAbove,
	})
)

// RekaGoSetScriptHost registers the Swift callbacks before starting the tunnel.
//
//	typedef void (*RekaScriptStart)(uint64_t run, const void *job, size_t jobLength,
//	    void *requestBody, size_t requestLength, void *responseBody, size_t responseLength);
//	typedef void (*RekaScriptCancel)(uint64_t run);
//	typedef void (*RekaScriptReply)(uint64_t run, uint64_t call, const void *response, size_t length,
//	    void *body, size_t bodyLength);
//	typedef void (*RekaScriptPurge)(void);
//	typedef void (*RekaScriptNotify)(const void *notification, size_t length);
//	void RekaGoSetScriptHost(RekaScriptStart start, RekaScriptCancel cancel, RekaScriptReply reply,
//	    RekaScriptPurge purge, RekaScriptNotify notify);
//
// Callbacks may run on any Go thread. Keep them registered until the tunnel
// stops. Passing any NULL callback clears the registration. Start should
// schedule execution and return promptly so Go can cancel a timed-out run.
// JSON pointers are borrowed for the callback. Each non-NULL body pointer
// passes to Swift, which must release it with free(). A NULL body means no
// body. An empty body has a non-NULL pointer and length zero.
//
//export RekaGoSetScriptHost
func RekaGoSetScriptHost(start C.RekaScriptStart, cancel C.RekaScriptCancel, reply C.RekaScriptReply, purge C.RekaScriptPurge, notify C.RekaScriptNotify) {
	scriptRegistrationMu.Lock()
	defer scriptRegistrationMu.Unlock()
	if start == nil || cancel == nil || reply == nil || purge == nil || notify == nil {
		packettunnel.SetScriptHost(nil, nil)
		scriptHostCallbacks.Store(nil)
		return
	}
	scriptHostCallbacks.Store(&scriptCallbacks{start: start, cancel: cancel, reply: reply, purge: purge, notify: notify})
	packettunnel.SetScriptHost(func() script.Engine { return processScriptBridge }, sendScriptNotification)
}

type iosScriptHost struct{}

func (iosScriptHost) Start(run uint64, job, requestBody, responseBody []byte) {
	callbacks := scriptHostCallbacks.Load()
	if callbacks == nil {
		processScriptBridge.Done(run, []byte(`{"error":{"kind":"internal","message":"script host is unavailable"}}`), nil, nil)
		return
	}
	C.rekaScriptStart(callbacks.start, C.uint64_t(run), unsafe.Pointer(unsafe.SliceData(job)), C.size_t(len(job)),
		scriptHostBody(requestBody), C.size_t(len(requestBody)), scriptHostBody(responseBody), C.size_t(len(responseBody)))
}

func (iosScriptHost) Cancel(run uint64) {
	if callbacks := scriptHostCallbacks.Load(); callbacks != nil {
		C.rekaScriptCancel(callbacks.cancel, C.uint64_t(run))
	}
}

func (iosScriptHost) Reply(run, call uint64, response, body []byte) {
	if callbacks := scriptHostCallbacks.Load(); callbacks != nil {
		C.rekaScriptReply(callbacks.reply, C.uint64_t(run), C.uint64_t(call),
			unsafe.Pointer(unsafe.SliceData(response)), C.size_t(len(response)), scriptHostBody(body), C.size_t(len(body)))
	}
}

func (iosScriptHost) Purge() {
	if callbacks := scriptHostCallbacks.Load(); callbacks != nil {
		C.rekaScriptPurge(callbacks.purge)
	}
}

func sendScriptNotification(notification api.ScriptNotification) {
	callbacks := scriptHostCallbacks.Load()
	if callbacks == nil {
		return
	}
	data, err := json.Marshal(notification)
	if err == nil {
		C.rekaScriptNotify(callbacks.notify, unsafe.Pointer(unsafe.SliceData(data)), C.size_t(len(data)))
	}
}

func scriptHostBody(body []byte) unsafe.Pointer {
	switch {
	case body == nil:
		return nil
	case len(body) == 0:
		return C.malloc(1)
	default:
		return C.CBytes(body)
	}
}

// RekaGoScriptDone hands the result of a live run back to Go.
//
//	int32_t RekaGoScriptDone(uint64_t run, const void *done, size_t length,
//	    const void *body, size_t bodyLength, const void *responseBody, size_t responseBodyLength);
//
// Go copies the input it retains. The caller owns all buffers and may release
// them after the call. The return is 1 for acceptance and 0 for rejection.
//
//export RekaGoScriptDone
func RekaGoScriptDone(run C.uint64_t, done C.RekaScriptInput, length C.size_t, body C.RekaScriptInput, bodyLength C.size_t, responseBody C.RekaScriptInput, responseBodyLength C.size_t) C.int32_t {
	result, ok := scriptInput(done, length)
	payload, bodyOK := scriptInput(body, bodyLength)
	response, responseOK := scriptInput(responseBody, responseBodyLength)
	if ok && bodyOK && responseOK && processScriptBridge.Done(uint64(run), result, payload, response) {
		return 1
	}
	return 0
}

// RekaGoScriptSource writes the source of a live script.
//
//	int32_t RekaGoScriptSource(uint64_t run, void *output, size_t capacity);
//
// The caller owns the output and the byte count excludes a NUL terminator.
// If the buffer is short, the return is the negative required capacity.
// NULL output with zero capacity requests a size. Errors return 0.
//
//export RekaGoScriptSource
func RekaGoScriptSource(run C.uint64_t, output unsafe.Pointer, capacity C.size_t) C.int32_t {
	if output == nil && capacity != 0 {
		return 0
	}
	reply := unsafe.Slice((*byte)(output), int(min(capacity, math.MaxInt32)))
	return C.int32_t(processScriptBridge.WriteSource(uint64(run), reply))
}

// RekaGoScriptCall executes a synchronous service operation.
//
//	int32_t RekaGoScriptCall(uint64_t run, const void *input, size_t length, void *output, size_t capacity);
//
// The caller owns both buffers. The return is the byte count without a NUL
// terminator, or the negative required capacity. NULL output with zero
// capacity requests a size. Serialize each request and its retries. Retry
// immediately with the same bytes to reuse the cached result. Errors return 0.
//
//export RekaGoScriptCall
func RekaGoScriptCall(run C.uint64_t, input C.RekaScriptInput, length C.size_t, output unsafe.Pointer, capacity C.size_t) C.int32_t {
	data, ok := scriptInput(input, length)
	if !ok || (output == nil && capacity != 0) {
		return 0
	}
	reply := unsafe.Slice((*byte)(output), int(min(capacity, math.MaxInt32)))
	return C.int32_t(processScriptBridge.WriteCallResponse(uint64(run), data, reply))
}

// RekaGoScriptHTTP starts an asynchronous HTTP service call.
//
//	int32_t RekaGoScriptHTTP(uint64_t run, uint64_t call, const void *request, size_t length,
//	    const void *body, size_t bodyLength);
//
// Go copies the input it retains. The caller owns both buffers and may release
// them after the call. The return is 1 for acceptance and 0 for rejection.
//
//export RekaGoScriptHTTP
func RekaGoScriptHTTP(run C.uint64_t, call C.uint64_t, request C.RekaScriptInput, length C.size_t, body C.RekaScriptInput, bodyLength C.size_t) C.int32_t {
	data, ok := scriptInput(request, length)
	payload, bodyOK := scriptInput(body, bodyLength)
	if ok && bodyOK && processScriptBridge.HTTP(uint64(run), uint64(call), data, payload) {
		return 1
	}
	return 0
}

func scriptInput(input C.RekaScriptInput, length C.size_t) ([]byte, bool) {
	if length > math.MaxInt || (input == nil && length != 0) {
		return nil, false
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(input)), int(length)), true
}
