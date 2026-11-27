//go:build darwin && cgo && with_gvisor

package main

/*
#include <stddef.h>
#include <stdint.h>
typedef int32_t (*RekaSecretReader)(const void *, size_t, void *, size_t);
typedef int32_t (*RekaSecretWriter)(const void *, size_t, const void *, size_t);
typedef const void *RekaAppOperationInput;
static inline int32_t readSecret(RekaSecretReader reader, const void *name, size_t length, void *output, size_t capacity) {
	return reader(name, length, output, capacity);
}
static inline int32_t writeSecret(RekaSecretWriter writer, const void *name, size_t length, const void *value, size_t valueLength) {
	return writer(name, length, value, valueLength);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/mobile/appbridge"
	"github.com/MimoProxy/reka/mobile/packettunnel"
	"github.com/MimoProxy/reka/mobile/profile"
)

type runningTunnel struct {
	id      uint64
	session *packettunnel.Session
}

var (
	lifecycle sync.Mutex
	active    atomic.Pointer[runningTunnel]
	lastID    uint64
	reader    atomic.Pointer[C.RekaSecretReader]
	writer    atomic.Pointer[C.RekaSecretWriter]
	keychain  = appbridge.KeychainStore{Read: readKeychain, Write: writeKeychain}
	appOps    = appbridge.New(keychain)
)

//export RekaGoSetSecretReader
func RekaGoSetSecretReader(callback C.RekaSecretReader) {
	reader.Store(&callback)
}

// RekaGoSetSecretWriter registers the synchronous Keychain callback.
//
//	typedef int32_t (*RekaSecretWriter)(const void *name, size_t nameLength,
//	    const void *value, size_t valueLength);
//	void RekaGoSetSecretWriter(RekaSecretWriter writer);
//
// The callback returns 1 for success and 0 for failure. NULL with length zero
// deletes an item and an already missing item counts as success. The callback
// may run on a Go worker thread; its pointers are valid only during the call.
//
//export RekaGoSetSecretWriter
func RekaGoSetSecretWriter(callback C.RekaSecretWriter) {
	writer.Store(&callback)
}

func readKeychain(name string, output []byte) int {
	callback := reader.Load()
	if callback == nil || *callback == nil {
		return -1
	}
	return int(C.readSecret(*callback, unsafe.Pointer(unsafe.StringData(name)), C.size_t(len(name)),
		unsafe.Pointer(unsafe.SliceData(output)), C.size_t(len(output))))
}

func writeKeychain(name string, value []byte) bool {
	callback := writer.Load()
	if callback == nil || *callback == nil {
		return false
	}
	return C.writeSecret(*callback, unsafe.Pointer(unsafe.StringData(name)), C.size_t(len(name)),
		unsafe.Pointer(unsafe.SliceData(value)), C.size_t(len(value))) == 1
}

// RekaGoAppOperation runs a main-app JSON operation.
//
//	int32_t RekaGoAppOperation(const void *input, size_t length, void *output, size_t capacity);
//
// The return is the JSON byte count without a NUL terminator, or the negative
// required capacity. NULL output with zero capacity requests a size. Retry
// immediately with the original bytes to reuse the result, including for a
// mutating operation. Serialize the operation and its retries in the caller.
// A NULL output with positive capacity is invalid and returns zero.
//
//export RekaGoAppOperation
func RekaGoAppOperation(input C.RekaAppOperationInput, length C.size_t, output unsafe.Pointer, capacity C.size_t) C.int32_t {
	if output == nil && capacity != 0 {
		return 0
	}
	var request []byte
	if input != nil && length <= appbridge.MaxInputBytes {
		request = unsafe.Slice((*byte)(unsafe.Pointer(input)), int(length))
	}
	reply := unsafe.Slice((*byte)(output), int(min(capacity, math.MaxInt32)))
	return C.int32_t(appOps.WriteResponse(request, reply))
}

//export RekaGoSetNetworkInterface
func RekaGoSetNetworkInterface(id C.uint64_t, name *C.char) {
	if session := lookup(id); session != nil && name != nil {
		session.SetNetworkInterface(C.GoString(name))
	}
}

//export RekaGoSetMTU
func RekaGoSetMTU(mtu C.int32_t) C.int32_t {
	if packettunnel.SetMTU(int(mtu)) {
		return 1
	}
	return 0
}

//export RekaGoStart
func RekaGoStart(data unsafe.Pointer, length C.size_t) C.uint64_t {
	if data == nil || length == 0 || length > 4096 {
		return 0
	}
	var node packettunnel.Node
	if err := json.Unmarshal(unsafe.Slice((*byte)(data), int(length)), &node); err != nil {
		return 0
	}
	return start(func() (*packettunnel.Session, error) { return packettunnel.Start(node) }, true, nil, 0)
}

//export RekaGoPrepareProfile
func RekaGoPrepareProfile(input, output, cache *C.char, failure *C.char, capacity C.size_t) C.int32_t {
	if input == nil || output == nil || cache == nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	if err := profile.PrepareFileWithOptions(ctx, C.GoString(input), C.GoString(output), C.GoString(cache), profile.PrepareOptions{Secrets: keychain}); err != nil {
		writeError(failure, capacity, err.Error())
		return 0
	}
	return 1
}

//export RekaGoPrepareProfileEx
func RekaGoPrepareProfileEx(input, output, cache, optionsPath *C.char, failure *C.char, capacity C.size_t) C.int32_t {
	if input == nil || output == nil || cache == nil || optionsPath == nil {
		return 0
	}
	data, err := os.ReadFile(C.GoString(optionsPath))
	var options struct {
		profile.PrepareOptions
		ProxySnapshot string           `json:"proxySnapshot"`
		ProxyControls profile.Controls `json:"proxyControls"`
		Background    bool             `json:"background"`
	}
	if err != nil || len(data) > 256<<10 {
		return 0
	}
	if json.Unmarshal(data, &options) != nil {
		writeValidationError(failure, capacity, &profile.ValidationError{Message: "Invalid profile options JSON"})
		return 0
	}
	// Geodata databases can take more than a minute through a proxy.
	timeout := 150 * time.Second
	if options.Background {
		timeout = 22 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	options.Secrets = keychain
	options.ProxyControls.Secrets = options.Secrets

	var seed *packettunnel.Session
	defer func() {
		if seed != nil {
			seed.Close()
		}
	}()
	if options.ProxySnapshot != "" {
		options.ClientFor = func(name string) (*http.Client, error) {
			if seed == nil {
				raw, err := os.ReadFile(options.ProxySnapshot)
				if err != nil {
					return nil, err
				}
				seed, err = packettunnel.StartProbeProfile(raw, options.ProxyControls)
				if err != nil {
					return nil, err
				}
			}
			return seed.ProviderClient(name)
		}
	}
	if err := profile.PrepareFileWithOptions(ctx, C.GoString(input), C.GoString(output), C.GoString(cache), options.PrepareOptions); err != nil {
		var report *profile.ValidationError
		if !errors.As(err, &report) {
			report = &profile.ValidationError{Message: err.Error()}
		}
		writeValidationError(failure, capacity, report)
		return 0
	}
	return 1
}

//export RekaGoStartProfile
func RekaGoStartProfile(snapshot unsafe.Pointer, size C.size_t, data unsafe.Pointer, length C.size_t, trace C.int32_t, failure *C.char, capacity C.size_t) C.uint64_t {
	controls, ok := decodeControls(data, length)
	if !ok || snapshot == nil || size == 0 || size > profile.MaxBundleBytes {
		return 0
	}
	return start(func() (*packettunnel.Session, error) {
		return packettunnel.StartProfile(unsafe.Slice((*byte)(snapshot), int(size)), controls, trace != 0)
	}, true, failure, capacity)
}

//export RekaGoStartProbeProfile
func RekaGoStartProbeProfile(snapshot unsafe.Pointer, size C.size_t, data unsafe.Pointer, length C.size_t) C.uint64_t {
	controls, ok := decodeControls(data, length)
	if !ok || snapshot == nil || size == 0 || size > profile.MaxBundleBytes {
		return 0
	}
	return start(func() (*packettunnel.Session, error) {
		return packettunnel.StartProbeProfile(unsafe.Slice((*byte)(snapshot), int(size)), controls)
	}, false, nil, 0)
}

func start(open func() (*packettunnel.Session, error), extension bool, failure *C.char, capacity C.size_t) C.uint64_t {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if active.Load() != nil {
		return 0
	}
	// Packet-flow sessions run inside the VPN extension process.
	if extension {
		tuneExtensionRuntime()
	}
	session, err := open()
	if err != nil {
		writeError(failure, capacity, err.Error())
		return 0
	}
	if extension && guardExtensionMemory {
		session.StartMemoryGuard()
	}
	lastID++
	active.Store(&runningTunnel{id: lastID, session: session})
	return C.uint64_t(lastID)
}

//export RekaGoApplyControls
func RekaGoApplyControls(id C.uint64_t, data unsafe.Pointer, length C.size_t) C.int32_t {
	session := lookup(id)
	controls, ok := decodeControls(data, length)
	if session == nil || !ok || session.ApplyControls(controls) != nil {
		return 0
	}
	return 1
}

//export RekaGoReplaceProfile
func RekaGoReplaceProfile(id C.uint64_t, snapshot unsafe.Pointer, size C.size_t, data unsafe.Pointer, length C.size_t) C.int32_t {
	session := lookup(id)
	controls, ok := decodeControls(data, length)
	if session == nil || !ok || snapshot == nil || size == 0 || size > profile.MaxBundleBytes {
		return 0
	}
	if session.ReplaceProfile(unsafe.Slice((*byte)(snapshot), int(size)), controls) != nil {
		return 0
	}
	return 1
}

//export RekaGoOperation
func RekaGoOperation(id C.uint64_t, input unsafe.Pointer, length C.size_t, output unsafe.Pointer, capacity C.size_t) C.int32_t {
	session := lookup(id)
	if session == nil || input == nil || length == 0 || length > 8<<10 || output == nil || capacity == 0 || capacity > 128<<10 {
		return 0
	}
	var op packettunnel.Operation
	if json.Unmarshal(unsafe.Slice((*byte)(input), int(length)), &op) != nil {
		return 0
	}
	result, err := session.RunOperation(op)
	if err != nil {
		result = map[string]string{"operation_error": history.Text(err.Error(), 384)}
	}
	data, err := json.Marshal(result)
	if err != nil || len(data) > int(capacity) {
		return 0
	}
	copy(unsafe.Slice((*byte)(output), int(capacity)), data)
	return C.int32_t(len(data))
}

//export RekaGoCounts
func RekaGoCounts(id C.uint64_t, connections, dns *C.uint32_t) C.int32_t {
	session := lookup(id)
	if session == nil || connections == nil || dns == nil {
		return 0
	}
	active, queries := session.Counts()
	*connections, *dns = C.uint32_t(active), C.uint32_t(queries)
	return 1
}

// RekaGoUplink reports whether every outbound dial has been failing, as on a
// network that the system lists as available but that passes no traffic.
// sinceMs is when the failures began; failures counts them.
//
//export RekaGoUplink
func RekaGoUplink(id C.uint64_t, sinceMS *C.int64_t, failures *C.uint32_t) C.int32_t {
	session := lookup(id)
	if session == nil || sinceMS == nil || failures == nil {
		return -1
	}
	status := session.Uplink()
	*sinceMS, *failures = C.int64_t(status.SinceMS), C.uint32_t(status.Failures)
	if status.Stalled {
		return 1
	}
	return 0
}

//export RekaGoNetworkChanged
func RekaGoNetworkChanged(id C.uint64_t, available, changed C.int32_t) {
	if session := lookup(id); session != nil {
		session.NetworkChanged(available == 1, changed == 1)
	}
}

// RekaGoMemoryPressure forwards a critical memory pressure notice from the
// system to the running tunnel.
//
//export RekaGoMemoryPressure
func RekaGoMemoryPressure(id C.uint64_t) {
	if session := lookup(id); session != nil {
		session.MemoryPressure()
	}
}

//export RekaGoSetRealDNS
func RekaGoSetRealDNS(id C.uint64_t, real C.int32_t) {
	if session := lookup(id); session != nil {
		session.SetRealDNS(real != 0)
	}
}

//export RekaGoPolicyStatus
func RekaGoPolicyStatus(id C.uint64_t, out unsafe.Pointer, capacity C.size_t) C.int32_t {
	session := lookup(id)
	if session == nil || out == nil || capacity == 0 || capacity > 64<<10 {
		return 0
	}
	status, err := session.ProfileStatus()
	if err != nil {
		return 0
	}
	data, err := json.Marshal(status)
	if err != nil || len(data) > int(capacity) {
		return 0
	}
	copy(unsafe.Slice((*byte)(out), int(capacity)), data)
	return C.int32_t(len(data))
}

func decodeControls(data unsafe.Pointer, length C.size_t) (profile.Controls, bool) {
	controls := profile.Controls{Secrets: keychain}
	if data == nil || length == 0 || length > 64<<10 {
		return controls, false
	}
	err := json.Unmarshal(unsafe.Slice((*byte)(data), int(length)), &controls)
	return controls, err == nil
}

func writeError(failure *C.char, capacity C.size_t, description string) {
	if failure != nil && capacity > 1 && capacity <= 48<<10 {
		buffer := unsafe.Slice((*byte)(unsafe.Pointer(failure)), int(capacity))
		n := copy(buffer[:len(buffer)-1], description)
		buffer[n] = 0
	}
}

func writeValidationError(failure *C.char, capacity C.size_t, report *profile.ValidationError) {
	bounded := *report
	bounded.Message = history.Text(bounded.Message, 512)
	bounded.Diagnostics = bounded.Diagnostics[:min(len(bounded.Diagnostics), 40)]
	for i := range bounded.Diagnostics {
		bounded.Diagnostics[i].Message = history.Text(bounded.Diagnostics[i].Message, 512)
		bounded.Diagnostics[i].Path = history.Text(bounded.Diagnostics[i].Path, 256)
	}
	for {
		payload, err := json.Marshal(bounded)
		if err == nil && len(payload) < int(capacity) {
			writeError(failure, capacity, string(payload))
			return
		}
		if len(bounded.Diagnostics) == 0 {
			return
		}
		bounded.Diagnostics = bounded.Diagnostics[:len(bounded.Diagnostics)/2]
	}
}

func lookup(id C.uint64_t) *packettunnel.Session {
	if current := active.Load(); current != nil && current.id == uint64(id) {
		return current.session
	}
	return nil
}

//export RekaGoSubmit
func RekaGoSubmit(id C.uint64_t, data unsafe.Pointer, length C.size_t) C.int32_t {
	session := lookup(id)
	if session == nil || data == nil || length == 0 || length > C.size_t(session.MTU()) {
		return 0
	}
	if session.Submit(unsafe.Slice((*byte)(data), int(length))) {
		return 1
	}
	return 0
}

//export RekaGoRead
func RekaGoRead(id C.uint64_t, data unsafe.Pointer, lengths *C.uint16_t, count C.int32_t) C.int32_t {
	session := lookup(id)
	if session == nil || data == nil || lengths == nil || count <= 0 || count > packettunnel.MaxBatch {
		return 0
	}
	output := unsafe.Slice((*byte)(data), int(count)*session.MTU())
	sizes := unsafe.Slice((*uint16)(unsafe.Pointer(lengths)), int(count))
	return C.int32_t(session.ReadBatch(output, sizes))
}

//export RekaGoTraffic
func RekaGoTraffic(id C.uint64_t, upload *C.uint64_t, download *C.uint64_t) C.int32_t {
	session := lookup(id)
	if session == nil || upload == nil || download == nil {
		return 0
	}
	up, down := session.Traffic()
	*upload, *download = C.uint64_t(up), C.uint64_t(down)
	return 1
}

//export RekaGoStop
func RekaGoStop(id C.uint64_t) {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if session := lookup(id); session != nil {
		active.Store(nil)
		session.Close()
	}
}

func main() {}
