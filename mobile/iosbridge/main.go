//go:build ios && cgo && with_gvisor

package main

/*
#include <stdint.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

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
)

//export RekaGoStart
func RekaGoStart(data unsafe.Pointer, length C.size_t) C.uint64_t {
	if data == nil || length == 0 || length > 4096 {
		return 0
	}
	var node packettunnel.Node
	if err := json.Unmarshal(unsafe.Slice((*byte)(data), int(length)), &node); err != nil {
		return 0
	}
	return start(func() (*packettunnel.Session, error) { return packettunnel.Start(node) }, nil, 0)
}

//export RekaGoPrepareProfile
func RekaGoPrepareProfile(input, output, cache *C.char, failure *C.char, capacity C.size_t) C.int32_t {
	if input == nil || output == nil || cache == nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	if err := profile.PrepareFile(ctx, C.GoString(input), C.GoString(output), C.GoString(cache)); err != nil {
		writeError(failure, capacity, err.Error())
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
	}, failure, capacity)
}

func start(open func() (*packettunnel.Session, error), failure *C.char, capacity C.size_t) C.uint64_t {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if active.Load() != nil {
		return 0
	}
	// This library is linked only into the VPN extension process.
	runtime.GOMAXPROCS(2)
	debug.SetMemoryLimit(20 << 20)
	session, err := open()
	if err != nil {
		writeError(failure, capacity, err.Error())
		return 0
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
	var controls profile.Controls
	if data == nil || length == 0 || length > 64<<10 {
		return controls, false
	}
	err := json.Unmarshal(unsafe.Slice((*byte)(data), int(length)), &controls)
	return controls, err == nil
}

func writeError(failure *C.char, capacity C.size_t, description string) {
	if failure != nil && capacity > 1 && capacity <= 4096 {
		buffer := unsafe.Slice((*byte)(unsafe.Pointer(failure)), int(capacity))
		n := copy(buffer[:len(buffer)-1], description)
		buffer[n] = 0
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
	if session == nil || data == nil || length == 0 || length > packettunnel.MTU {
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
	output := unsafe.Slice((*byte)(data), int(count)*packettunnel.MTU)
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
