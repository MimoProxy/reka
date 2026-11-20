//go:build ios && cgo && with_gvisor

package main

/*
#include <stdint.h>
*/
import "C"

import (
	"encoding/json"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/MimoProxy/reka/mobile/packettunnel"
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
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if active.Load() != nil {
		return 0
	}
	// This library is linked only into the VPN extension process.
	runtime.GOMAXPROCS(2)
	debug.SetMemoryLimit(20 << 20)
	session, err := packettunnel.Start(node)
	if err != nil {
		return 0
	}
	lastID++
	active.Store(&runningTunnel{id: lastID, session: session})
	return C.uint64_t(lastID)
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
