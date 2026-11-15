// Command tunprobe-android is the Go half of the Android TUN probe: a
// c-shared library loaded by the probe app. Native.run receives the TUN fd
// from VpnService.Builder.establish() and the VpnService itself, whose
// protect(int) is called for every relay socket so it leaves the VPN.
//
// Build with tools/tunprobe-android/build.sh.
package main

/*
#include <jni.h>
#include <stdlib.h>

static JavaVM *g_vm;
static jobject g_service;
static jmethodID g_protect;

static int setup(JNIEnv *env, jobject service) {
	if ((*env)->GetJavaVM(env, &g_vm) != JNI_OK) return 0;
	g_service = (*env)->NewGlobalRef(env, service);
	jclass cls = (*env)->GetObjectClass(env, service);
	g_protect = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
	(*env)->DeleteLocalRef(env, cls);
	return g_protect != NULL;
}

static void teardown(JNIEnv *env) {
	if (g_service != NULL) {
		(*env)->DeleteGlobalRef(env, g_service);
		g_service = NULL;
	}
}

// do_protect may run on any Go thread, so it attaches to the JVM if needed.
static int do_protect(int fd) {
	JNIEnv *env;
	int attached = 0;
	if ((*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
		if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) return 0;
		attached = 1;
	}
	jboolean ok = (*env)->CallBooleanMethod(env, g_service, g_protect, (jint)fd);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		ok = JNI_FALSE;
	}
	if (attached) (*g_vm)->DetachCurrentThread(g_vm);
	return ok == JNI_TRUE;
}

static const char *get_utf(JNIEnv *env, jstring s) { return (*env)->GetStringUTFChars(env, s, NULL); }
static void release_utf(JNIEnv *env, jstring s, const char *c) { (*env)->ReleaseStringUTFChars(env, s, c); }
static jstring new_utf(JNIEnv *env, const char *c) { return (*env)->NewStringUTF(env, c); }
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
	"unsafe"

	"github.com/MimoProxy/reka/internal/backend/sagernet/tunprobe"
)

func main() {}

// lockedBuffer collects logs for the report (stderr goes nowhere on Android).
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.Len() < 64<<10 {
		l.b.Write(p)
	}
	return len(p), nil
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

//export Java_org_mimoproxy_reka_probe_Native_run
func Java_org_mimoproxy_reka_probe_Native_run(env *C.JNIEnv, _ C.jclass, service C.jobject, fd C.jint, jstack C.jstring, holdSeconds C.jint) C.jstring {
	cstack := C.get_utf(env, jstack)
	stack := C.GoString(cstack)
	C.release_utf(env, jstack, cstack)
	out := run(env, service, int(fd), stack, time.Duration(holdSeconds)*time.Second)
	cout := C.CString(out)
	defer C.free(unsafe.Pointer(cout))
	return C.new_utf(env, cout)
}

func run(env *C.JNIEnv, service C.jobject, fd int, stack string, hold time.Duration) string {
	if C.setup(env, service) == 0 {
		return "FAIL: VpnService.protect(int) not found"
	}
	defer C.teardown(env)

	logs := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	targets := tunprobe.DefaultTargets()
	start := time.Now()
	p, err := tunprobe.Start(tunprobe.Options{
		Stack:          stack,
		Inet4Address:   netip.MustParsePrefix("172.19.0.1/30"),
		Inet6Address:   netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
		MTU:            9000,
		FileDescriptor: fd,
		Protect:        func(fd int) bool { return C.do_protect(C.int(fd)) != 0 },
		Logger:         log,
	})
	if err != nil {
		return "FAIL: start: " + err.Error() + "\n" + logs.String()
	}
	up := time.Since(start)
	time.Sleep(500 * time.Millisecond)
	r := p.Run(targets)
	r.Checks = append([]tunprobe.Check{{Name: "tun up (VpnService fd)", OK: true, Detail: fmt.Sprintf("fd %d", fd), Duration: up.Round(time.Millisecond).String()}}, r.Checks...)

	// Idle memory: let the stack sit with no traffic, then measure.
	time.Sleep(hold)
	runtime.GC()
	debug.FreeOSMemory()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	idle := fmt.Sprintf("  idle after %s: go sys %.1f MB, heap in use %.1f MB, goroutines %d\n",
		hold, float64(ms.Sys)/(1<<20), float64(ms.HeapInuse)/(1<<20), runtime.NumGoroutine())
	p.Close()

	js, _ := json.Marshal(r)
	text := r.String() + idle
	if l := logs.String(); l != "" {
		text += "logs:\n" + l
	}
	return text + "JSON " + string(js) + "\n"
}
