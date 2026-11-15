//go:build android

// Command jni builds libreka.so, the JNI binding of mobile/core for
// org.mimoproxy.reka.Native. Build with mobile/android/build.sh.
package main

/*
#include <jni.h>
#include <stdlib.h>
#include <string.h>

static JavaVM *g_vm;

typedef struct {
	jobject host;
	jmethodID protect, seal, open, onMessage, findProcess;
} host_t;

static int init_vm(JNIEnv *env) {
	if (g_vm != NULL) return 1;
	return (*env)->GetJavaVM(env, &g_vm) == JNI_OK;
}

static host_t *new_host(JNIEnv *env, jobject host) {
	jclass cls = (*env)->GetObjectClass(env, host);
	host_t *h = calloc(1, sizeof(host_t));
	h->protect = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
	h->seal = (*env)->GetMethodID(env, cls, "seal", "([B)[B");
	h->open = (*env)->GetMethodID(env, cls, "open", "([B)[B");
	h->findProcess = (*env)->GetMethodID(env, cls, "findProcess", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
 if (!h->findProcess) (*env)->ExceptionClear(env);
 h->onMessage = (*env)->GetMethodID(env, cls, "onMessage", "(Ljava/lang/String;)V");
	(*env)->DeleteLocalRef(env, cls);
	if (!h->protect || !h->seal || !h->open || !h->onMessage) {
		(*env)->ExceptionClear(env);
		free(h);
		return NULL;
	}
	h->host = (*env)->NewGlobalRef(env, host);
	return h;
}

// attach returns a JNIEnv for the current thread; *attached is set when
// the thread had to be attached and must be detached afterwards.
static JNIEnv *attach(int *attached) {
	JNIEnv *env;
	*attached = 0;
	if ((*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) return env;
	if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) return NULL;
	*attached = 1;
	return env;
}

static void detach(int attached) {
	if (attached) (*g_vm)->DetachCurrentThread(g_vm);
}

static void free_host(host_t *h) {
	int attached;
	JNIEnv *env = attach(&attached);
	if (env) (*env)->DeleteGlobalRef(env, h->host);
	detach(attached);
	free(h);
}

static int host_protect(host_t *h, int fd) {
	int attached;
	JNIEnv *env = attach(&attached);
	if (!env) return 0;
	jboolean ok = (*env)->CallBooleanMethod(env, h->host, h->protect, (jint)fd);
	if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); ok = JNI_FALSE; }
	detach(attached);
	return ok == JNI_TRUE;
}

// host_bytes calls seal or open. It returns a malloc'd copy (free it) and
// its length, or NULL on failure.
static void *host_bytes(host_t *h, int which, const void *in, int n, int *outn) {
	int attached;
	JNIEnv *env = attach(&attached);
	void *out = NULL;
	if (!env) return NULL;
	jbyteArray arr = (*env)->NewByteArray(env, n);
	(*env)->SetByteArrayRegion(env, arr, 0, n, (const jbyte *)in);
	jbyteArray res = (jbyteArray)(*env)->CallObjectMethod(env, h->host, which ? h->open : h->seal, arr);
	if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); res = NULL; }
	if (res) {
		*outn = (*env)->GetArrayLength(env, res);
		out = malloc(*outn > 0 ? *outn : 1);
		(*env)->GetByteArrayRegion(env, res, 0, *outn, (jbyte *)out);
		(*env)->DeleteLocalRef(env, res);
	}
	(*env)->DeleteLocalRef(env, arr);
	detach(attached);
	return out;
}

static void host_message(host_t *h, const char *msg) {
	int attached;
	JNIEnv *env = attach(&attached);
	if (!env) return;
	jstring s = (*env)->NewStringUTF(env, msg);
	(*env)->CallVoidMethod(env, h->host, h->onMessage, s);
	if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
	(*env)->DeleteLocalRef(env, s);
	detach(attached);
}

static char *host_find_process(host_t *h, const char *network, const char *source, const char *destination) {
 if (!h->findProcess) return NULL;
 int attached; JNIEnv *env = attach(&attached); if (!env) return NULL;
 jstring n=(*env)->NewStringUTF(env,network), s=(*env)->NewStringUTF(env,source), d=(*env)->NewStringUTF(env,destination);
 jstring result=(*env)->CallObjectMethod(env,h->host,h->findProcess,n,s,d);char *out=NULL;
 if ((*env)->ExceptionCheck(env)) {(*env)->ExceptionClear(env);result=NULL;}
 if (result) {const char *v=(*env)->GetStringUTFChars(env,result,NULL);if(v){out=strdup(v);(*env)->ReleaseStringUTFChars(env,result,v);}(*env)->DeleteLocalRef(env,result);}
 (*env)->DeleteLocalRef(env,n);(*env)->DeleteLocalRef(env,s);(*env)->DeleteLocalRef(env,d);detach(attached);return out;
}

static const char *get_utf(JNIEnv *env, jstring s) { return s ? (*env)->GetStringUTFChars(env, s, NULL) : NULL; }
static void release_utf(JNIEnv *env, jstring s, const char *c) { if (s) (*env)->ReleaseStringUTFChars(env, s, c); }
static jstring new_utf(JNIEnv *env, const char *c) { return (*env)->NewStringUTF(env, c); }
*/
import "C"

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"
	"unsafe"

	"github.com/MimoProxy/reka/mobile/core"
)

func main() {}

type jniHost struct {
	h      *C.host_t
	mu     sync.RWMutex
	closed bool
}

func (j *jniHost) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.closed {
		j.closed = true
		C.free_host(j.h)
	}
}

func (j *jniHost) FindProcess(network, source, destination string) string {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if j.closed {
		return ""
	}
	n, s, d := C.CString(network), C.CString(source), C.CString(destination)
	defer C.free(unsafe.Pointer(n))
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(d))
	v := C.host_find_process(j.h, n, s, d)
	if v == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(v))
	return C.GoString(v)
}

func (j *jniHost) Protect(fd int) bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return !j.closed && C.host_protect(j.h, C.int(fd)) != 0
}

func (j *jniHost) bytes(which int, in []byte) ([]byte, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if j.closed {
		return nil, errors.New("host closed")
	}
	var p unsafe.Pointer
	if len(in) > 0 {
		p = unsafe.Pointer(&in[0])
	}
	var n C.int
	out := C.host_bytes(j.h, C.int(which), p, C.int(len(in)), &n)
	if out == nil {
		return nil, errors.New("host cipher failed")
	}
	defer C.free(out)
	return C.GoBytes(out, n), nil
}

func (j *jniHost) Seal(p []byte) ([]byte, error) { return j.bytes(0, p) }
func (j *jniHost) Open(p []byte) ([]byte, error) { return j.bytes(1, p) }
func (j *jniHost) OnMessage(b []byte) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if j.closed {
		return
	}
	c := C.CString(string(b))
	defer C.free(unsafe.Pointer(c))
	C.host_message(j.h, c)
}

var (
	mu        sync.Mutex
	instances = map[int64]*instance{}
	nextID    int64
	lastErr   string
)

type instance struct {
	in   *core.Instance
	host *jniHost
}

func goString(env *C.JNIEnv, s C.jstring) string {
	c := C.get_utf(env, s)
	if c == nil {
		return ""
	}
	defer C.release_utf(env, s, c)
	return C.GoString(c)
}

func jstr(env *C.JNIEnv, s string) C.jstring {
	c := C.CString(s)
	defer C.free(unsafe.Pointer(c))
	return C.new_utf(env, c)
}

//export Java_org_mimoproxy_reka_Native_start
func Java_org_mimoproxy_reka_Native_start(env *C.JNIEnv, _ C.jclass, jroot, jprofile, jlocal C.jstring, jhost C.jobject) C.jlong {
	return startJNI(env, jroot, jprofile, jlocal, jhost, 0)
}

//export Java_org_mimoproxy_reka_Native_startVPN
func Java_org_mimoproxy_reka_Native_startVPN(env *C.JNIEnv, _ C.jclass, jroot, jprofile, jlocal C.jstring, jhost C.jobject, fd C.jint) C.jlong {
	return startJNI(env, jroot, jprofile, jlocal, jhost, int(fd))
}
func startJNI(env *C.JNIEnv, jroot, jprofile, jlocal C.jstring, jhost C.jobject, fd int) C.jlong {
	fail := func(err error) C.jlong {
		mu.Lock()
		lastErr = err.Error()
		mu.Unlock()
		return 0
	}
	if C.init_vm(env) == 0 {
		return fail(errors.New("GetJavaVM failed"))
	}
	h := C.new_host(env, jhost)
	if h == nil {
		return fail(errors.New("host object lacks protect, seal, open or onMessage"))
	}
	opts := core.Options{TUNFD: fd, StateRoot: goString(env, jroot), Logger: slog.Default()}
	if p := goString(env, jprofile); p != "" {
		opts.InitialProfile = []byte(p)
	}
	if l := goString(env, jlocal); l != "" {
		opts.InitialLocal = []byte(l)
	}
	host := &jniHost{h: h}
	in, err := core.Start(opts, host)
	if err != nil {
		host.Close()
		return fail(err)
	}
	mu.Lock()
	nextID++
	id := nextID
	instances[id] = &instance{in: in, host: host}
	mu.Unlock()
	return C.jlong(id)
}

//export Java_org_mimoproxy_reka_Native_lastError
func Java_org_mimoproxy_reka_Native_lastError(env *C.JNIEnv, _ C.jclass) C.jstring {
	mu.Lock()
	defer mu.Unlock()
	return jstr(env, lastErr)
}

//export Java_org_mimoproxy_reka_Native_call
func Java_org_mimoproxy_reka_Native_call(env *C.JNIEnv, _ C.jclass, handle C.jlong, jreq C.jstring) C.jstring {
	mu.Lock()
	inst := instances[int64(handle)]
	mu.Unlock()
	if inst == nil {
		return jstr(env, `{"error":{"code":"internal","message":"kernel not running"}}`)
	}
	return jstr(env, string(inst.in.Call([]byte(goString(env, jreq)))))
}

//export Java_org_mimoproxy_reka_Native_stop
func Java_org_mimoproxy_reka_Native_stop(env *C.JNIEnv, _ C.jclass, handle C.jlong) {
	mu.Lock()
	inst := instances[int64(handle)]
	delete(instances, int64(handle))
	mu.Unlock()
	if inst != nil {
		inst.in.Stop()
		inst.host.Close()
	}
}

//export Java_org_mimoproxy_reka_Native_memStats
func Java_org_mimoproxy_reka_Native_memStats(env *C.JNIEnv, _ C.jclass) C.jstring {
	runtime.GC()
	debug.FreeOSMemory()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return jstr(env, fmt.Sprintf(`{"sys_mb":%.1f,"heap_inuse_mb":%.1f,"goroutines":%d}`,
		float64(ms.Sys)/(1<<20), float64(ms.HeapInuse)/(1<<20), runtime.NumGoroutine()))
}

//export Java_org_mimoproxy_reka_Native_reconfigureVPN
func Java_org_mimoproxy_reka_Native_reconfigureVPN(env *C.JNIEnv, _ C.jclass, handle C.jlong, fd C.jint, request C.jstring) C.jstring {
	mu.Lock()
	in := instances[int64(handle)]
	mu.Unlock()
	if in == nil {
		return jstr(env, `{"error":{"code":"closed","message":"unknown instance"}}`)
	}
	return jstr(env, string(in.in.ReconfigureVPN(int(fd), []byte(goString(env, request)))))
}
