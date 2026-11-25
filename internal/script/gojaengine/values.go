package gojaengine

import (
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/script"
	"github.com/dop251/goja"
)

type primitives struct {
	stringValue goja.Callable
	stringify   goja.Callable
	isArray     goja.Callable
	isView      goja.Callable
	viewBuffer  goja.Callable
	typedBuffer goja.Callable
	uint8Array  goja.Constructor
	rangeError  goja.Constructor
}

func (s *session) capturePrimitives() {
	vm := s.vm
	object := vm.Get("Object").ToObject(vm)
	descriptor, _ := goja.AssertFunction(object.Get("getOwnPropertyDescriptor"))
	bufferGetter := func(proto *goja.Object) goja.Callable {
		prop := s.call(descriptor, proto, vm.ToValue("buffer")).ToObject(vm)
		get, _ := goja.AssertFunction(prop.Get("get"))
		return get
	}
	u8 := vm.Get("Uint8Array").ToObject(vm)
	p := &s.primitives
	p.uint8Array, _ = goja.AssertConstructor(u8)
	p.rangeError, _ = goja.AssertConstructor(vm.Get("RangeError"))
	p.stringValue, _ = goja.AssertFunction(vm.Get("String"))
	p.stringify, _ = goja.AssertFunction(vm.Get("JSON").ToObject(vm).Get("stringify"))
	p.isArray, _ = goja.AssertFunction(vm.Get("Array").ToObject(vm).Get("isArray"))
	p.isView, _ = goja.AssertFunction(vm.Get("ArrayBuffer").ToObject(vm).Get("isView"))
	p.typedBuffer = bufferGetter(u8.Get("prototype").ToObject(vm).Prototype())
	p.viewBuffer = bufferGetter(vm.Get("DataView").ToObject(vm).Get("prototype").ToObject(vm))
}

func absent(v goja.Value) bool {
	return v == nil || goja.IsUndefined(v) || goja.IsNull(v)
}

func (s *session) jsonString(v goja.Value) (string, bool) {
	encoded := s.call(s.primitives.stringify, v)
	if goja.IsUndefined(encoded) {
		return "", false
	}
	return encoded.String(), true
}

func (s *session) uint8Array(data []byte) goja.Value {
	value, err := s.primitives.uint8Array(nil, s.vm.ToValue(s.vm.NewArrayBuffer(data)))
	if err != nil {
		panic(err)
	}
	return value
}

// bytes borrows the native buffer or view range without converting elements.
func (s *session) bytes(v goja.Value) ([]byte, bool) {
	o, ok := v.(*goja.Object)
	if !ok {
		return nil, false
	}
	if o.ExportType() == reflect.TypeFor[goja.ArrayBuffer]() {
		return o.Export().(goja.ArrayBuffer).Bytes(), true
	}
	if !s.call(s.primitives.isView, v).ToBoolean() {
		return nil, false
	}
	buffer := s.primitives.viewBuffer
	if o.ExportType().Kind() == reflect.Slice {
		buffer = s.primitives.typedBuffer
	}
	if callWithThis(buffer, v).Export().(goja.ArrayBuffer).Detached() {
		// goja's byte-slice export assumes that view offsets remain valid.
		return nil, true
	}
	var data []byte
	if err := s.vm.ExportTo(v, &data); err != nil {
		panic(err)
	}
	return data, true
}

func (s *session) inputBody(data []byte) goja.Value {
	if s.job.Script.BinaryBody {
		return s.uint8Array(slices.Clone(data))
	}
	return s.vm.ToValue(string(data))
}

func (s *session) readBody(v goja.Value) []byte {
	if b, ok := s.bytes(v); ok {
		return slices.Clone(b)
	}
	return []byte(s.call(s.primitives.stringValue, v).String())
}

func (s *session) headers(fields []script.HeaderField, full bool) goja.Value {
	if full {
		items := make([]any, 0, len(fields))
		for _, field := range fields {
			item := s.vm.NewObject()
			s.set(item, "field", field.Name)
			s.set(item, "value", field.Value)
			items = append(items, item)
		}
		return s.vm.NewArray(items...)
	}

	// Surge's default mode does not preserve repeated header fields. Use the
	// first spelling as the object key and join values in arrival order.
	type mergedField struct {
		name   string
		values []string
	}
	merged := make([]mergedField, 0, len(fields))
	indices := make(map[string]int, len(fields))
	for _, field := range fields {
		key := strings.ToLower(field.Name)
		if index, present := indices[key]; present {
			merged[index].values = append(merged[index].values, field.Value)
			continue
		}
		indices[key] = len(merged)
		merged = append(merged, mergedField{field.Name, []string{field.Value}})
	}
	o := s.vm.NewObject()
	for _, field := range merged {
		v := s.vm.ToValue(strings.Join(field.values, ", "))
		if err := o.DefineDataProperty(field.name, v, goja.FLAG_TRUE, goja.FLAG_TRUE, goja.FLAG_TRUE); err != nil {
			panic(err)
		}
	}
	return o
}

func (s *session) readHeaders(v goja.Value) []script.HeaderField {
	o, ok := v.(*goja.Object)
	if !ok {
		return nil
	}
	var fields []script.HeaderField
	add := func(name string, value goja.Value) {
		fields = append(fields, script.HeaderField{Name: name, Value: s.call(s.primitives.stringValue, value).String()})
	}
	if s.call(s.primitives.isArray, o).ToBoolean() {
		s.arrayItems(o, func(v goja.Value) {
			if field, ok := v.(*goja.Object); ok {
				name, value := field.Get("field"), field.Get("value")
				if !absent(name) && value != nil {
					add(s.call(s.primitives.stringValue, name).String(), value)
				}
			}
		})
		return fields
	}
	for _, name := range o.Keys() {
		value := o.Get(name)
		if s.call(s.primitives.isArray, value).ToBoolean() {
			s.arrayItems(value.(*goja.Object), func(item goja.Value) { add(name, item) })
		} else {
			add(name, value)
		}
	}
	return fields
}

func (s *session) arrayItems(o *goja.Object, visit func(goja.Value)) {
	// Visit existing entries so a sparse array's length cannot hold up the loop.
	for _, key := range o.GetOwnPropertyNames() {
		if s.ctx.Err() != nil {
			return
		}
		index, err := strconv.ParseUint(key, 10, 32)
		if err == nil && index < 1<<32-1 && strconv.FormatUint(index, 10) == key {
			visit(o.Get(key))
		}
	}
}

func (s *session) readDone(v goja.Value) script.Done {
	done := script.Done{Called: true, HasValue: !absent(v)}
	o, ok := v.(*goja.Object)
	if !ok {
		return done
	}
	if v := o.Get("url"); !absent(v) {
		url := s.call(s.primitives.stringValue, v).String()
		done.URL = &url
	}
	if status, ok := readStatus(o); ok {
		done.Status = &status
	}
	if v := o.Get("headers"); !absent(v) {
		done.Headers, done.HeadersSet = s.readHeaders(v), true
	}
	if v := o.Get("body"); !absent(v) {
		done.Body, done.BodySet = s.readBody(v), true
	}
	if resp, ok := o.Get("response").(*goja.Object); ok {
		status, _ := readStatus(resp)
		done.Response = &script.Response{Status: status, Headers: s.readHeaders(resp.Get("headers"))}
		if v := resp.Get("body"); !absent(v) {
			done.Response.Body = s.readBody(v)
		}
	}
	if abort := o.Get("abort"); abort != nil {
		done.Abort = abort.StrictEquals(s.vm.ToValue(true))
	}
	return done
}

func readStatus(o *goja.Object) (int, bool) {
	v := o.Get("status")
	if absent(v) {
		v = o.Get("statusCode")
	}
	if absent(v) {
		return 0, false
	}
	if text, ok := v.(goja.String); ok && strings.HasPrefix(text.String(), "HTTP/") {
		// Some Surge scripts use a complete HTTP status line for an override.
		if parts := strings.Fields(text.String()); len(parts) > 1 {
			if status, err := strconv.Atoi(parts[1]); err == nil {
				return status, true
			}
		}
	}
	return int(v.ToInteger()), true
}
