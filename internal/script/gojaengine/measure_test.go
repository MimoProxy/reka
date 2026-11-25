package gojaengine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/internal/script/gojaengine"
)

type corpusSample struct {
	file, url string
	kind      script.Kind
	binary    bool
	argument  string
}

var corpusSamples = []corpusSample{
	{"maasea-youtube.response.js", "https://youtubei.googleapis.com/youtubei/v1/browse?prettyPrint=false", script.KindHTTPResponse, true, `{"captionLang":"off","lyricLang":"off","blockUpload":true,"blockImmersive":true,"debug":false}`},
	{"maasea-youtube.request.js", "https://youtubei.googleapis.com/youtubei/v1/log_event?alt=json", script.KindHTTPRequest, true, `{"captionLang":"off"}`},
	{"maasea-bilibili.helper.js", "https://grpc.biliapi.net/bilibili.app.dynamic.v2.Dynamic/DynAll", script.KindHTTPResponse, true, ""},
	{"kokoryh-bilibili.protobuf.response.js", "https://grpc.biliapi.net/bilibili.app.dynamic.v2.Dynamic/DynAll", script.KindHTTPResponse, true, `{"displayUpList":"auto"}`},
	{"biliuniverse-adblock.response.bundle.js", "https://grpc.biliapi.net/bilibili.main.community.reply.v1.Reply/MainList", script.KindHTTPResponse, true, ""},
	{"dualsubs-youtube.response.bundle.js", "https://youtubei.googleapis.com/youtubei/v1/player?prettyPrint=false", script.KindHTTPResponse, true, ""},
	{"app2smile-tieba-proto.js", "https://tiebac.baidu.com/c/f/frs/page?cmd=301001", script.KindHTTPResponse, true, "per_filter_video_thread=true"},
	{"keywos-wyres.js", "https://interface.music.163.com/eapi/batch", script.KindHTTPResponse, true, `{"MY":"true","PRGG":"true"}`},
	{"app2smile-zhihu.js", "https://api.zhihu.com/topstory/recommend", script.KindHTTPResponse, false, ""},
}

func corpusInput(sample corpusSample, size int) *script.Input {
	in := testInput(sample.kind)
	in.Request.URL = sample.url
	contentType := "application/json"
	if sample.binary {
		contentType = "application/x-protobuf"
	}
	grpc := strings.Contains(sample.url, "biliapi.net")
	headers := []script.HeaderField{{Name: "Content-Type", Value: contentType}}
	in.Request.Headers = headers
	body := corpusBody(size, sample.binary, grpc)
	if in.Response != nil {
		in.Response.Headers, in.Response.Body = headers, body
	} else {
		in.Request.Body = body
	}
	return in
}

func corpusBody(size int, isBinary, grpc bool) []byte {
	if size == 0 {
		return nil
	}
	if !isBinary {
		var body strings.Builder
		title := strings.Repeat("t", 200)
		body.WriteString(`{"data":[`)
		for i := 0; body.Len() < size; i++ {
			if i > 0 {
				body.WriteByte(',')
			}
			fmt.Fprintf(&body, `{"id":%d,"type":"feed","target":{"title":"%s"}}`, i, title)
		}
		body.WriteString(`],"paging":{"is_end":true}}`)
		return []byte(body.String())
	}

	// Populate a valid protobuf message with an unknown length-delimited field.
	chunk := bytes.Repeat([]byte{'x'}, 1000)
	field := binary.AppendUvarint(nil, 15000<<3|2)
	field = binary.AppendUvarint(field, uint64(len(chunk)))
	field = append(field, chunk...)
	body := bytes.Repeat(field, (size+len(field)-1)/len(field))
	if !grpc {
		return body
	}
	frame := make([]byte, 5, 5+len(body))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(body)))
	return append(frame, body...)
}

func liveHeapBytes() uint64 {
	samples := [1]metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(samples[:])
	return samples[0].Value.Uint64()
}

// peakLiveHeap samples live heap growth above the settled baseline.
func peakLiveHeap(run func()) uint64 {
	runtime.GC()
	base := liveHeapBytes()
	peak := base
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(500 * time.Microsecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				peak = max(peak, liveHeapBytes())
			}
		}
	}()
	run()
	final := liveHeapBytes()
	close(stop)
	<-done
	return max(peak, final) - base
}

// Set REKA_SCRIPT_DIR to measure scripts from a local corpus.
func TestMeasureScripts(t *testing.T) {
	dir := os.Getenv("REKA_SCRIPT_DIR")
	if dir == "" {
		t.Skip("REKA_SCRIPT_DIR is unset")
	}
	sizes := []int{0, 64 << 10, 512 << 10, 2 << 20}
	if value := os.Getenv("REKA_SIZE_KIB"); value != "" {
		size, err := strconv.Atoi(value)
		if err != nil || size < 0 || int64(size) > script.DefaultLimits().HardMaxSize/(1<<10) {
			t.Fatalf("invalid REKA_SIZE_KIB %q", value)
		}
		sizes = []int{size << 10}
	}
	only := os.Getenv("REKA_ONLY")
	for _, sample := range corpusSamples {
		if only != "" && !strings.Contains(sample.file, only) {
			continue
		}
		t.Run(sample.file, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join(dir, sample.file))
			if err != nil {
				t.Fatal(err)
			}
			spec := script.Script{
				Name: sample.file, Path: sample.file, Source: string(source), Kind: sample.kind, BinaryBody: sample.binary,
				Timeout: 10 * time.Second,
			}
			if sample.argument != "" {
				spec.Argument = &sample.argument
			}
			start := time.Now()
			err = gojaengine.Check(spec.Name, spec.Source)
			compileTime := time.Since(start)
			t.Logf("source %.1f KiB, compile %v", float64(len(source))/1024, compileTime.Round(time.Microsecond))
			if err != nil {
				t.Logf("compile error: %v", err)
				return
			}
			host := newTestHost(t, script.Limits{BreakerFailures: 2*len(sizes) + 1}, script.Environment{})
			for _, size := range sizes {
				in := corpusInput(sample, size)
				_, _ = host.Run(context.Background(), &spec, in, script.Services{})
				var result script.Result
				var runErr error
				var elapsed time.Duration
				peak := peakLiveHeap(func() {
					start := time.Now()
					result, runErr = host.Run(context.Background(), &spec, in, script.Services{})
					elapsed = time.Since(start)
				})
				outBytes := len(result.Body)
				if result.Response != nil {
					outBytes = len(result.Response.Body)
				}
				t.Logf("body %d KiB, run %v, heap peak +%.2f MiB, output %.1f KiB, action %v, error %v",
					size>>10, elapsed.Round(time.Microsecond), float64(peak)/(1<<20), float64(outBytes)/1024,
					result.Action, runErr)
			}
		})
	}
}
