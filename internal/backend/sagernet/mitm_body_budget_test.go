package sagernet

import (
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/MimoProxy/reka/internal/script"
)

func TestMITMBodyBudgetPassthrough(t *testing.T) {
	budget := mitmBodyBudget{limit: 8}
	first, err := budget.buffer(io.NopCloser(strings.NewReader("body")), 4, 7)
	if err != nil || first.exceeds(7) || string(first.data) != "body" {
		t.Fatalf("first buffer = %q, error %v", first.data, err)
	}

	original := io.NopCloser(strings.NewReader("another"))
	second, err := budget.buffer(original, -1, 7)
	if err != nil || !second.exceeds(7) || second.reader != original {
		t.Fatalf("budget exhaustion = %+v, error %v", second, err)
	}
	_, err = (mitmScriptInput{}).scriptInput(&MITMScript{RequiresBody: true, MaxSize: 7}, second)
	if !errors.Is(err, script.ErrBodyTooLarge) {
		t.Fatalf("script input error = %v", err)
	}
	data, err := io.ReadAll(second.reader)
	if err != nil || string(data) != "another" {
		t.Fatalf("forwarded body = %q, error %v", data, err)
	}

	first.releaseBudget()
	next, err := budget.buffer(io.NopCloser(strings.NewReader("another")), -1, 7)
	defer next.releaseBudget()
	if err != nil || next.exceeds(7) || string(next.data) != "another" {
		t.Fatalf("buffer after release = %q, error %v", next.data, err)
	}
}

func TestMITMBodyBudgetConcurrentRelease(t *testing.T) {
	const (
		streams = 20
		slots   = 4
		bytes   = 32
	)
	budget := mitmBodyBudget{limit: slots * bytes}
	start := make(chan struct{})
	results := make(chan mitmBufferedBody, streams)
	for range streams {
		go func() {
			<-start
			buffer, err := budget.buffer(io.NopCloser(strings.NewReader("body")), -1, bytes-1)
			if err != nil {
				t.Error(err)
			}
			results <- buffer
		}()
	}
	close(start)

	var buffered []mitmBufferedBody
	for range streams {
		if result := <-results; !result.truncated {
			buffered = append(buffered, result)
		}
	}
	if len(buffered) != slots || budget.used.Load() != budget.limit {
		t.Fatalf("buffered %d streams, reserved %d bytes", len(buffered), budget.used.Load())
	}

	var releases sync.WaitGroup
	for _, buffer := range buffered {
		releases.Go(buffer.releaseBudget)
	}
	releases.Wait()
	if budget.used.Load() != 0 || !budget.reserve(budget.limit) {
		t.Fatalf("budget still held after parallel releases: %d", budget.used.Load())
	}
}

func TestMITMBodyBudgetReleasesOnReadError(t *testing.T) {
	budget := mitmBodyBudget{limit: 8}
	body := io.NopCloser(iotest.ErrReader(io.ErrUnexpectedEOF))
	_, err := budget.buffer(body, -1, 7)
	if !errors.Is(err, io.ErrUnexpectedEOF) || budget.used.Load() != 0 {
		t.Fatalf("read error %v left %d bytes reserved", err, budget.used.Load())
	}
}

func TestMITMBodyBudgetGrowsWithUnknownLength(t *testing.T) {
	budget := mitmBodyBudget{limit: 4 << 10}
	small, err := budget.buffer(io.NopCloser(strings.NewReader("body")), -1, 1<<20)
	if err != nil || small.exceeds(1<<20) || string(small.data) != "body" {
		t.Fatalf("small buffer = %q, error %v", small.data, err)
	}
	if used := budget.used.Load(); used > 512 {
		t.Fatalf("small body without a length reserved %d bytes", used)
	}

	// The budget runs out partway through a body that fits the size limit.
	payload := strings.Repeat("x", 8<<10)
	large, err := budget.buffer(io.NopCloser(strings.NewReader(payload)), -1, 1<<20)
	if err != nil || !large.exceeds(1<<20) {
		t.Fatalf("budget exhaustion during read = %+v, error %v", large.truncated, err)
	}
	data, err := io.ReadAll(large.reader)
	if err != nil || string(data) != payload {
		t.Fatalf("forwarded %d bytes, error %v", len(data), err)
	}
	small.releaseBudget()
	large.releaseBudget()
	if used := budget.used.Load(); used != 0 {
		t.Fatalf("budget still holds %d bytes", used)
	}
}
