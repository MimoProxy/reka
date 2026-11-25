package gojaengine

import (
	"container/list"
	"context"
	"crypto/sha256"
	"sync"

	"github.com/MimoProxy/reka/internal/script"
	"github.com/dop251/goja"
	"github.com/dop251/goja/parser"
)

func compile(name, source string) (*goja.Program, error) {
	// Source maps are unnecessary for script execution and can reference local files.
	ast, err := goja.Parse(name, source, parser.WithDisableSourceMaps)
	if err != nil {
		return nil, err
	}
	return goja.CompileAST(ast, false)
}

type programKey struct {
	key string
	// An explicit key can be reused when the source at a script path changes.
	revision [sha256.Size]byte
}

type cachedProgram struct {
	key     programKey
	program *goja.Program
	weight  int64
}

type compilation struct {
	ready   chan struct{}
	program *goja.Program
	err     error
}

type programCache struct {
	mu        sync.Mutex
	lru       list.List
	entries   map[programKey]*list.Element
	flights   map[programKey]*compilation
	bytes     int64
	compiling int
	space     chan struct{}
	compile   func(name, source string) (*goja.Program, error)
}

func (c *programCache) get(ctx context.Context, s *script.Script, limits script.Limits) (*goja.Program, error) {
	key := programKey{key: s.CacheKey()}
	if s.Key != "" {
		key.revision = sha256.Sum256([]byte(s.Source))
	}
	for ctx.Err() == nil {
		c.mu.Lock()
		c.trim(limits.CacheBytes)
		if elem := c.entries[key]; elem != nil {
			c.lru.MoveToFront(elem)
			p := elem.Value.(cachedProgram).program
			c.mu.Unlock()
			return p, nil
		}
		f := c.flights[key]
		if f == nil && c.compiling >= limits.Concurrency {
			// The parser cannot be interrupted. Keep active compilations bounded
			// even when callers repeatedly leave early on deadline.
			if c.space == nil {
				c.space = make(chan struct{})
			}
			space := c.space
			c.mu.Unlock()
			select {
			case <-ctx.Done():
			case <-space:
			}
			continue
		}
		if f == nil {
			f = &compilation{ready: make(chan struct{})}
			if c.flights == nil {
				c.flights = make(map[programKey]*compilation)
			}
			c.flights[key] = f
			c.compiling++
			go c.fill(key, f, s.Name, s.Source, limits.CacheBytes)
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.ready:
			return f.program, f.err
		}
	}
	return nil, ctx.Err()
}

func (c *programCache) fill(key programKey, f *compilation, name, source string, budget int64) {
	compiler := c.compile
	if compiler == nil {
		compiler = compile
	}
	f.program, f.err = compiler(name, source)

	c.mu.Lock()
	defer c.mu.Unlock()
	defer close(f.ready)
	c.compiling--
	if c.space != nil {
		close(c.space)
		c.space = nil
	}
	if c.flights[key] != f {
		// A purge occurred during compilation. Existing waiters still get the result.
		return
	}
	delete(c.flights, key)
	// Account for empty programs as well so explicit keys cannot add free entries.
	weight := max(1, int64(len(source))) * 10
	if f.err != nil || weight > budget {
		return
	}
	c.trim(budget - weight)
	if c.entries == nil {
		c.entries = make(map[programKey]*list.Element)
	}
	c.entries[key] = c.lru.PushFront(cachedProgram{key: key, program: f.program, weight: weight})
	c.bytes += weight
}

func (c *programCache) trim(budget int64) {
	for c.bytes > budget {
		elem := c.lru.Back()
		entry := elem.Value.(cachedProgram)
		c.bytes -= entry.weight
		delete(c.entries, entry.key)
		c.lru.Remove(elem)
	}
}

func (c *programCache) purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Init()
	c.entries = nil
	c.flights = nil
	c.bytes = 0
}
