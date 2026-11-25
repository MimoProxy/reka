package api

import (
	"encoding/json"
	"errors"
	"net"
	"sync"

	"github.com/MimoProxy/reka/internal/config/module"
)

// Client is a control API client. Calls may be made concurrently; events
// arrive on Events once subscribed.
type Client struct {
	conn    net.Conn
	wmu     sync.Mutex
	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan Message
	err     error
	Events  chan Event
	Hello   HelloResult
	done    chan struct{}
}

// Connect dials addr and says Hello.
func Connect(addr, name string) (*Client, error) {
	conn, err := Dial(addr)
	if err != nil {
		return nil, err
	}
	return NewClient(conn, name)
}

// NewClient starts a client on an established connection.
func NewClient(conn net.Conn, name string) (*Client, error) {
	c := &Client{conn: conn, pending: map[uint64]chan Message{}, Events: make(chan Event, 256), done: make(chan struct{})}
	go c.read()
	if err := c.Call("Hello", HelloParams{Versions: []int{APIVersion}, Client: name}, &c.Hello); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) read() {
	defer close(c.done)
	defer close(c.Events)
	var dropped uint64
	for {
		frame, err := ReadFrame(c.conn)
		if err != nil {
			c.mu.Lock()
			c.err = err
			for id, ch := range c.pending {
				close(ch)
				delete(c.pending, id)
			}
			c.mu.Unlock()
			return
		}
		var m Message
		if json.Unmarshal(frame, &m) != nil {
			continue
		}
		if m.Event != nil {
			select {
			case c.Events <- withDropped(*m.Event, dropped):
				dropped = 0
			default: // the caller is not reading events
				dropped += 1 + m.Event.Dropped
			}
			continue
		}
		c.mu.Lock()
		ch := c.pending[m.ID]
		delete(c.pending, m.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
}

// ErrClosed is returned for calls on a closed connection.
var ErrClosed = errors.New("api: connection closed")

// Call sends a request and decodes the result into out (may be nil). A
// server-side error is returned as *Error.
func (c *Client) Call(method string, params, out any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return ErrClosed
	}
	c.nextID++
	id := c.nextID
	ch := make(chan Message, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	b, _ := json.Marshal(Request{ID: id, Method: method, Params: raw})
	c.wmu.Lock()
	err = WriteFrame(c.conn, b)
	c.wmu.Unlock()
	if err != nil {
		_ = c.conn.Close() // read loop fails every pending call and releases its map entry
		return err
	}
	m, ok := <-ch
	if !ok {
		return ErrClosed
	}
	if m.Error != nil {
		return m.Error
	}
	if out != nil && len(m.Result) > 0 {
		return json.Unmarshal(m.Result, out)
	}
	return nil
}

func (c *Client) AddModule(req AddModuleRequest) (Result, error) {
	var result Result
	err := c.Call("AddModule", req, &result)
	return result, err
}

func (c *Client) RemoveModule(req RemoveModuleRequest) (Result, error) {
	var result Result
	err := c.Call("RemoveModule", req, &result)
	return result, err
}

func (c *Client) SetModuleEnabled(req SetModuleEnabledRequest) (Result, error) {
	var result Result
	err := c.Call("SetModuleEnabled", req, &result)
	return result, err
}

func (c *Client) SetModuleArguments(req SetModuleArgumentsRequest) (Result, error) {
	var result Result
	err := c.Call("SetModuleArguments", req, &result)
	return result, err
}

func (c *Client) RefreshModule(req RefreshModuleRequest) (ModuleStatus, error) {
	var status ModuleStatus
	err := c.Call("RefreshModule", req, &status)
	return status, err
}

func (c *Client) ListModules() ([]ModuleInfo, error) {
	var modules []ModuleInfo
	err := c.Call("ListModules", nil, &modules)
	return modules, err
}

func (c *Client) ListScripts() (ScriptList, error) {
	var list ScriptList
	err := c.Call("ListScripts", nil, &list)
	return list, err
}

func (c *Client) RunScript(req RunScriptRequest) (ScriptRun, error) {
	var run ScriptRun
	err := c.Call("RunScript", req, &run)
	return run, err
}

func (c *Client) GetScriptRuns(req GetScriptRunsRequest) ([]ScriptRun, error) {
	var runs []ScriptRun
	err := c.Call("GetScriptRuns", req, &runs)
	return runs, err
}

func (c *Client) GetModuleReport(req GetModuleReportRequest) (module.Report, error) {
	var report module.Report
	err := c.Call("GetModuleReport", req, &report)
	return report, err
}

func (c *Client) PreviewModule(req PreviewModuleRequest) (module.Report, error) {
	var report module.Report
	err := c.Call("PreviewModule", req, &report)
	return report, err
}

// Close closes the connection.
func (c *Client) Close() error {
	err := c.conn.Close()
	<-c.done
	return err
}

func withDropped(ev Event, n uint64) Event {
	ev.Dropped += n
	return ev
}
