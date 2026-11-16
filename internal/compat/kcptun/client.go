package kcptun

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/metacubex/kcp-go"
	"github.com/sagernet/smux"
)

type DialFunc func(context.Context) (net.PacketConn, net.Addr, error)
type carrier struct {
	session           *smux.Session
	expires, retireAt time.Time
}
type Client struct {
	config  Config
	block   kcp.BlockCrypt
	dial    DialFunc
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	keep    bool
	slots   []*carrier
	retired []*carrier
	next    int
}

func NewClient(config Config, dial DialFunc) (*Client, error) {
	if err := config.Normalize(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{config: config, block: config.NewBlock(), dial: dial, ctx: ctx, cancel: cancel, slots: make([]*carrier, config.Conn), keep: true}
	go c.scavenge()
	return c, nil
}
func (c *Client) create(ctx context.Context) (*carrier, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	pc, addr, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			pc.Close()
		}
	}()
	stopPC := context.AfterFunc(ctx, func() { pc.Close() })
	defer stopPC()
	cfg := c.config
	conn, err := kcp.NewConn4(rand.Uint32(), addr, c.block, cfg.DataShard, cfg.ParityShard, true, pc)
	if err != nil {
		return nil, err
	}
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetNoDelay(cfg.NoDelay, cfg.Interval, cfg.Resend, cfg.NoCongestion)
	conn.SetWindowSize(cfg.SndWnd, cfg.RcvWnd)
	conn.SetMtu(cfg.MTU)
	conn.SetACKNoDelay(cfg.AckNodelay)
	conn.SetRateLimit(uint32(cfg.RateLimit))
	conn.SetDSCP(cfg.DSCP)
	conn.SetReadBuffer(cfg.SockBuf)
	conn.SetWriteBuffer(cfg.SockBuf)
	mux := smux.DefaultConfig()
	mux.Version = cfg.SmuxVer
	mux.MaxReceiveBuffer = cfg.SmuxBuf
	mux.MaxStreamBuffer = cfg.StreamBuf
	mux.MaxFrameSize = cfg.FrameSize
	mux.KeepAliveInterval = time.Duration(cfg.KeepAlive) * time.Second
	if mux.KeepAliveInterval >= mux.KeepAliveTimeout {
		mux.KeepAliveTimeout = 3 * mux.KeepAliveInterval
	}
	var stream net.Conn = conn
	if !cfg.NoComp {
		stream = NewCompStream(conn)
	}
	session, err := smux.Client(stream, mux)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		session.Close()
		return nil, err
	}
	failed = false
	return &carrier{session: session, expires: time.Now().Add(time.Duration(cfg.AutoExpire) * time.Second)}, nil
}
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	closeCarriers(c.take(false, false))
	index := c.next % len(c.slots)
	c.next = (c.next + 1) % len(c.slots)
	item := c.slots[index]
	if item == nil || item.session.IsClosed() || c.config.AutoExpire > 0 && time.Now().After(item.expires) {
		if item != nil && !item.session.IsClosed() {
			if len(c.retired) >= 256 {
				return nil, errors.New("kcptun retired carrier budget exhausted")
			}
			item.retireAt = item.expires.Add(time.Duration(c.config.ScavengeTTL) * time.Second)
			c.retired = append(c.retired, item)
		}
		c.slots[index] = nil
		var err error
		item, err = c.create(ctx)
		if err != nil {
			return nil, err
		}
		c.slots[index] = item
	}
	stream, err := item.session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &pooledConn{Conn: stream, owner: c}, nil
}

type pooledConn struct {
	net.Conn
	owner *Client
	once  sync.Once
	err   error
}

func (c *pooledConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.owner.prune(false) })
	return c.err
}
func (c *Client) take(all, forceIdle bool) []*carrier {
	var closeList []*carrier
	for i, item := range c.slots {
		if item != nil && (all || (!c.keep || forceIdle) && item.session.NumStreams() == 0) {
			closeList = append(closeList, item)
			c.slots[i] = nil
		}
	}
	retained := c.retired[:0]
	for _, item := range c.retired {
		if all || item.session.NumStreams() == 0 || time.Now().After(item.retireAt) {
			closeList = append(closeList, item)
		} else {
			retained = append(retained, item)
		}
	}
	c.retired = retained
	return closeList
}
func closeCarriers(items []*carrier) error {
	var errs []error
	for _, item := range items {
		errs = append(errs, item.session.Close())
	}
	return errors.Join(errs...)
}
func (c *Client) Close() error {
	c.cancel()
	c.mu.Lock()
	c.closed = true
	items := c.take(true, false)
	c.mu.Unlock()
	return closeCarriers(items)
}
func (c *Client) Reset() {
	c.mu.Lock()
	items := c.take(true, false)
	c.mu.Unlock()
	closeCarriers(items)
}
func (c *Client) SetKeepIdleConnections(keep bool) {
	c.mu.Lock()
	c.keep = keep
	items := c.take(false, false)
	c.mu.Unlock()
	closeCarriers(items)
}
func (c *Client) CloseIdleConnections() { c.prune(true) }
func (c *Client) prune(force bool) {
	c.mu.Lock()
	items := c.take(false, force)
	c.mu.Unlock()
	closeCarriers(items)
}
func (c *Client) scavenge() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.prune(false)
		}
	}
}
