//go:build with_gvisor

package packettunnel

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/runtime/generation"
)

type cloudflareSpeedState struct {
	mu  sync.Mutex
	job *cloudflareSpeedJob
}

type cloudflareSpeedJob struct {
	id     uint64
	cancel context.CancelFunc
	reply  cloudflareSpeedReply
}

type cloudflareSpeedReply struct {
	generation.CloudflareSpeedReading
	Complete bool   `json:"complete"`
	Error    string `json:"error,omitempty"`
}

func (s *Session) startCloudflareSpeed(id uint64, member string) (bool, error) {
	if id == 0 || member == "" || len(member) > 128 {
		return false, errors.New("speed test requires a probe ID and outbound")
	}
	if s.profile == nil && member != model.OutboundDirect {
		return false, errors.New("the selected speed test route requires a profile")
	}
	state := &s.speed
	state.mu.Lock()
	defer state.mu.Unlock()
	if previous := state.job; previous != nil && !previous.reply.Complete {
		if id == previous.id {
			return true, nil
		}
		return false, errors.New("a speed test is already running")
	}
	ctx, cancel := context.WithTimeout(s.ctx, 45*time.Second)
	job := &cloudflareSpeedJob{id: id, cancel: cancel}
	job.reply.Phase = "latency"
	state.job = job
	go func() {
		defer cancel()
		err := s.measureCloudflareSpeed(ctx, member, func(reading generation.CloudflareSpeedReading) {
			state.mu.Lock()
			job.reply.CloudflareSpeedReading = reading
			state.mu.Unlock()
		})
		state.mu.Lock()
		defer state.mu.Unlock()
		if err != nil {
			job.reply.Error = history.Text(err.Error(), 384)
		}
		job.reply.Complete = true
	}()
	return true, nil
}

func (s *Session) measureCloudflareSpeed(ctx context.Context, member string, update func(generation.CloudflareSpeedReading)) error {
	if s.profile != nil {
		return s.profile.engine.RunCloudflareSpeed(ctx, member, update)
	}
	direct, err := s.backend.NewOutbound(model.OutboundDirect, sagernet.DirectSpec{})
	if err != nil {
		return err
	}
	defer direct.Close()
	pin, err := direct.Pin()
	if err != nil {
		return err
	}
	defer pin.Close()
	return generation.MeasureCloudflareSpeed(ctx, model.OutboundDirect, pin.Dial, update)
}

func (s *Session) readCloudflareSpeed(id uint64) (cloudflareSpeedReply, error) {
	state := &s.speed
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.job == nil || state.job.id != id {
		return cloudflareSpeedReply{}, errors.New("speed test unavailable")
	}
	return state.job.reply, nil
}

func (s *Session) cancelCloudflareSpeed(id uint64) bool {
	state := &s.speed
	state.mu.Lock()
	defer state.mu.Unlock()
	if job := state.job; job != nil && (id == 0 || job.id == id) {
		job.cancel()
	}
	return true
}
