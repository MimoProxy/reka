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

type speedTestState struct {
	mu  sync.Mutex
	job *speedTestJob
}

type speedTestJob struct {
	id     uint64
	cancel context.CancelFunc
	reply  speedTestReply
}

type speedTestReply struct {
	generation.CloudflareSpeedReading
	Complete bool   `json:"complete"`
	Error    string `json:"error,omitempty"`
	// ErrorCode lets the app show its own text for failures it recognizes.
	ErrorCode string `json:"errorCode,omitempty"`
}

func (s *Session) startSpeedTest(id uint64, member string, source generation.SpeedSource) (bool, error) {
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
	if source == "" {
		source = generation.SpeedSourceCloudflare
	}
	// Leave time for server discovery and latency sampling around the two 10-second transfers.
	ctx, cancel := context.WithTimeout(s.ctx, 75*time.Second)
	job := &speedTestJob{id: id, cancel: cancel}
	job.reply.Phase = "latency"
	job.reply.Source = string(source)
	state.job = job
	go func() {
		defer cancel()
		err := s.measureSpeed(ctx, member, source, func(reading generation.CloudflareSpeedReading) {
			state.mu.Lock()
			job.reply.CloudflareSpeedReading = reading
			state.mu.Unlock()
		})
		state.mu.Lock()
		defer state.mu.Unlock()
		if err != nil {
			job.reply.Error = history.Text(err.Error(), 384)
			if errors.Is(err, generation.ErrOoklaUnreachable) {
				job.reply.ErrorCode = "ooklaUnreachable"
			}
		}
		job.reply.Complete = true
	}()
	return true, nil
}

func (s *Session) measureSpeed(ctx context.Context, member string, source generation.SpeedSource, update func(generation.CloudflareSpeedReading)) error {
	if s.profile != nil {
		return s.profile.engine.RunSpeedTest(ctx, member, source, update)
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
	return generation.MeasureSpeed(ctx, model.OutboundDirect, pin.Dial, source, update)
}

func (s *Session) readSpeedTest(id uint64) (speedTestReply, error) {
	state := &s.speed
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.job == nil || state.job.id != id {
		return speedTestReply{}, errors.New("speed test unavailable")
	}
	return state.job.reply, nil
}

func (s *Session) cancelSpeedTest(id uint64) bool {
	state := &s.speed
	state.mu.Lock()
	defer state.mu.Unlock()
	if job := state.job; job != nil && (id == 0 || job.id == id) {
		job.cancel()
	}
	return true
}
