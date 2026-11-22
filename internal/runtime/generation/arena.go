package generation

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
)

func probeTimeout(endpoint string, milliseconds int) (time.Duration, error) {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 8192 || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return 0, errors.New("probe requires an HTTP(S) URL without userinfo")
	}
	if milliseconds == 0 {
		milliseconds = 5000
	}
	if milliseconds < 100 || milliseconds > 30000 {
		return 0, errors.New("probe timeout must be 100..30000 ms")
	}
	return time.Duration(milliseconds) * time.Millisecond, nil
}

// RunArena compares the same frozen generation and resolved outbounds in
// every round. It never updates group choices or their health samples.
func (e *Engine) RunArena(ctx context.Context, request api.ArenaRequest) (api.ArenaResult, error) {
	if len(request.Outbounds) < 2 || len(request.Outbounds) > 16 {
		return api.ArenaResult{}, errors.New("arena requires 2..16 outbounds or policy groups")
	}
	if request.Rounds == 0 {
		request.Rounds = 3
	}
	if request.Rounds < 1 || request.Rounds > 5 {
		return api.ArenaResult{}, errors.New("arena rounds must be 1..5")
	}
	if request.URL == "" {
		request.URL = "https://www.gstatic.com/generate_204"
	}
	timeout, err := probeTimeout(request.URL, request.TimeoutMS)
	if err != nil {
		return api.ArenaResult{}, err
	}
	seen := map[string]bool{}
	for _, id := range request.Outbounds {
		if id == "" || len(id) > 256 || seen[id] {
			return api.ArenaResult{}, errors.New("arena candidates must be distinct outbound or group IDs")
		}
		seen[id] = true
	}
	if !e.arenaRunning.CompareAndSwap(false, true) {
		return api.ArenaResult{}, errors.New("an arena is already running")
	}
	defer e.arenaRunning.Store(false)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		snapshot, g := e.current()
		if g.router == nil {
			return api.ArenaResult{}, errors.New("no active configuration")
		}
		result := api.ArenaResult{Generation: snapshot.Generation, Revision: g.revision, Ranking: make([]api.ArenaEntry, len(request.Outbounds))}
		outbounds := make([]*sagernet.Outbound, len(request.Outbounds))
		for i, candidate := range request.Outbounds {
			id, err := g.resolveProbe(candidate, request.URL)
			if err != nil || snapshot.Resources[id] == nil {
				return api.ArenaResult{}, fmt.Errorf("candidate %q is unavailable or rejects traffic", candidate)
			}
			outbounds[i] = snapshot.Resources[id]
			result.Ranking[i] = api.ArenaEntry{Outbound: candidate, ResolvedOutbound: id, Samples: make([]api.ArenaSample, request.Rounds)}
		}
		pins, err := pinProbeOutbounds(g, snapshot, outbounds...)
		if err != nil {
			if e.rt.Current() != snapshot {
				continue
			}
			return api.ArenaResult{}, errors.New("arena runtime stopped")
		}
		defer closeSniffPins(pins)
		ctx = sniffSnapshotContext(sagernet.WithPinnedOutbounds(ctx, pins), snapshot)
		slots := make(chan struct{}, 4)
		for round := range request.Rounds {
			var wg sync.WaitGroup
			for i, outbound := range outbounds {
				wg.Go(func() {
					result.Ranking[i].Samples[round] = e.arenaSample(ctx, slots, timeout, g, outbound, pins[outbound], request.URL)
				})
			}
			wg.Wait()
		}
		rankArena(&result)
		return result, nil
	}
	return api.ArenaResult{}, ctx.Err()
}

func (e *Engine) arenaSample(ctx context.Context, slots chan struct{}, timeout time.Duration, g *generation, out *sagernet.Outbound, pin *sagernet.PinnedOutbound, endpoint string) api.ArenaSample {
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		return api.ArenaSample{Error: arenaError(ctx.Err(), 0)}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	release, err := e.takeProbeSlot(ctx)
	if err != nil {
		return api.ArenaSample{Error: arenaError(err, 0)}
	}
	defer release()
	sample, err := probeHTTP(ctx, g, out, pin, endpoint, false)
	if err != nil {
		sample.Error = arenaError(err, sample.StatusCode)
	}
	return sample
}

func arenaError(err error, status int) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case status != 0:
		return "http_status"
	default:
		return "probe_failed"
	}
}

func rankArena(result *api.ArenaResult) {
	for i := range result.Ranking {
		entry := &result.Ranking[i]
		var delays []int64
		for _, sample := range entry.Samples {
			if sample.Error == "" {
				delays = append(delays, sample.DelayMS)
			}
		}
		slices.Sort(delays)
		entry.Successes = len(delays)
		if n := len(delays); n != 0 {
			entry.MedianMS = (delays[(n-1)/2] + delays[n/2]) / 2
			entry.SpreadMS = delays[n-1] - delays[0]
		}
	}
	slices.SortFunc(result.Ranking, func(a, b api.ArenaEntry) int {
		return cmp.Or(cmp.Compare(b.Successes, a.Successes), cmp.Compare(a.MedianMS, b.MedianMS),
			cmp.Compare(a.SpreadMS, b.SpreadMS), cmp.Compare(a.Outbound, b.Outbound))
	})
	if len(result.Ranking) != 0 && result.Ranking[0].Successes != 0 {
		result.Winner = result.Ranking[0].Outbound
	}
}
