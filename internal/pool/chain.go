package pool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Poller follows the producer: its status (tip and the PULSE activation
// height) and its current work.
type Poller struct {
	Pool   *Pool
	API    string // e.g. http://127.0.0.1:18080/api/v1
	Client *http.Client
}

func (pl *Poller) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pl.API+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pl.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return b, nil
}

// Once polls status and work one time.
func (pl *Poller) Once(ctx context.Context) error {
	sb, err := pl.get(ctx, "/status")
	if err != nil {
		pl.Pool.SetChain(ChainStatus{Seen: pl.Pool.now(), Err: err.Error()})
		return err
	}
	var st struct {
		ChainTip              uint64 `json:"chain_tip"`
		PulseActivationHeight uint64 `json:"pulse_activation_height"`
		PulseActive           bool   `json:"pulse_active"`
	}
	if err := json.Unmarshal(sb, &st); err != nil {
		return err
	}
	prev := pl.Pool.chainTip()
	pl.Pool.mu.Lock()
	pools := pl.Pool.chain.Pools
	pl.Pool.mu.Unlock()
	pl.Pool.SetChain(ChainStatus{Tip: st.ChainTip, ActivationHeight: st.PulseActivationHeight, PulseActive: st.PulseActive,
		Pools: pools, Seen: pl.Pool.now()})
	if st.PulseActivationHeight > 0 {
		if err := pl.FetchChainState(ctx); err != nil {
			return err
		}
	}
	wb, err := pl.get(ctx, "/mining/work")
	if err != nil {
		return err
	}
	if _, err := pl.Pool.AddJob(wb); err != nil {
		return err
	}
	if st.ChainTip > prev && st.PulseActive {
		rec, err := pl.Pool.Settle(st.ChainTip)
		if err != nil {
			return err
		}
		if rec != nil {
			return pl.Submit(ctx, rec)
		}
	}
	return nil
}

// Run polls until ctx ends.
func (pl *Poller) Run(ctx context.Context, every time.Duration, logf func(string, ...any)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := pl.Once(ctx); err != nil && logf != nil {
			logf("poll: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Pool) chainTip() uint64 { p.mu.Lock(); defer p.mu.Unlock(); return p.chain.Tip }

func (p *Pool) chainActive() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.chain.Active() }
