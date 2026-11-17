package pool

import (
	"encoding/csv"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/qsdm-tech/qsdm-mining-bootstrap/pulse"
)

// No accounts: everything here is keyed by the public payout address.
//
//	GET /pool/api/v1/address/{addr}             workers, window share, owed, expected payouts
//	GET /pool/api/v1/address/{addr}/shares.csv  this address's accepted shares
//	GET /pool/api/v1/address/{addr}/payouts.csv this address's payouts per settlement

// AddressStats is the per-address view.
type AddressStats struct {
	Address      string        `json:"address"`
	Workers      []WorkerStats `json:"workers"`
	WindowWeight uint64        `json:"window_weight"`
	WindowTotal  uint64        `json:"window_total"`
	WindowShare  float64       `json:"window_share"` // fraction of the current window
	OwedDust     uint64        `json:"owed_dust"`    // carried on the chain, below the payout floor or over a cap
	ExpectedDust uint64        `json:"expected_paid_dust"`
	EstimateNote string        `json:"estimate_note"`
}

// WorkerStats is one worker of an address.
type WorkerStats struct {
	Worker     string    `json:"worker"`
	Shares     uint64    `json:"shares"`
	Difficulty uint64    `json:"difficulty_sum"`
	LastShare  time.Time `json:"last_share"`
}

func (p *Pool) addressFrom(w http.ResponseWriter, r *http.Request) (pulse.Address, bool) {
	a, err := pulse.ParseAddress(r.PathValue("addr"))
	if err != nil {
		fail(w, 400, "not a QSDM address (64 hex characters)")
		return "", false
	}
	return a, true
}

// Address computes the per-address stats.
func (p *Pool) Address(a pulse.Address) AddressStats {
	out := AddressStats{Address: string(a),
		EstimateNote: "window_share is this address's part of the current share window: each pooled reward is split by it after the pool fee. The chain's settlement is authoritative; per-payee epoch caps can carry part of a payout to later blocks."}
	ws := map[string]*WorkerStats{}
	p.mu.Lock()
	for _, s := range p.shares {
		if s.Owner != a {
			continue
		}
		x := ws[s.Worker]
		if x == nil {
			x = &WorkerStats{Worker: s.Worker}
			ws[s.Worker] = x
		}
		x.Shares++
		x.Difficulty += s.Difficulty
		if s.At.After(x.LastShare) {
			x.LastShare = s.At
		}
	}
	out.OwedDust = p.chainPool.Owed[string(a)]
	for _, b := range p.batches {
		for _, py := range b.Expected {
			if py.To == a {
				out.ExpectedDust += py.Amount
			}
		}
	}
	p.mu.Unlock()
	for _, x := range ws {
		out.Workers = append(out.Workers, *x)
	}
	sort.Slice(out.Workers, func(i, j int) bool { return out.Workers[i].Worker < out.Workers[j].Worker })
	if j := p.CurrentJob(); j != nil {
		if weights, fill, err := p.Window(j.WindowTarget); err == nil && fill > 0 {
			out.WindowTotal = fill
			for _, w := range weights {
				if w.Owner == a {
					out.WindowWeight = w.Weight
				}
			}
			out.WindowShare = float64(out.WindowWeight) / float64(fill)
		}
	}
	return out
}

func (p *Pool) hAddress(w http.ResponseWriter, r *http.Request) {
	a, ok := p.addressFrom(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, p.Address(a))
}

func csvOut(w http.ResponseWriter, name string, rows [][]string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	cw := csv.NewWriter(w)
	_ = cw.WriteAll(rows)
}

func (p *Pool) hAddressShares(w http.ResponseWriter, r *http.Request) {
	a, ok := p.addressFrom(w, r)
	if !ok {
		return
	}
	rows := [][]string{{"index", "time_utc", "worker", "difficulty", "job_id"}}
	p.mu.Lock()
	for _, s := range p.shares {
		if s.Owner == a {
			rows = append(rows, []string{strconv.FormatUint(s.Index, 10), s.At.UTC().Format(time.RFC3339),
				s.Worker, strconv.FormatUint(s.Difficulty, 10), s.JobID})
		}
	}
	p.mu.Unlock()
	csvOut(w, "pulse-shares-"+string(a)[:8]+".csv", rows)
}

func (p *Pool) hAddressPayouts(w http.ResponseWriter, r *http.Request) {
	a, ok := p.addressFrom(w, r)
	if !ok {
		return
	}
	rows := [][]string{{"settlement_seq", "height", "time_utc", "expected_cell", "kind", "tx_id"}}
	p.mu.Lock()
	for _, b := range p.batches {
		for _, py := range b.Expected {
			if py.To == a {
				rows = append(rows, []string{strconv.FormatUint(b.Seq, 10), strconv.FormatUint(b.Height, 10),
					b.Created.UTC().Format(time.RFC3339), strconv.FormatFloat(float64(py.Amount)/1e8, 'f', 8, 64), py.Kind, b.TxID})
			}
		}
	}
	p.mu.Unlock()
	csvOut(w, "pulse-payouts-"+string(a)[:8]+".csv", rows)
}
