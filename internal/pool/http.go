package pool

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxBody bounds every request body (a registration carries a 2,592-byte
// public key and a 4,627-byte signature, in hex).
const MaxBody = 64 << 10

// Handler is the miner and public API under /pool/api/v1/.
func (p *Pool) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /pool/api/v1/info", p.hInfo)
	m.HandleFunc("GET /pool/api/v1/stats", p.hStats)
	m.HandleFunc("GET /pool/api/v1/window", p.hWindow)
	m.HandleFunc("GET /pool/api/v1/batches", p.hBatches)
	m.HandleFunc("GET /pool/api/v1/metrics", p.hMetrics)
	m.HandleFunc("POST /pool/api/v1/register", p.hRegister)
	m.HandleFunc("GET /pool/api/v1/work", p.hWork)
	m.HandleFunc("POST /pool/api/v1/shares", p.hShare)
	m.HandleFunc("POST /pool/api/v1/proofs", p.hProof)
	m.HandleFunc("GET /pool/api/v1/address/{addr}", p.hAddress)
	m.HandleFunc("GET /pool/api/v1/address/{addr}/shares.csv", p.hAddressShares)
	m.HandleFunc("GET /pool/api/v1/address/{addr}/payouts.csv", p.hAddressPayouts)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		m.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func token(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func decode(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, MaxBody))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

func (p *Pool) mode() (string, ChainStatus) {
	p.mu.Lock()
	c := p.chain
	p.mu.Unlock()
	if c.Active() {
		return "active", c
	}
	return "preview", c
}

func (p *Pool) hInfo(w http.ResponseWriter, _ *http.Request) {
	mode, c := p.mode()
	note := "Settlement is live: each block's reward for pooled proofs is paid by the chain directly to members."
	if mode == "preview" {
		if c.ActivationHeight > 0 {
			note = fmt.Sprintf("Preview: settlement starts at block %d. Shares sent now pay nothing.", c.ActivationHeight)
		} else {
			note = "Preview: the chain rule has no activation height yet. Shares sent now pay nothing."
		}
	}
	writeJSON(w, 200, map[string]any{
		"name": "PULSE", "pool_id": p.key.ID(), "public_key": hex.EncodeToString(p.key.Pub.Bytes()),
		"mode": mode, "note": note, "fee_bps": p.cfg.FeeAt(p.now()), "fee_to": strings.ToLower(p.cfg.FeeTo),
		"fee_network_cap_bps": NetworkMaxFeeBPS, "fee_notice_days": p.cfg.FeeNoticeDays,
		"fee_next":         map[string]any{"bps": p.cfg.FeeNextBPS, "from": p.cfg.FeeNextFrom},
		"authorized_pools": c.Pools,
		"rules_note":       "Every authorized pool is paid by the same chain rule: the network caps every pool's fee at 3 % and settles every batch the same way.",
		"window_factor":    p.cfg.WindowFactor, "payout_floor_dust": p.cfg.FloorDust,
		"share_difficulty": p.cfg.ShareDifficulty, "min_share_difficulty": p.cfg.MinShareDiff,
		"preview_accepts_shares": p.cfg.PreviewShares,
		"chain":                  map[string]any{"tip": c.Tip, "activation_height": c.ActivationHeight, "active": c.Active(), "error": c.Err},
	})
}

func (p *Pool) hStats(w http.ResponseWriter, _ *http.Request) {
	now := p.now()
	p.mu.Lock()
	var diff10 uint64
	miners := map[string]bool{}
	workers := map[string]bool{}
	for i := len(p.shares) - 1; i >= 0; i-- {
		s := p.shares[i]
		if now.Sub(s.At) > 10*time.Minute {
			break
		}
		diff10 += s.Difficulty
		miners[string(s.Owner)] = true
		workers[string(s.Owner)+"."+s.Worker] = true
	}
	st := p.stats
	nb := len(p.batches)
	var job *Job
	if len(p.order) > 0 {
		job = p.jobs[p.order[len(p.order)-1]]
	}
	p.mu.Unlock()
	out := map[string]any{
		"miners_10m": len(miners), "workers_10m": len(workers),
		"hashrate_10m_hs": float64(diff10) / 600.0, // each share stands for about `difficulty` hashes
		"shares_accepted": st.accepted, "shares_rejected": st.rejected, "network_solutions": st.solutions,
		"settlements": nb,
	}
	if job != nil {
		_, fill, _ := p.Window(job.WindowTarget)
		out["height"] = job.Height
		out["network_difficulty"] = job.NetDiff.String()
		out["window_target"] = job.WindowTarget
		out["window_filled"] = fill
	}
	writeJSON(w, 200, out)
}

func (p *Pool) hWindow(w http.ResponseWriter, _ *http.Request) {
	j := p.CurrentJob()
	if j == nil {
		fail(w, 503, "no work yet")
		return
	}
	ws, fill, err := p.Window(j.WindowTarget)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"job_id": j.ID, "window_target": j.WindowTarget, "filled": fill, "weights": ws})
}

func (p *Pool) hBatches(w http.ResponseWriter, r *http.Request) {
	from, _ := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	p.mu.Lock()
	var out []BatchRecord
	for _, b := range p.batches {
		if b.Seq >= from {
			out = append(out, b)
		}
		if len(out) >= 100 {
			break
		}
	}
	p.mu.Unlock()
	writeJSON(w, 200, map[string]any{"pool_id": p.key.ID(), "batches": out})
}

func (p *Pool) hMetrics(w http.ResponseWriter, _ *http.Request) {
	mode, c := p.mode()
	p.mu.Lock()
	st, nb, ns := p.stats, len(p.batches), len(p.sess)
	p.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	active := 0
	if mode == "active" {
		active = 1
	}
	fmt.Fprintf(w, "pulse_shares_accepted_total %d\npulse_shares_rejected_total %d\npulse_network_solutions_total %d\n", st.accepted, st.rejected, st.solutions)
	fmt.Fprintf(w, "pulse_settlements_total %d\npulse_sessions %d\npulse_chain_rule_active %d\npulse_chain_tip %d\n", nb, ns, active, c.Tip)
}

func (p *Pool) hRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Login     string `json:"login"`
		Password  string `json:"password"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "bad request")
		return
	}
	tok, err := p.Register(in.Login, in.PublicKey, in.Signature, in.Password)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"session": tok})
}

func (p *Pool) hWork(w http.ResponseWriter, r *http.Request) {
	j, diff, err := p.WorkFor(token(r))
	if err != nil {
		fail(w, 401, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"job_id": j.ID, "share_difficulty": strconv.FormatUint(diff, 10),
		"network_difficulty": j.NetDiff.String(), "window_target": j.WindowTarget, "work": j.Raw})
}

func (p *Pool) hShare(w http.ResponseWriter, r *http.Request) {
	var in struct {
		JobID      string `json:"job_id"`
		Nonce      string `json:"nonce"`
		BatchCount uint32 `json:"batch_count"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "bad request")
		return
	}
	res, err := p.SubmitShare(token(r), in.JobID, in.Nonce, in.BatchCount)
	if err != nil {
		fail(w, 401, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (p *Pool) hProof(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ProofID string `json:"proof_id"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "bad request")
		return
	}
	if err := p.ReportProof(token(r), in.ProofID); err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"recorded": true})
}
