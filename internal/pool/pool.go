package pool

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blackbeardONE/qsdm-mining-bootstrap/internal/qsdmpow"
	"github.com/blackbeardONE/qsdm-mining-bootstrap/pulse"
)

// RegisterDomain separates miner registration signatures.
const RegisterDomain = "QSDM/pulse/register/v1\x00"

// Config is the pool's settings; every policy number is the operator's choice.
type Config struct {
	Listen            string `json:"listen"`             // loopback address, e.g. 127.0.0.1:17760
	ProducerAPI       string `json:"producer_api"`       // e.g. http://127.0.0.1:18080/api/v1
	DataDir           string `json:"data_dir"`           // journal location
	KeyFile           string `json:"key_file"`           // the pool's ML-DSA-87 seed (0600)
	FeeBPS            uint16 `json:"fee_bps"`            // pool fee; default 0
	FeeTo             string `json:"fee_to"`             // fee recipient (required, also gets dust)
	WindowFactor      uint64 `json:"window_factor"`      // TIDES window = factor x network difficulty; default 8
	FloorDust         uint64 `json:"floor_dust"`         // payout floor in dust (required)
	ShareDifficulty   uint64 `json:"share_difficulty"`   // default share difficulty
	MinShareDiff      uint64 `json:"min_share_difficulty"`
	PreviewShares     bool   `json:"preview_accept_shares"` // accept shares before the chain rule is active (they pay nothing)
	PollSeconds       int    `json:"poll_seconds"`
	PublicExplorerURL string `json:"public_explorer_url"`
}

// Validate refuses a config the pool must not start with.
func (c *Config) Validate() error {
	if c.WindowFactor == 0 {
		c.WindowFactor = 8
	}
	if c.PollSeconds == 0 {
		c.PollSeconds = 5
	}
	if _, err := pulse.ParseAddress(c.FeeTo); err != nil {
		return errors.New("config: fee_to (the fee recipient, a QSDM address) is required, even at 0 bps")
	}
	if c.FeeBPS > 10000 {
		return errors.New("config: fee_bps above 10000")
	}
	if c.ShareDifficulty == 0 || c.MinShareDiff == 0 || c.MinShareDiff > c.ShareDifficulty {
		return errors.New("config: share_difficulty and min_share_difficulty must be > 0, min <= default")
	}
	if !strings.HasPrefix(c.Listen, "127.0.0.1:") && !strings.HasPrefix(c.Listen, "[::1]:") {
		return errors.New("config: listen must be a loopback address (nginx fronts the pool)")
	}
	return nil
}

type session struct {
	Login     pulse.Login
	MinDiff   uint64
	FixedDiff uint64
	LastSeen  time.Time
}

type acceptedShare struct {
	Owner      pulse.Address
	Worker     string
	Difficulty uint64
	At         time.Time
	JobID      string
}

// BatchRecord is a signed settlement as the pool publishes it.
type BatchRecord struct {
	Seq      uint64         `json:"seq"`
	Height   uint64         `json:"height"`
	BodyHex  string         `json:"body"`
	SigHex   string         `json:"signature"`
	Proofs   []string       `json:"proof_ids"`
	Weights  []pulse.Weight `json:"weights"`
	Created  time.Time      `json:"created"`
}

// ChainStatus is what the pool knows of the producer.
type ChainStatus struct {
	Tip              uint64
	ActivationHeight uint64 // pulse_activation_height from /status; 0 = not configured
	Seen             time.Time
	Err              string
}

// Active reports whether the chain pays PULSE settlements at the tip.
func (s ChainStatus) Active() bool { return s.ActivationHeight > 0 && s.Tip >= s.ActivationHeight }

// Pool is the server state. All methods are safe for concurrent use.
type Pool struct {
	cfg   Config
	key   *pulse.KeyPair
	jr    *Journal
	now   func() time.Time
	mu    sync.Mutex
	jobs  map[string]*Job
	order []string
	dags  map[string]qsdmpow.DAG
	sess  map[string]*session
	seen  map[string]bool // job|nonce|count
	shares []acceptedShare // oldest first
	proofs map[string]pulse.Address
	batches []BatchRecord
	seq   uint64
	chain ChainStatus
	stats struct{ accepted, rejected, solutions uint64 }
}

const keepJobs = 16

// New makes a pool; jr may be nil in tests.
func New(cfg Config, key *pulse.KeyPair, jr *Journal) (*Pool, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Pool{cfg: cfg, key: key, jr: jr, now: time.Now, jobs: map[string]*Job{}, dags: map[string]qsdmpow.DAG{},
		sess: map[string]*session{}, seen: map[string]bool{}, proofs: map[string]pulse.Address{}}
	if jr != nil {
		if err := jr.Replay(p.apply); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// SetChain records the producer status.
func (p *Pool) SetChain(s ChainStatus) { p.mu.Lock(); p.chain = s; p.mu.Unlock() }

// AddJob installs a new job from the producer's work (idempotent per job ID).
func (p *Pool) AddJob(raw []byte) (*Job, error) {
	j, ws, root, err := NewJob(raw, p.cfg.WindowFactor)
	if err != nil {
		return nil, err
	}
	_ = ws
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.jobs[j.ID]; ok {
		return old, nil
	}
	if _, ok := p.dags[j.DAGKey]; !ok {
		var w ProducerWork
		_ = jsonUnmarshal(raw, &w)
		d, err := qsdmpow.NewInMemoryDAG(j.Epoch, root, w.DAGSize)
		if err != nil {
			return nil, err
		}
		if len(p.dags) >= 2 {
			p.dags = map[string]qsdmpow.DAG{}
		}
		p.dags[j.DAGKey] = d
	}
	p.jobs[j.ID] = j
	p.order = append(p.order, j.ID)
	for len(p.order) > keepJobs {
		old := p.order[0]
		p.order = p.order[1:]
		delete(p.jobs, old)
		for k := range p.seen {
			if strings.HasPrefix(k, old+"|") {
				delete(p.seen, k)
			}
		}
	}
	return j, nil
}

// CurrentJob is the newest job.
func (p *Pool) CurrentJob() *Job {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.order) == 0 {
		return nil
	}
	return p.jobs[p.order[len(p.order)-1]]
}

// ParseHints reads "d=<difficulty>" (fixed) and "md=<difficulty>" (minimum)
// from a comma-separated password field; other words are ignored.
func ParseHints(s string) (fixed, min uint64) {
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n == 0 {
			continue
		}
		switch k {
		case "d":
			fixed = n
		case "md":
			min = n
		}
	}
	return
}

// Register checks that the caller holds the key of the payout address and
// opens a session. The signature is over RegisterDomain || login.
func (p *Pool) Register(login, pubHex, sigHex, password string) (string, error) {
	l, err := pulse.ParseLogin(login)
	if err != nil {
		return "", err
	}
	pb, err1 := hex.DecodeString(pubHex)
	sig, err2 := hex.DecodeString(sigHex)
	if err1 != nil || err2 != nil {
		return "", errors.New("public_key and signature must be hex")
	}
	pk, err := pulse.ParsePublicKey(pb)
	if err != nil {
		return "", err
	}
	if pulse.AddressOf(pk) != l.Address {
		return "", errors.New("the public key does not belong to the login's address")
	}
	if !pulse.Verify(pk, RegisterDomain, []byte(login), sig) {
		return "", errors.New("signature does not verify")
	}
	fixed, min := ParseHints(password)
	var tok [32]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(tok[:])
	ev := Event{Type: "session", Session: id, Login: login, FixedDiff: fixed, MinDiff: min, At: p.now()}
	if err := p.record(ev); err != nil {
		return "", err
	}
	return id, nil
}

func (p *Pool) shareDiff(s *session, j *Job) uint64 {
	d := p.cfg.ShareDifficulty
	if s.MinDiff > d {
		d = s.MinDiff
	}
	if s.FixedDiff > 0 {
		d = s.FixedDiff
	}
	if d < p.cfg.MinShareDiff {
		d = p.cfg.MinShareDiff
	}
	if j != nil && d > j.NetDiff.Uint64() {
		d = j.NetDiff.Uint64()
	}
	return d
}

// WorkFor returns the job and share difficulty for a session.
func (p *Pool) WorkFor(token string) (*Job, uint64, error) {
	p.mu.Lock()
	s, ok := p.sess[token]
	p.mu.Unlock()
	if !ok {
		return nil, 0, errors.New("unknown session")
	}
	j := p.CurrentJob()
	if j == nil {
		return nil, 0, errors.New("no work yet")
	}
	return j, p.shareDiff(s, j), nil
}

// ShareResult is the answer to a share.
type ShareResult struct {
	Accepted        bool   `json:"accepted"`
	Reason          string `json:"reason,omitempty"`
	Difficulty      uint64 `json:"difficulty,omitempty"`
	NetworkSolution bool   `json:"network_solution,omitempty"`
	Preview         bool   `json:"preview"`
}

// SubmitShare checks a share: a known job, an allowed batch_root, the real
// Mesh3D hash under the session's share target, and no repeat.
func (p *Pool) SubmitShare(token, jobID, nonceHex string, batchCount uint32) (ShareResult, error) {
	p.mu.Lock()
	s, ok := p.sess[token]
	j := p.jobs[jobID]
	var dag qsdmpow.DAG
	if j != nil {
		dag = p.dags[j.DAGKey]
	}
	active := p.chain.Active()
	p.mu.Unlock()
	res := ShareResult{Preview: !active}
	if !ok {
		return res, errors.New("unknown session")
	}
	if !active && !p.cfg.PreviewShares {
		return p.reject(res, "the chain rule is not active yet; shares open at the activation height")
	}
	if j == nil || dag == nil {
		return p.reject(res, "unknown or stale job")
	}
	nb, err := hex.DecodeString(nonceHex)
	if err != nil || len(nb) != 16 {
		return p.reject(res, "nonce must be 16 hex bytes")
	}
	var nonce [16]byte
	copy(nonce[:], nb)
	var root [32]byte
	found := false
	for r, c := range j.Roots {
		if c == batchCount {
			root, found = r, true
		}
	}
	if !found {
		return p.reject(res, "batch_count is not allowed for this job")
	}
	key := fmt.Sprintf("%s|%x|%d", jobID, nonce, batchCount)
	diff := p.shareDiff(s, j)
	mix, err := qsdmpow.ComputeMixDigest(j.Header, nonce, dag)
	if err != nil {
		return p.reject(res, "dag")
	}
	h := qsdmpow.ProofPoWHash(j.Header, nonce, root, mix)
	st, _ := qsdmpow.TargetFromDifficulty(new(big.Int).SetUint64(diff))
	if !qsdmpow.MeetsTarget(h, st) {
		return p.reject(res, "above the share target")
	}
	p.mu.Lock()
	if p.seen[key] {
		p.mu.Unlock()
		return p.reject(res, "duplicate share")
	}
	p.seen[key] = true
	p.mu.Unlock()
	res.Accepted, res.Difficulty = true, diff
	res.NetworkSolution = qsdmpow.MeetsTarget(h, j.NetTarget)
	ev := Event{Type: "share", Session: token, Owner: string(s.Login.Address), Worker: s.Login.Worker, Difficulty: diff, JobID: jobID, Solution: res.NetworkSolution, At: p.now()}
	if err := p.record(ev); err != nil {
		return res, err
	}
	return res, nil
}

func (p *Pool) reject(res ShareResult, why string) (ShareResult, error) {
	p.mu.Lock()
	p.stats.rejected++
	p.mu.Unlock()
	res.Reason = why
	return res, nil
}

// ReportProof records an accepted network proof of a member, to be pooled
// in the next settlement. The chain refuses any listed proof that the
// producer did not accept for an owner in the batch's weights.
func (p *Pool) ReportProof(token, proofID string) error {
	if len(proofID) == 0 || len(proofID) > pulse.MaxProofIDLen {
		return errors.New("proof_id length")
	}
	p.mu.Lock()
	s, ok := p.sess[token]
	_, dup := p.proofs[proofID]
	p.mu.Unlock()
	if !ok {
		return errors.New("unknown session")
	}
	if dup {
		return errors.New("proof already reported")
	}
	return p.record(Event{Type: "proof", Owner: string(s.Login.Address), ProofID: proofID, At: p.now()})
}

// Window returns the TIDES weights for target (newest shares first).
func (p *Pool) Window(target uint64) ([]pulse.Weight, uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ws := make([]pulse.WindowShare, 0, len(p.shares))
	for i := len(p.shares) - 1; i >= 0; i-- {
		ws = append(ws, pulse.WindowShare{Owner: p.shares[i].Owner, Difficulty: p.shares[i].Difficulty})
	}
	return pulse.TIDESWindow(ws, target)
}

// Settle builds and signs the settlement for height from the pending
// reported proofs and the window frozen in the newest job. It refuses
// while the chain rule is not active.
func (p *Pool) Settle(height uint64) (*BatchRecord, error) {
	p.mu.Lock()
	active := p.chain.Active()
	var pending []string
	for id, o := range p.proofs {
		if o != "" {
			pending = append(pending, id)
		}
	}
	p.mu.Unlock()
	if !active {
		return nil, errors.New("the chain rule is not active: no settlement before the activation height")
	}
	if len(pending) == 0 {
		return nil, nil
	}
	sort.Strings(pending)
	if len(pending) > pulse.MaxBatchProofs {
		pending = pending[:pulse.MaxBatchProofs]
	}
	j := p.CurrentJob()
	if j == nil {
		return nil, errors.New("no job")
	}
	weights, _, err := p.Window(j.WindowTarget)
	if err != nil {
		return nil, err
	}
	if len(weights) == 0 {
		return nil, errors.New("empty window")
	}
	if len(weights) > pulse.MaxBatchWeights {
		return nil, errors.New("window has more members than one batch carries")
	}
	p.mu.Lock()
	seq := p.seq + 1
	p.mu.Unlock()
	b := &pulse.Batch{Version: pulse.BatchVersion, PoolID: p.key.ID(), Seq: seq, Height: height, FeeBPS: p.cfg.FeeBPS,
		FeeTo: pulse.Address(strings.ToLower(p.cfg.FeeTo)), FloorDust: p.cfg.FloorDust, ProofIDs: pending, Weights: weights}
	sb, err := pulse.SignBatch(p.key, b)
	if err != nil {
		return nil, err
	}
	rec := BatchRecord{Seq: seq, Height: height, BodyHex: hex.EncodeToString(sb.Body), SigHex: hex.EncodeToString(sb.Sig),
		Proofs: pending, Weights: weights, Created: p.now()}
	if err := p.record(Event{Type: "batch", Batch: &rec, At: p.now()}); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (p *Pool) record(ev Event) error {
	if p.jr != nil {
		if err := p.jr.Append(ev); err != nil {
			return err
		}
	}
	p.apply(ev)
	return nil
}

// apply changes state for one event (also used by journal replay).
func (p *Pool) apply(ev Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch ev.Type {
	case "session":
		l, err := pulse.ParseLogin(ev.Login)
		if err == nil {
			p.sess[ev.Session] = &session{Login: l, FixedDiff: ev.FixedDiff, MinDiff: ev.MinDiff, LastSeen: ev.At}
		}
	case "share":
		p.shares = append(p.shares, acceptedShare{Owner: pulse.Address(ev.Owner), Worker: ev.Worker, Difficulty: ev.Difficulty, At: ev.At, JobID: ev.JobID})
		p.stats.accepted++
		if ev.Solution {
			p.stats.solutions++
		}
		if s := p.sess[ev.Session]; s != nil {
			s.LastSeen = ev.At
		}
		const keepShares = 200_000
		if len(p.shares) > keepShares {
			p.shares = append([]acceptedShare(nil), p.shares[len(p.shares)-keepShares:]...)
		}
	case "proof":
		p.proofs[ev.ProofID] = pulse.Address(ev.Owner)
	case "batch":
		if ev.Batch != nil {
			p.batches = append(p.batches, *ev.Batch)
			if ev.Batch.Seq > p.seq {
				p.seq = ev.Batch.Seq
			}
			for _, id := range ev.Batch.Proofs {
				p.proofs[id] = "" // settled: kept so it cannot be reported again
			}
		}
	}
}
