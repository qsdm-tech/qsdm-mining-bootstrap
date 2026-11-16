package pool

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blackbeardONE/qsdm-mining-bootstrap/internal/qsdmpow"
	"github.com/blackbeardONE/qsdm-mining-bootstrap/pulse"
)

var liveWork = func() []byte {
	b, err := os.ReadFile("../qsdmpow/testdata/live-work-20261116.json")
	if err != nil {
		panic(err)
	}
	return b
}()

// fakeProducer serves /status and /mining/work like the QSDM producer.
type fakeProducer struct {
	tip, act uint64
}

func (f *fakeProducer) handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/api/v1/status", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"chain_tip":%d,"pulse_activation_height":%d}`, f.tip, f.act)
	})
	m.HandleFunc("/api/v1/mining/work", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(liveWork) })
	return m
}

func feeAddr() string { return strings.Repeat("f", 64) }

func newTestPool(t *testing.T, preview bool) (*Pool, *pulse.KeyPair, *fakeProducer, *Poller, string) {
	t.Helper()
	k, _ := pulse.NewKeyPair()
	dir := t.TempDir()
	jr, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { jr.Close() })
	cfg := Config{Listen: "127.0.0.1:0", FeeTo: feeAddr(), FloorDust: 1_000_000, ShareDifficulty: 64, MinShareDiff: 16, PreviewShares: preview}
	p, err := New(cfg, k, jr)
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeProducer{tip: 1_118_166}
	srv := httptest.NewServer(fp.handler())
	t.Cleanup(srv.Close)
	pl := &Poller{Pool: p, API: srv.URL + "/api/v1", Client: srv.Client()}
	if err := pl.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	return p, k, fp, pl, dir
}

type miner struct {
	k     *pulse.KeyPair
	login string
	tok   string
}

func register(t *testing.T, h http.Handler, worker, password string) *miner {
	t.Helper()
	k, _ := pulse.NewKeyPair()
	login := string(k.ID()) + "." + worker
	sig, _ := k.Sign(RegisterDomain, []byte(login))
	body, _ := json.Marshal(map[string]string{"login": login, "password": password,
		"public_key": hex.EncodeToString(k.Pub.Bytes()), "signature": hex.EncodeToString(sig)})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/pool/api/v1/register", bytes.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("register: %d %s", rr.Code, rr.Body)
	}
	var out struct{ Session string }
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return &miner{k: k, login: login, tok: out.Session}
}

// mine finds a nonce meeting diff for the job, the way a miner would.
func mine(t *testing.T, p *Pool, j *Job, diff uint64, start uint64) ([16]byte, uint64) {
	t.Helper()
	p.mu.Lock()
	dag := p.dags[j.DAGKey]
	p.mu.Unlock()
	var root [32]byte
	for r := range j.Roots {
		root = r
	}
	tg, _ := qsdmpow.TargetFromDifficulty(new(big.Int).SetUint64(diff))
	for n := start; n < start+2_000_000; n++ {
		var nonce [16]byte
		binary.BigEndian.PutUint64(nonce[8:], n)
		mix, _ := qsdmpow.ComputeMixDigest(j.Header, nonce, dag)
		if qsdmpow.MeetsTarget(qsdmpow.ProofPoWHash(j.Header, nonce, root, mix), tg) {
			return nonce, n + 1
		}
	}
	t.Fatal("no share found")
	return [16]byte{}, 0
}

func share(t *testing.T, h http.Handler, m *miner, job string, nonce [16]byte, count uint32) ShareResult {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"job_id": job, "nonce": hex.EncodeToString(nonce[:]), "batch_count": count})
	req := httptest.NewRequest("POST", "/pool/api/v1/shares", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+m.tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var out ShareResult
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return out
}

func TestRegisterRefusesForeignAddress(t *testing.T) {
	p, _, _, _, _ := newTestPool(t, true)
	a, _ := pulse.NewKeyPair()
	b, _ := pulse.NewKeyPair()
	login := string(a.ID())
	sig, _ := b.Sign(RegisterDomain, []byte(login))
	if _, err := p.Register(login, hex.EncodeToString(b.Pub.Bytes()), hex.EncodeToString(sig), ""); err == nil {
		t.Fatal("registered someone else's address")
	}
	sig, _ = a.Sign(RegisterDomain, []byte(login+"x"))
	if _, err := p.Register(login, hex.EncodeToString(a.Pub.Bytes()), hex.EncodeToString(sig), ""); err == nil {
		t.Fatal("accepted a signature over other words")
	}
}

func TestEndToEndPreviewThenSettlement(t *testing.T) {
	p, key, fp, pl, dir := newTestPool(t, true)
	h := p.Handler()
	alice := register(t, h, "rig1", "md=128")
	bob := register(t, h, "gpu", "")
	j := p.CurrentJob()
	var count uint32
	for _, c := range j.Roots {
		count = c
	}
	// Preview: shares count for stats, Settle refuses.
	n1, next := mine(t, p, j, 128, 0)
	r := share(t, h, alice, j.ID, n1, count)
	if !r.Accepted || !r.Preview || r.Difficulty != 128 {
		t.Fatalf("%+v", r)
	}
	if r2 := share(t, h, alice, j.ID, n1, count); r2.Accepted || r2.Reason != "duplicate share" {
		t.Fatalf("duplicate: %+v", r2)
	}
	if r3 := share(t, h, alice, j.ID, n1, count+1); r3.Accepted {
		t.Fatalf("other batch_count accepted: %+v", r3)
	}
	n2, _ := mine(t, p, j, 64, next)
	if r := share(t, h, bob, j.ID, n2, count); !r.Accepted || r.Difficulty != 64 {
		t.Fatalf("%+v", r)
	}
	if _, err := p.Settle(1_118_167); err == nil {
		t.Fatal("settled before the activation height")
	}
	// The chain rule turns on.
	fp.act, fp.tip = 1_118_160, 1_118_170
	if err := p.ReportProof(alice.tok, "proof-a"); err != nil {
		t.Fatal(err)
	}
	if err := p.ReportProof(bob.tok, "proof-a"); err == nil {
		t.Fatal("a proof was reported twice")
	}
	if err := pl.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	nb := len(p.batches)
	var rec BatchRecord
	if nb > 0 {
		rec = p.batches[0]
	}
	p.mu.Unlock()
	if nb != 1 || rec.Seq != 1 || len(rec.Weights) != 2 {
		t.Fatalf("batches %d %+v", nb, rec)
	}
	body, _ := hex.DecodeString(rec.BodyHex)
	sig, _ := hex.DecodeString(rec.SigHex)
	if !pulse.Verify(key.Pub, pulse.BatchDomain, body, sig) {
		t.Fatal("batch signature")
	}
	b, err := pulse.DecodeBatch(body)
	if err != nil || b.FeeBPS != 0 || string(b.FeeTo) != feeAddr() || b.ProofIDs[0] != "proof-a" {
		t.Fatalf("%v %+v", err, b)
	}
	got := map[pulse.Address]uint64{}
	for _, w := range b.Weights {
		got[w.Owner] = w.Weight
	}
	if got[alice.k.ID()] != 128 || got[bob.k.ID()] != 64 {
		t.Fatalf("weights %v", got)
	}
	// Restart from the journal: same window, same sequence, proof stays settled.
	jr2, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer jr2.Close()
	p2, err := New(p.cfg, key, jr2)
	if err != nil {
		t.Fatal(err)
	}
	p2.mu.Lock()
	ok := p2.seq == 1 && len(p2.shares) == 2 && p2.proofs["proof-a"] == "" && len(p2.sess) == 2
	p2.mu.Unlock()
	if !ok {
		t.Fatal("journal replay lost state")
	}
	if err := p2.ReportProof(alice.tok, "proof-a"); err == nil {
		t.Fatal("a settled proof was reported again after restart")
	}
}

func TestPreviewWithoutSharesRefuses(t *testing.T) {
	p, _, _, _, _ := newTestPool(t, false)
	h := p.Handler()
	m := register(t, h, "w", "")
	j := p.CurrentJob()
	n, _ := mine(t, p, j, 64, 0)
	var count uint32
	for _, c := range j.Roots {
		count = c
	}
	if r := share(t, h, m, j.ID, n, count); r.Accepted || !strings.Contains(r.Reason, "not active") {
		t.Fatalf("%+v", r)
	}
}

func TestInfoIsHonestInPreview(t *testing.T) {
	p, _, _, _, _ := newTestPool(t, true)
	rr := httptest.NewRecorder()
	p.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/pool/api/v1/info", nil))
	var info map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &info)
	if info["mode"] != "preview" || !strings.Contains(info["note"].(string), "pay nothing") || info["fee_bps"].(float64) != 0 {
		t.Fatalf("%v", info)
	}
}

func TestConfigRefusesMissingFeeRecipient(t *testing.T) {
	c := Config{Listen: "127.0.0.1:1", ShareDifficulty: 1, MinShareDiff: 1}
	if err := c.Validate(); err == nil {
		t.Fatal("started without a fee recipient")
	}
	c.FeeTo = feeAddr()
	c.Listen = "0.0.0.0:1"
	if err := c.Validate(); err == nil {
		t.Fatal("listened beyond loopback")
	}
}

func TestHintsAndJobChecks(t *testing.T) {
	if f, m := ParseHints("x,d=512,md=64"); f != 512 || m != 64 {
		t.Fatal(f, m)
	}
	bad := bytes.Replace(liveWork, []byte(`"workset_root":"c`), []byte(`"workset_root":"d`), 1)
	if _, _, _, err := NewJob(bad, 8); err == nil {
		t.Fatal("a work-set that does not match its root was accepted")
	}
	j, _, _, err := NewJob(liveWork, 8)
	if err != nil || j.WindowTarget != 8*16777216 {
		t.Fatal(err, j.WindowTarget)
	}
	_ = time.Now
}
