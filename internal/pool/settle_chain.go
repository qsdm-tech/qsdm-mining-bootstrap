package pool

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/qsdm-tech/qsdm-mining-bootstrap/pulse"
)

// EscrowedProof is one of the pool's unsettled escrowed proofs on the chain.
type EscrowedProof struct {
	ProofID string `json:"proof_id"`
	Owner   string `json:"owner"`
	Dust    uint64 `json:"dust"`
	Height  uint64 `json:"height"`
}

// chainPoolState is the node's view of this pool (/api/v1/pulse/state?pool=).
type chainPoolState struct {
	LastSeq  uint64            `json:"last_seq"`
	Escrowed []EscrowedProof   `json:"escrowed"`
	Owed     map[string]uint64 `json:"owed"`
	// Members are the owners that joined this pool on chain. The chain refuses a settlement that names any other
	// owner as a weight owner, so the pool signs weights for these owners only.
	Members        []string `json:"members"`
	AccountNonce   uint64   `json:"account_nonce"`
	AccountPresent bool     `json:"account_present"`
}

// FetchChainState reads the rule's status and this pool's chain state.
func (pl *Poller) FetchChainState(ctx context.Context) error {
	b, err := pl.get(ctx, "/pulse/state?pool="+string(pl.Pool.key.ID()))
	if err != nil {
		return err
	}
	var st struct {
		Active bool            `json:"active"`
		Pools  []ChainPool     `json:"pools"`
		Pool   *chainPoolState `json:"pool"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if st.Pool != nil && st.Pool.Members == nil {
		// A node that does not list members yet (before rc1116): ask /pulse/member for every owner with shares.
		ms, err := pl.membersByLookup(ctx)
		if err != nil {
			return err
		}
		st.Pool.Members = ms
	}
	pl.Pool.mu.Lock()
	pl.Pool.chain.Pools = st.Pools
	if st.Pool != nil {
		pl.Pool.chainPool = *st.Pool
	}
	pl.Pool.mu.Unlock()
	return nil
}

// membersByLookup asks the node, owner by owner, which share owners are members of this pool.
func (pl *Poller) membersByLookup(ctx context.Context) ([]string, error) {
	pl.Pool.mu.Lock()
	seen := map[pulse.Address]bool{}
	for _, s := range pl.Pool.shares {
		seen[s.Owner] = true
	}
	pl.Pool.mu.Unlock()
	me := string(pl.Pool.key.ID())
	out := []string{}
	for owner := range seen {
		b, err := pl.get(ctx, "/pulse/member?owner="+string(owner))
		if err != nil {
			return nil, err
		}
		var m struct {
			Member bool   `json:"member"`
			Pool   string `json:"pool"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		if m.Member && m.Pool == me {
			out = append(out, string(owner))
		}
	}
	sort.Strings(out)
	return out, nil
}

// Submit sends a recorded batch to the node as the pool's settle tx.
func (pl *Poller) Submit(ctx context.Context, rec *BatchRecord) error {
	body, err := hex.DecodeString(rec.BodyHex)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(rec.SigHex)
	if err != nil {
		return err
	}
	pl.Pool.mu.Lock()
	nonce := pl.Pool.chainPool.AccountNonce
	pl.Pool.mu.Unlock()
	env, err := pulse.SettleEnvelope(pl.Pool.key, nonce, &pulse.SignedBatch{Body: body, Sig: sig})
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(env)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pl.API+"/pulse/submit-signed", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := pl.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != 200 {
		return fmt.Errorf("settle seq %d: HTTP %d: %s", rec.Seq, resp.StatusCode, bytes.TrimSpace(rb))
	}
	var ok struct {
		TxID string `json:"tx_id"`
	}
	if err := json.Unmarshal(rb, &ok); err != nil || ok.TxID == "" {
		return errors.New("settle: the node's answer has no tx_id")
	}
	pl.Pool.mu.Lock()
	pl.Pool.chainPool.AccountNonce++
	pl.Pool.mu.Unlock()
	return pl.Pool.record(Event{Type: "submitted", Seq: rec.Seq, TxID: ok.TxID, At: pl.Pool.now()})
}

// memberWeights keeps the window weights whose owner is an on-chain member of this pool.
func memberWeights(ws []pulse.Weight, members []string) []pulse.Weight {
	in := make(map[pulse.Address]bool, len(members))
	for _, m := range members {
		in[pulse.Address(m)] = true
	}
	out := ws[:0:0]
	for _, w := range ws {
		if in[w.Owner] {
			out = append(out, w)
		}
	}
	return out
}
