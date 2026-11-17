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
	LastSeq        uint64            `json:"last_seq"`
	Escrowed       []EscrowedProof   `json:"escrowed"`
	Owed           map[string]uint64 `json:"owed"`
	AccountNonce   uint64            `json:"account_nonce"`
	AccountPresent bool              `json:"account_present"`
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
	pl.Pool.mu.Lock()
	pl.Pool.chain.Pools = st.Pools
	if st.Pool != nil {
		pl.Pool.chainPool = *st.Pool
	}
	pl.Pool.mu.Unlock()
	return nil
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
