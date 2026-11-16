package pulse

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
)

// TxDomain separates PULSE transaction signatures (the node's
// chain.PulseTxSigningBytes; pinned by TestTxSigningBytesVector).
const TxDomain = "QSDM/pulse/tx/v1\x00"

// ReceiptDomain separates share receipts from every other signature.
const ReceiptDomain = "QSDM/pulse/receipt/v1\x00"

// TxSigningBytes is what a PULSE transaction's sender signs: the domain, then
// a canonical JSON of sender, nonce, fee and payload. It must equal the
// node's chain.PulseTxSigningBytes byte for byte.
func TxSigningBytes(sender string, nonce uint64, fee float64, payload []byte) []byte {
	body, _ := json.Marshal(struct {
		Sender  string `json:"sender"`
		Nonce   uint64 `json:"nonce"`
		Fee     string `json:"fee"`
		Payload string `json:"payload"`
	}{sender, nonce, strconv.FormatFloat(fee, 'f', -1, 64), string(payload)})
	return append([]byte(TxDomain), body...)
}

// Envelope is a signed PULSE transaction as the node's
// POST /api/v1/pulse/submit-signed takes it.
type Envelope struct {
	Sender    string          `json:"sender"`
	Nonce     uint64          `json:"nonce"`
	Fee       float64         `json:"fee"`
	Payload   json.RawMessage `json:"payload"`
	PublicKey string          `json:"public_key"`
	Signature string          `json:"signature"`
}

// SignEnvelope signs a PULSE action with k (the sender is k's address).
func SignEnvelope(k *KeyPair, nonce uint64, fee float64, action any) (*Envelope, error) {
	payload, err := json.Marshal(action)
	if err != nil {
		return nil, err
	}
	sender := string(k.ID())
	sig, err := k.Sign("", TxSigningBytes(sender, nonce, fee, payload))
	if err != nil {
		return nil, err
	}
	return &Envelope{Sender: sender, Nonce: nonce, Fee: fee, Payload: payload,
		PublicKey: hex.EncodeToString(k.Pub.Bytes()), Signature: hex.EncodeToString(sig)}, nil
}

// SettleEnvelope is the pool's settle transaction for a signed batch.
func SettleEnvelope(k *KeyPair, nonce uint64, sb *SignedBatch) (*Envelope, error) {
	return SignEnvelope(k, nonce, 0, struct {
		Op       string `json:"op"`
		Batch    string `json:"batch"`
		BatchSig string `json:"batch_sig"`
	}{"settle", hex.EncodeToString(sb.Body), hex.EncodeToString(sb.Sig)})
}

// Receipt is the pool's signed statement that one share was counted. A miner
// keeps it: with the pool's public key anyone can verify it, and the share
// (by Index) must then appear in every published window log that covers it.
type Receipt struct {
	Pool       Address `json:"pool"`
	Index      uint64  `json:"index"` // the pool's running share number
	Owner      Address `json:"owner"`
	Worker     string  `json:"worker"`
	JobID      string  `json:"job_id"`
	Nonce      string  `json:"nonce"`
	BatchCount uint32  `json:"batch_count"`
	Difficulty uint64  `json:"difficulty"`
	AtUnixMs   int64   `json:"at_unix_ms"`
}

// ReceiptBytes is the signed form of a receipt.
func ReceiptBytes(r Receipt) []byte {
	b, _ := json.Marshal(r)
	return b
}

// SignReceipt signs r with the pool key (r.Pool must be the key's address).
func SignReceipt(k *KeyPair, r Receipt) (string, error) {
	if k.ID() != r.Pool {
		return "", errors.New("pulse: receipt pool is not this key")
	}
	sig, err := k.Sign(ReceiptDomain, ReceiptBytes(r))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

// VerifyReceipt checks a receipt against the pool's public key (hex).
func VerifyReceipt(publicKeyHex string, r Receipt, sigHex string) bool {
	pkb, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false
	}
	pk, err := ParsePublicKey(pkb)
	if err != nil || AddressOf(pk) != r.Pool {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return Verify(pk, ReceiptDomain, ReceiptBytes(r), sig)
}

// LogShare is one share of a published window log, newest first.
type LogShare struct {
	Index      uint64  `json:"index"`
	Owner      Address `json:"owner"`
	Difficulty uint64  `json:"difficulty"`
}

// RecomputeWindow recomputes a settlement's weights from its published window
// log and target, exactly as the pool did (TIDESWindow).
func RecomputeWindow(log []LogShare, target uint64) ([]Weight, uint64, error) {
	ws := make([]WindowShare, len(log))
	for i, s := range log {
		ws[i] = WindowShare{Owner: s.Owner, Difficulty: s.Difficulty}
	}
	return TIDESWindow(ws, target)
}
