package pulse

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// The node pins the same vector (pkg/chain TestPulseTxSigningBytesVector).
func TestTxSigningBytesVector(t *testing.T) {
	b := TxSigningBytes("abababababababababababababababababababababababababababababababab", 7, 0.001,
		[]byte(`{"op":"join","pool":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}`))
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != "809119a56e49435857355a33fc40b3ad2d84af5a18adab2a66110728f2766a95" {
		t.Fatalf("vector %s", got)
	}
}

func TestSettleEnvelopeVerifies(t *testing.T) {
	k, _ := NewKeyPair()
	sb := &SignedBatch{Body: []byte{1, 2, 3}, Sig: []byte{4, 5}}
	env, err := SettleEnvelope(k, 3, sb)
	if err != nil {
		t.Fatal(err)
	}
	pkb, _ := hex.DecodeString(env.PublicKey)
	pk, _ := ParsePublicKey(pkb)
	sig, _ := hex.DecodeString(env.Signature)
	if env.Sender != string(k.ID()) || !Verify(pk, "", TxSigningBytes(env.Sender, env.Nonce, env.Fee, env.Payload), sig) {
		t.Fatal("settle envelope does not verify")
	}
	if string(env.Payload) != `{"op":"settle","batch":"010203","batch_sig":"0405"}` {
		t.Fatalf("payload %s", env.Payload)
	}
}

func TestReceiptSignVerify(t *testing.T) {
	k, _ := NewKeyPair()
	m, _ := NewKeyPair()
	r := Receipt{Pool: k.ID(), Index: 41, Owner: m.ID(), Worker: "rig1", JobID: "j", Nonce: "00", BatchCount: 1, Difficulty: 9, AtUnixMs: 5}
	sig, err := SignReceipt(k, r)
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(k.Pub.Bytes())
	if !VerifyReceipt(pub, r, sig) {
		t.Fatal("receipt does not verify")
	}
	tampered := r
	tampered.Difficulty = 10
	if VerifyReceipt(pub, tampered, sig) {
		t.Fatal("a tampered receipt verifies")
	}
	other := hex.EncodeToString(m.Pub.Bytes())
	if VerifyReceipt(other, r, sig) {
		t.Fatal("a receipt verifies under another key")
	}
	if _, err := SignReceipt(m, r); err == nil {
		t.Fatal("signed a receipt for another pool")
	}
}

func TestRecomputeWindowMatchesTIDES(t *testing.T) {
	a := Address("aa" + "00000000000000000000000000000000000000000000000000000000000000")
	b := Address("bb" + "00000000000000000000000000000000000000000000000000000000000000")
	log := []LogShare{{3, a, 5}, {2, b, 10}, {1, a, 10}}
	ws := []WindowShare{{a, 5}, {b, 10}, {a, 10}}
	w1, f1, err1 := RecomputeWindow(log, 18)
	w2, f2, err2 := TIDESWindow(ws, 18)
	if err1 != nil || err2 != nil || f1 != f2 || !reflect.DeepEqual(w1, w2) {
		t.Fatalf("recompute %v %d %v vs %v %d %v", w1, f1, err1, w2, f2, err2)
	}
}

// Sabotage gaps (2026-11-16).
func TestReceiptMustNameTheSigningPool(t *testing.T) {
	k, _ := NewKeyPair()
	m, _ := NewKeyPair()
	r := Receipt{Pool: m.ID(), Index: 1, Owner: m.ID(), Difficulty: 1}
	sig, _ := k.Sign(ReceiptDomain, ReceiptBytes(r)) // k signs a receipt that names m's pool
	if VerifyReceipt(hex.EncodeToString(k.Pub.Bytes()), r, hex.EncodeToString(sig)) {
		t.Fatal("a receipt naming another pool verified")
	}
}

func TestTxSigningBytesFeeIsPlainDecimal(t *testing.T) {
	b := string(TxSigningBytes("a", 1, 0.00000001, []byte("{}")))
	if !strings.Contains(b, `"fee":"0.00000001"`) {
		t.Fatalf("fee encoding %q", b)
	}
}
