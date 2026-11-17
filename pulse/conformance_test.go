package pulse

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Conformance is the vector the QSDM node's internal/pulse must reproduce:
// the same batch body, a signature that verifies, and the same split.
type Conformance struct {
	PublicKey string             `json:"public_key"`
	PoolID    Address            `json:"pool_id"`
	Body      string             `json:"body"`
	Sig       string             `json:"signature"`
	Pooled    uint64             `json:"pooled"`
	Owed      map[Address]uint64 `json:"owed"`
	CapLeft   map[Address]uint64 `json:"cap_left"`
	Payouts   []Payout           `json:"payouts"`
	OwedAfter map[Address]uint64 `json:"owed_after"`
}

func conformanceVector(t *testing.T) Conformance {
	var seed [mldsa87.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	k := KeyPairFromSeed(seed)
	b := &Batch{Version: BatchVersion, PoolID: k.ID(), Seq: 3, Height: 1_230_005, FeeBPS: 150, FeeTo: addr(77),
		FloorDust: 5_000_000, ProofIDs: []string{"lmp1-aa", "lmp1-bb"},
		Weights: []Weight{{addr(1), 3 << 24}, {addr(2), 5 << 24}, {addr(3), 1}}}
	sb, err := SignBatch(k, b)
	if err != nil {
		t.Fatal(err)
	}
	owed := map[Address]uint64{addr(3): 4_000_000, addr(9): 1_000}
	capLeft := map[Address]uint64{addr(1): 100_000_000}
	in := SplitInput{Pooled: 712_981_974, FeeBPS: b.FeeBPS, FeeTo: b.FeeTo, FloorDust: b.FloorDust, Weights: b.Weights, Owed: owed,
		CapLeft: func(a Address) uint64 {
			if v, ok := capLeft[a]; ok {
				return v
			}
			return ^uint64(0)
		}}
	r, err := Split(in)
	if err != nil || !Conserved(in, r) {
		t.Fatal(err)
	}
	return Conformance{PublicKey: hex.EncodeToString(k.Pub.Bytes()), PoolID: k.ID(), Body: hex.EncodeToString(sb.Body),
		Sig: hex.EncodeToString(sb.Sig), Pooled: in.Pooled, Owed: owed, CapLeft: capLeft, Payouts: r.Payouts, OwedAfter: r.Owed}
}

// PULSE_WRITE_CONFORMANCE=<path> go test ./pulse -run TestConformance writes the vector.
func TestConformance(t *testing.T) {
	c := conformanceVector(t)
	if p := os.Getenv("PULSE_WRITE_CONFORMANCE"); p != "" {
		b, _ := json.MarshalIndent(c, "", " ")
		if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	body, _ := hex.DecodeString(c.Body)
	if _, err := DecodeBatch(body); err != nil {
		t.Fatal(err)
	}
}
