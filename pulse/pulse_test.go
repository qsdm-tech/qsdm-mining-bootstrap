package pulse

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func addr(i int) Address { return Address(fmt.Sprintf("%064x", i)) }

func testBatch(t *testing.T, k *KeyPair) *Batch {
	t.Helper()
	return &Batch{Version: BatchVersion, PoolID: k.ID(), Seq: 7, Height: 1_250_000, FeeBPS: 0, FeeTo: addr(99),
		FloorDust: 10_000_000, ProofIDs: []string{"p1", "p2"},
		Weights: []Weight{{addr(1), 5}, {addr(2), 9}}}
}

func TestBatchRoundTripAndSignature(t *testing.T) {
	k, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b := testBatch(t, k)
	sb, err := SignBatch(k, b)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeBatch(sb.Body)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := d.Encode()
	if !bytes.Equal(again, sb.Body) || d.PoolID != b.PoolID || d.Weights[1].Weight != 9 {
		t.Fatal("round trip changed the batch")
	}
	if !Verify(k.Pub, BatchDomain, sb.Body, sb.Sig) {
		t.Fatal("signature does not verify")
	}
	tampered := append([]byte{}, sb.Body...)
	tampered[len(tampered)-1] ^= 1
	if Verify(k.Pub, BatchDomain, tampered, sb.Sig) {
		t.Fatal("tampered body verified")
	}
	if Verify(k.Pub, "QSDM/other\x00", sb.Body, sb.Sig) {
		t.Fatal("signature verified under another domain")
	}
	other, _ := NewKeyPair()
	if _, err := SignBatch(other, b); err == nil {
		t.Fatal("a key signed another pool's batch")
	}
}

func TestBatchRejectsMalformed(t *testing.T) {
	k, _ := NewKeyPair()
	bad := []func(b *Batch){
		func(b *Batch) { b.Version = 2 },
		func(b *Batch) { b.FeeBPS = 10001 },
		func(b *Batch) { b.ProofIDs = nil },
		func(b *Batch) { b.ProofIDs = []string{"x", "x"} },
		func(b *Batch) { b.ProofIDs = []string{strings.Repeat("a", MaxProofIDLen+1)} },
		func(b *Batch) { b.Weights = []Weight{{addr(2), 1}, {addr(1), 1}} },
		func(b *Batch) { b.Weights = []Weight{{addr(1), 1}, {addr(1), 1}} },
		func(b *Batch) { b.Weights = []Weight{{addr(1), 0}} },
		func(b *Batch) { b.FeeTo = "nope" },
	}
	for i, f := range bad {
		b := testBatch(t, k)
		f(b)
		if _, err := b.Encode(); err == nil {
			t.Fatalf("case %d encoded", i)
		}
	}
	b := testBatch(t, k)
	body, _ := b.Encode()
	if _, err := DecodeBatch(append(body, 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := DecodeBatch(body[:len(body)-1]); err == nil {
		t.Fatal("truncated batch accepted")
	}
}

func FuzzDecodeBatch(f *testing.F) {
	k, _ := NewKeyPair()
	b := &Batch{Version: BatchVersion, PoolID: k.ID(), Seq: 1, Height: 2, FeeTo: addr(3), ProofIDs: []string{"a"}, Weights: []Weight{{addr(1), 1}}}
	body, _ := b.Encode()
	f.Add(body)
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, p []byte) {
		d, err := DecodeBatch(p)
		if err != nil {
			return
		}
		again, err := d.Encode()
		if err != nil || !bytes.Equal(again, p) {
			t.Fatalf("accepted a non-canonical batch")
		}
	})
}

func TestLogin(t *testing.T) {
	a := strings.Repeat("A", 64)
	l, err := ParseLogin(a + ".rig_1")
	if err != nil || l.Address != Address(strings.Repeat("a", 64)) || l.Worker != "rig_1" {
		t.Fatalf("%v %v", l, err)
	}
	for _, s := range []string{"", a[:63], a + ".", a + ".bad name", a + "." + strings.Repeat("w", 33), strings.Repeat("z", 64)} {
		if _, err := ParseLogin(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestTIDESWindow(t *testing.T) {
	shares := []WindowShare{{addr(1), 100}, {addr(2), 50}, {addr(1), 30}, {addr(3), 1000}}
	w, cum, err := TIDESWindow(shares, 170)
	if err != nil || cum != 170 {
		t.Fatal(cum, err)
	}
	// newest 100 (a1) + 50 (a2) + 20 of the 30 (a1); a3 is outside the window.
	if len(w) != 2 || w[0] != (Weight{addr(1), 120}) || w[1] != (Weight{addr(2), 50}) {
		t.Fatalf("%v", w)
	}
	w, cum, _ = TIDESWindow(shares[:2], 1000) // window not full: all count
	if cum != 150 || len(w) != 2 {
		t.Fatal(cum, w)
	}
	if _, err := WindowTarget(8, 1<<62); err == nil {
		t.Fatal("overflow accepted")
	}
	if x, _ := WindowTarget(8, 16777216); x != 134217728 {
		t.Fatal(x)
	}
}

func noCap(Address) uint64 { return ^uint64(0) }

func TestSplitBasics(t *testing.T) {
	fee := addr(99)
	in := SplitInput{Pooled: 356_490_987, FeeBPS: 0, FeeTo: fee, FloorDust: 0,
		Weights: []Weight{{addr(1), 1}, {addr(2), 2}}, CapLeft: noCap}
	r, err := Split(in)
	if err != nil {
		t.Fatal(err)
	}
	if !Conserved(in, r) {
		t.Fatal("not conserved")
	}
	// 0 bps: the fee recipient gets only the rounding dust.
	got := map[Address]uint64{}
	for _, p := range r.Payouts {
		got[p.To] = p.Amount
	}
	if got[addr(1)] != 118_830_329 || got[addr(2)] != 237_660_658 || got[fee] != 0 && got[fee] != r.Dust || r.Fee != 0 {
		t.Fatalf("%v fee %d dust %d", got, r.Fee, r.Dust)
	}
}

func TestSplitFeeFloorCarryAndCap(t *testing.T) {
	fee := addr(99)
	in := SplitInput{Pooled: 1000, FeeBPS: 100, FeeTo: fee, FloorDust: 300,
		Weights: []Weight{{addr(1), 3}, {addr(2), 1}},
		Owed:    map[Address]uint64{addr(2): 60, addr(5): 40, addr(6): 500},
		CapLeft: func(a Address) uint64 {
			if a == addr(1) {
				return 200
			}
			return ^uint64(0)
		}}
	r, err := Split(in)
	if err != nil {
		t.Fatal(err)
	}
	if !Conserved(in, r) {
		t.Fatal("not conserved")
	}
	// fee 10; dist 990: a1 742 (cap 200 -> pay 200, owe 542), a2 247+60=307 >= floor -> paid;
	// a5 left the window with 40 < floor -> dust; a6 left with 500 >= floor -> paid.
	if r.Owed[addr(1)] != 542 || r.Owed[addr(2)] != 0 || r.Owed[addr(5)] != 0 {
		t.Fatalf("owed %v", r.Owed)
	}
	got := map[Address]uint64{}
	for _, p := range r.Payouts {
		got[p.To] = p.Amount
	}
	if got[addr(1)] != 200 || got[addr(2)] != 307 || got[addr(6)] != 500 || got[fee] != 10+1+40 {
		t.Fatalf("%v", got)
	}
	// Under the floor while still in the window: carried, not paid.
	in2 := SplitInput{Pooled: 100, FeeTo: fee, FloorDust: 300, Weights: []Weight{{addr(1), 1}}, CapLeft: noCap}
	r2, _ := Split(in2)
	if r2.Owed[addr(1)] != 100 || len(r2.Payouts) != 0 || !Conserved(in2, r2) {
		t.Fatalf("%v %v", r2.Owed, r2.Payouts)
	}
}

func TestSplitConservesRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 3000; n++ {
		var ws []Weight
		for i := 0; i < 1+rng.Intn(8); i++ {
			ws = append(ws, Weight{addr(i * 3), uint64(1 + rng.Intn(1_000_000))})
		}
		owed := map[Address]uint64{}
		for i := 0; i < rng.Intn(5); i++ {
			owed[addr(1+i*5)] = uint64(rng.Intn(500_000))
		}
		in := SplitInput{Pooled: uint64(rng.Int63n(1_000_000_000)), FeeBPS: uint16(rng.Intn(10001)), FeeTo: addr(500),
			FloorDust: uint64(rng.Intn(300_000)), Weights: ws, Owed: owed,
			CapLeft: func(a Address) uint64 { return uint64(len(a)) * 1_000_000 * uint64(1+rng.Intn(3)) }}
		r, err := Split(in)
		if err != nil {
			t.Fatal(err)
		}
		if !Conserved(in, r) {
			t.Fatalf("case %d not conserved", n)
		}
		for _, p := range r.Payouts {
			if p.Amount == 0 {
				t.Fatal("zero payout")
			}
		}
	}
}
