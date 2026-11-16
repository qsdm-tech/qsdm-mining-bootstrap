package qsdmpow

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// Vectors printed by QSDM's own pkg/mining (HL2 b6b3fba) for the same inputs:
// epoch 7, root[i]=i, header[i]=255-i, batch_root[i]=7i, N=4096,
// nonce[0]=0xAB, nonce[15]=k.
var golden = []struct{ mix, hash string }{
	{"e05b1caa2c1700fe21fdb341acf74487bf2f914acba010f4a4784e0f0ce6fcd6", "cc69e9504ab0464ef511d489e49129b5a577a19da80bcc18f576e2de793bad0c"},
	{"6a353595cef54e3e111e8a502edae4d8ac9aaeb34fdfd562340efa238fa472be", "6a1745f0a62ec135a8fe0e1a4d81deca98e8406fc13ec980f4903641dac99e07"},
	{"fb63a2ded328ccc9eb0557bc5400c222c992e65a1cb99df6bf4a00d12786be95", "e7db118ad1e5170b358fef1ccd0aa0025d6d835b6f56fc840fac63a1fc52ec76"},
}

func TestGoldenAgainstQSDM(t *testing.T) {
	var root, hdr, br [32]byte
	for i := range root {
		root[i] = byte(i)
		hdr[i] = byte(255 - i)
		br[i] = byte(i * 7)
	}
	s := DAGSeed(7, root)
	if got := hex.EncodeToString(s[:]); got != "43bae624b6143c4e05780b30257ea3fd6dd441d9174a460adf3ad61ab20dd92d" {
		t.Fatalf("seed %s", got)
	}
	d, err := NewInMemoryDAG(7, root, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for k, g := range golden {
		var nonce [16]byte
		nonce[0] = 0xAB
		nonce[15] = byte(k)
		mix, err := ComputeMixDigest(hdr, nonce, d)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(mix[:]) != g.mix {
			t.Fatalf("mix %d differs from QSDM", k)
		}
		h := ProofPoWHash(hdr, nonce, br, mix)
		if hex.EncodeToString(h[:]) != g.hash {
			t.Fatalf("hash %d differs from QSDM", k)
		}
	}
	tg, _ := TargetFromDifficulty(DifficultyForBits(20))
	if tg.Text(16) != "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe" {
		t.Fatalf("target %s", tg.Text(16))
	}
	if _, err := TargetFromDifficulty(big.NewInt(0)); err == nil {
		t.Fatal("zero difficulty accepted")
	}
}
