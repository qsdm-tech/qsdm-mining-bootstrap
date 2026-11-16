// Package qsdmpow is the Mesh3D proof-of-work of QSDM (MINING_PROTOCOL.md
// §3.3, §5.2, §5.3), copied from QSDM pkg/mining (dag.go, pow.go; MIT, same
// copyright holder) so the pool can check shares without importing the node.
// golden_test.go pins it to vectors produced by the QSDM code itself.
package qsdmpow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// NumWalkSteps is the number of DAG lookups per attempt (§5.3).
const NumWalkSteps = 64

// ProductionDAGSize is N for the live network: 2^26 entries x 32 B = 2 GiB.
const ProductionDAGSize uint32 = 1 << 26

const dagDomainSeparator = "QSDM/mesh3d-pow/v1"

// DAG is a read-only epoch DAG.
type DAG interface {
	N() uint32
	Get(idx uint32) ([32]byte, error)
}

// DAGSeed is D_e[0] = SHA3-256("QSDM/mesh3d-pow/v1" || LE64(e) || root).
func DAGSeed(epoch uint64, workSetRoot [32]byte) [32]byte {
	h := sha3.New256()
	_, _ = h.Write([]byte(dagDomainSeparator))
	var le64 [8]byte
	binary.LittleEndian.PutUint64(le64[:], epoch)
	_, _ = h.Write(le64[:])
	_, _ = h.Write(workSetRoot[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// InMemoryDAG is a fully built DAG: D_e[i] = SHA3-256(D_e[i-1] || LE32(i)).
type InMemoryDAG struct {
	n    uint32
	data []byte
}

// NewInMemoryDAG builds the DAG for epoch e. It allocates n*32 bytes.
func NewInMemoryDAG(epoch uint64, workSetRoot [32]byte, n uint32) (*InMemoryDAG, error) {
	if n < 2 {
		return nil, errors.New("qsdmpow: DAG size N must be >= 2")
	}
	d := &InMemoryDAG{n: n, data: make([]byte, uint64(n)*32)}
	seed := DAGSeed(epoch, workSetRoot)
	copy(d.data[:32], seed[:])
	h := sha3.New256()
	var le32 [4]byte
	var digest [32]byte
	for i := uint32(1); i < n; i++ {
		h.Reset()
		_, _ = h.Write(d.data[uint64(i-1)*32 : uint64(i)*32])
		binary.LittleEndian.PutUint32(le32[:], i)
		_, _ = h.Write(le32[:])
		sum := h.Sum(digest[:0])
		copy(d.data[uint64(i)*32:uint64(i+1)*32], sum)
	}
	return d, nil
}

// N returns the number of entries.
func (d *InMemoryDAG) N() uint32 { return d.n }

// Get returns entry idx.
func (d *InMemoryDAG) Get(idx uint32) ([32]byte, error) {
	if idx >= d.n {
		return [32]byte{}, fmt.Errorf("qsdmpow: DAG index %d >= N %d", idx, d.n)
	}
	var out [32]byte
	copy(out[:], d.data[uint64(idx)*32:uint64(idx+1)*32])
	return out, nil
}

// ComputeMixDigest is the 64-step DAG walk (§5.3).
func ComputeMixDigest(headerHash [32]byte, nonce [16]byte, dag DAG) ([32]byte, error) {
	h := sha3.New256()
	_, _ = h.Write(headerHash[:])
	_, _ = h.Write(nonce[:])
	var mix [32]byte
	copy(mix[:], h.Sum(nil))
	n := dag.N()
	var digest [32]byte
	for s := 0; s < NumWalkSteps; s++ {
		idx := binary.BigEndian.Uint32(mix[0:4]) % n
		entry, err := dag.Get(idx)
		if err != nil {
			return [32]byte{}, err
		}
		h.Reset()
		_, _ = h.Write(mix[:])
		_, _ = h.Write(entry[:])
		sum := h.Sum(digest[:0])
		copy(mix[:], sum)
	}
	return mix, nil
}

// ProofPoWHash is H(header || nonce || batch_root || mix_digest) (§5.2).
func ProofPoWHash(headerHash [32]byte, nonce [16]byte, batchRoot, mixDigest [32]byte) [32]byte {
	h := sha3.New256()
	_, _ = h.Write(headerHash[:])
	_, _ = h.Write(nonce[:])
	_, _ = h.Write(batchRoot[:])
	_, _ = h.Write(mixDigest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MeetsTarget reports hash < target, both unsigned 256-bit big-endian.
func MeetsTarget(hash [32]byte, target *big.Int) bool {
	if target == nil || target.Sign() <= 0 {
		return false
	}
	return new(big.Int).SetBytes(hash[:]).Cmp(target) < 0
}

var maxTarget256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// TargetFromDifficulty is QSDM's mining.TargetFromDifficulty:
// floor((2^256-1) / d) - 1, or 0 when the quotient is 0.
func TargetFromDifficulty(d *big.Int) (*big.Int, error) {
	if d == nil || d.Sign() <= 0 {
		return nil, errors.New("qsdmpow: difficulty must be > 0")
	}
	q := new(big.Int).Quo(maxTarget256, d)
	if q.Sign() == 0 {
		return new(big.Int), nil
	}
	return q.Sub(q, big.NewInt(1)), nil
}

// DifficultyForBits is 2^bits, as the producer's difficulty_bits defines it.
func DifficultyForBits(bits uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), bits) }
