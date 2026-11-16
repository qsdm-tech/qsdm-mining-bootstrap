package qsdmpow

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// Cell is one parent-cell reference of a work-set batch (§3.2).
type Cell struct {
	ID          []byte
	ContentHash [32]byte
}

// WorkSet is the canonical work-set as /api/v1/mining/work serves it
// (cells sorted by ID inside each batch, batches in canonical order).
type WorkSet struct {
	Batches [][]Cell
}

// BatchHash is SHA-256(0x00 || id_1 || content_1 || ...), as QSDM's mining.BatchHash.
func BatchHash(cells []Cell) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte{0x00})
	for _, c := range cells {
		_, _ = h.Write(c.ID)
		_, _ = h.Write(c.ContentHash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Root is the Merkle root over every batch (it seeds the epoch DAG).
func (ws WorkSet) Root() [32]byte {
	hs := make([][32]byte, len(ws.Batches))
	for i, b := range ws.Batches {
		hs[i] = BatchHash(b)
	}
	return merkleRoot(hs)
}

// PrefixRoot is the root over the first count batches: the batch_root a
// proof claiming batch_count = count must carry (§7.1).
func (ws WorkSet) PrefixRoot(count uint32) ([32]byte, error) {
	if count == 0 {
		return [32]byte{}, errors.New("qsdmpow: prefix count must be > 0")
	}
	if uint64(count) > uint64(len(ws.Batches)) {
		return [32]byte{}, fmt.Errorf("qsdmpow: prefix count %d exceeds work-set size %d", count, len(ws.Batches))
	}
	hs := make([][32]byte, count)
	for i := uint32(0); i < count; i++ {
		hs[i] = BatchHash(ws.Batches[i])
	}
	return merkleRoot(hs), nil
}

func merkleRoot(hashes [][32]byte) [32]byte {
	if len(hashes) == 0 {
		return [32]byte{}
	}
	level := make([][32]byte, len(hashes))
	for i, x := range hashes {
		h := sha256.New()
		_, _ = h.Write([]byte{0x01})
		_, _ = h.Write(x[:])
		copy(level[i][:], h.Sum(nil))
	}
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][32]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha256.New()
			_, _ = h.Write([]byte{0x02})
			_, _ = h.Write(level[i][:])
			_, _ = h.Write(level[i+1][:])
			copy(next[i/2][:], h.Sum(nil))
		}
		level = next
	}
	return level[0]
}
