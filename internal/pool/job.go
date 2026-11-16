// Package pool is the PULSE pool server: jobs from the QSDM producer, share
// checks, the TIDES window, signed settlement batches, a journal and the
// HTTP/JSON miner API.
package pool

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/blackbeardONE/qsdm-mining-bootstrap/internal/qsdmpow"
)

// ProducerWork is GET /api/v1/mining/work on the QSDM producer.
type ProducerWork struct {
	Epoch             uint64 `json:"epoch"`
	Height            uint64 `json:"height"`
	HeaderHash        string `json:"header_hash"`
	Difficulty        string `json:"difficulty"`
	DAGSize           uint32 `json:"dag_size"`
	WorkSetRoot       string `json:"workset_root"`
	BatchCountMaximum uint32 `json:"batch_count_maximum"`
	WorkSet           []struct {
		Cells []struct {
			ID          string `json:"id"`
			ContentHash string `json:"content_hash"`
		} `json:"cells"`
	} `json:"workset"`
}

// Job is one unit of work handed to miners, with its window target frozen
// at issue time (window factor x the network difficulty of this job).
type Job struct {
	ID           string
	Height       uint64
	Epoch        uint64
	Header       [32]byte
	NetDiff      *big.Int
	NetTarget    *big.Int
	WindowTarget uint64
	Roots        map[[32]byte]uint32 // allowed batch_root -> batch_count
	DAGKey       string
	Raw          json.RawMessage // the producer's work, passed to miners as is
}

// MaxDAGEntries bounds the DAG the pool will build (2^26 = 2 GiB, the
// protocol's production size). The live network served N = 1024 on 2026-11-16.
const MaxDAGEntries = qsdmpow.ProductionDAGSize

func decodeHex32(s, name string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("pool: %s is not 32 hex bytes", name)
	}
	copy(out[:], b)
	return out, nil
}

// NewJob checks the producer's work and derives the job: the work-set root
// must rebuild from the cells, and the allowed batch roots are the prefix
// roots 1..batch_count_maximum.
func NewJob(raw []byte, windowFactor uint64) (*Job, *qsdmpow.WorkSet, [32]byte, error) {
	var w ProducerWork
	var root [32]byte
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, nil, root, fmt.Errorf("pool: work: %w", err)
	}
	hdr, err := decodeHex32(w.HeaderHash, "header_hash")
	if err != nil {
		return nil, nil, root, err
	}
	if root, err = decodeHex32(w.WorkSetRoot, "workset_root"); err != nil {
		return nil, nil, root, err
	}
	if w.DAGSize < 2 || w.DAGSize > MaxDAGEntries {
		return nil, nil, root, fmt.Errorf("pool: dag_size %d out of range", w.DAGSize)
	}
	d, ok := new(big.Int).SetString(w.Difficulty, 10)
	if !ok || d.Sign() <= 0 || !d.IsUint64() {
		return nil, nil, root, errors.New("pool: difficulty")
	}
	tgt, err := qsdmpow.TargetFromDifficulty(d)
	if err != nil {
		return nil, nil, root, err
	}
	wt, err := windowTarget(windowFactor, d.Uint64())
	if err != nil {
		return nil, nil, root, err
	}
	var ws qsdmpow.WorkSet
	for _, b := range w.WorkSet {
		var cells []qsdmpow.Cell
		for _, c := range b.Cells {
			id, err1 := hex.DecodeString(c.ID)
			ch, err2 := decodeHex32(c.ContentHash, "content_hash")
			if err1 != nil || err2 != nil || len(id) == 0 {
				return nil, nil, root, errors.New("pool: bad work-set cell")
			}
			cells = append(cells, qsdmpow.Cell{ID: id, ContentHash: ch})
		}
		ws.Batches = append(ws.Batches, cells)
	}
	if len(ws.Batches) == 0 || ws.Root() != root {
		return nil, nil, root, errors.New("pool: the work-set does not rebuild to workset_root")
	}
	maxC := w.BatchCountMaximum
	if maxC == 0 || maxC > uint32(len(ws.Batches)) {
		maxC = uint32(len(ws.Batches))
	}
	roots := map[[32]byte]uint32{}
	for c := uint32(1); c <= maxC; c++ {
		r, err := ws.PrefixRoot(c)
		if err != nil {
			return nil, nil, root, err
		}
		roots[r] = c
	}
	j := &Job{
		ID:           strconv.FormatUint(w.Height, 10) + "-" + w.HeaderHash[:16],
		Height:       w.Height,
		Epoch:        w.Epoch,
		Header:       hdr,
		NetDiff:      d,
		NetTarget:    tgt,
		WindowTarget: wt,
		Roots:        roots,
		DAGKey:       fmt.Sprintf("%d-%s-%d", w.Epoch, w.WorkSetRoot, w.DAGSize),
		Raw:          append(json.RawMessage{}, raw...),
	}
	return j, &ws, root, nil
}

func windowTarget(factor, netDiff uint64) (uint64, error) {
	if factor == 0 {
		return 0, errors.New("pool: window factor must be > 0")
	}
	x := new(big.Int).Mul(new(big.Int).SetUint64(factor), new(big.Int).SetUint64(netDiff))
	if !x.IsUint64() {
		return 0, errors.New("pool: window target overflows")
	}
	return x.Uint64(), nil
}
