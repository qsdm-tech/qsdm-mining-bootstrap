package pool

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one journal line. The journal is the pool's only state: replaying
// it rebuilds sessions, the share window, reported proofs and batches.
type Event struct {
	Type       string       `json:"type"`
	At         time.Time    `json:"at"`
	Session    string       `json:"session,omitempty"`
	Login      string       `json:"login,omitempty"`
	FixedDiff  uint64       `json:"fixed_diff,omitempty"`
	MinDiff    uint64       `json:"min_diff,omitempty"`
	Owner      string       `json:"owner,omitempty"`
	Worker     string       `json:"worker,omitempty"`
	Difficulty uint64       `json:"difficulty,omitempty"`
	JobID      string       `json:"job_id,omitempty"`
	Solution   bool         `json:"solution,omitempty"`
	ProofID    string       `json:"proof_id,omitempty"`
	Batch      *BatchRecord `json:"batch,omitempty"`
	Index      uint64       `json:"index,omitempty"` // share: the pool's running share number
	Seq        uint64       `json:"seq,omitempty"`   // submitted: the batch
	TxID       string       `json:"tx_id,omitempty"` // submitted: the node's tx ID
}

// Journal is an append-only JSON-lines file, fsynced on every append.
type Journal struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// OpenJournal opens (or creates) dir/pulse-journal.jsonl with mode 0600.
func OpenJournal(dir string) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "pulse-journal.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return &Journal{path: path, f: f}, nil
}

// Append writes one event and syncs it to disk.
func (j *Journal) Append(ev Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return j.f.Sync()
}

// Replay feeds every complete line to apply. A torn last line (a crash
// mid-write) is ignored; a bad line anywhere else is an error.
func (j *Journal) Replay(apply func(Event)) error {
	f, err := os.Open(j.path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var pendingErr error
	n := 0
	for sc.Scan() {
		n++
		if pendingErr != nil {
			return pendingErr
		}
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			pendingErr = fmt.Errorf("journal line %d: %w", n, err)
			continue
		}
		apply(ev)
	}
	if err := sc.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return err
	}
	return nil
}

// Close closes the file.
func (j *Journal) Close() error { return j.f.Close() }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
