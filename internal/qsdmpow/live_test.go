package qsdmpow

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The live producer's /api/v1/mining/work of 2026-11-16 (height 1,118,166):
// rebuilding the work-set root from its cells must give the root it serves.
func TestLiveWorkSetRoot(t *testing.T) {
	raw, err := os.ReadFile("testdata/live-work-20261116.json")
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		WorkSetRoot string `json:"workset_root"`
		WorkSet     []struct {
			Cells []struct {
				ID          string `json:"id"`
				ContentHash string `json:"content_hash"`
			} `json:"cells"`
		} `json:"workset"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	var ws WorkSet
	for _, b := range w.WorkSet {
		var cells []Cell
		for _, c := range b.Cells {
			id, _ := hex.DecodeString(c.ID)
			ch, _ := hex.DecodeString(c.ContentHash)
			var x Cell
			x.ID = id
			copy(x.ContentHash[:], ch)
			cells = append(cells, x)
		}
		ws.Batches = append(ws.Batches, cells)
	}
	root := ws.Root()
	if hex.EncodeToString(root[:]) != w.WorkSetRoot {
		t.Fatalf("root %x, live %s", root, w.WorkSetRoot)
	}
	if _, err := ws.PrefixRoot(0); err == nil {
		t.Fatal("prefix 0 accepted")
	}
}
