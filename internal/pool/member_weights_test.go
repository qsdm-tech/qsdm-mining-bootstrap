package pool

import (
	"strings"
	"testing"

	"github.com/qsdm-tech/qsdm-mining-bootstrap/pulse"
)

// The chain refuses a settlement whose weight owner is not an on-chain member of the settling pool, so shares from
// an address that never joined (or has left) must carry no weight in a batch the pool signs.
func TestMemberWeightsKeepsOnlyMembers(t *testing.T) {
	a, b, c := pulse.Address(strings.Repeat("a", 64)), pulse.Address(strings.Repeat("b", 64)), pulse.Address(strings.Repeat("c", 64))
	ws := []pulse.Weight{{Owner: a, Weight: 5}, {Owner: b, Weight: 99}, {Owner: c, Weight: 1}}
	got := memberWeights(ws, []string{string(a), string(c)})
	if len(got) != 2 || got[0].Owner != a || got[1].Owner != c {
		t.Fatalf("member weights %v", got)
	}
	if len(ws) != 3 || ws[1].Owner != b {
		t.Fatalf("the window slice was changed: %v", ws)
	}
	if got := memberWeights(ws, nil); len(got) != 0 {
		t.Fatalf("no members: %v", got)
	}
}
