package pool

import (
	"strings"
	"testing"
	"time"

	"github.com/qsdm-tech/qsdm-mining-bootstrap/pulse"
)

func TestFeeIsCappedAndChangesOnlyAfterNotice(t *testing.T) {
	base := Config{Listen: "127.0.0.1:1", FeeTo: strings.Repeat("f", 64), FloorDust: 1, ShareDifficulty: 2, MinShareDiff: 1}
	c := base
	c.FeeBPS = 301
	if err := c.Validate(); err == nil {
		t.Fatal("a fee above the network's 3 % cap was accepted")
	}
	c = base
	c.FeeBPS, c.FeeNextBPS, c.FeeNextFrom = 100, 400, "2027-01-01T00:00:00Z"
	if err := c.Validate(); err == nil {
		t.Fatal("an announced fee above the cap was accepted")
	}
	c = base
	c.FeeBPS, c.FeeNextBPS, c.FeeNextFrom = 100, 50, "2027-01-01T00:00:00Z"
	if err := c.Validate(); err != nil || c.FeeNoticeDays != 30 {
		t.Fatalf("valid config refused: %v (notice %d)", err, c.FeeNoticeDays)
	}
	before := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	after := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if c.FeeAt(before) != 100 || c.FeeAt(after) != 50 {
		t.Fatalf("fee before %d after %d", c.FeeAt(before), c.FeeAt(after))
	}
	c.FeeNextFrom = "tomorrow"
	if err := c.Validate(); err == nil {
		t.Fatal("a non-RFC 3339 date was accepted")
	}
}

// The window log is newest first: with a target smaller than all shares, the
// oldest share is the one left out.
func TestWindowLogIsNewestFirst(t *testing.T) {
	p := &Pool{}
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	p.shares = []acceptedShare{{Index: 0, Owner: pulseAddr(a), Difficulty: 10}, {Index: 1, Owner: pulseAddr(b), Difficulty: 10}, {Index: 2, Owner: pulseAddr(c), Difficulty: 10}}
	log, _ := p.windowLog(15)
	if len(log) != 2 || log[0].Index != 2 || log[1].Index != 1 {
		t.Fatalf("log %+v", log)
	}
}

func pulseAddr(s string) pulse.Address { return pulse.Address(s) }
