package pulse

import (
	"errors"
	"math/bits"
)

// MaxShareBits bounds a share's difficulty to 2^60 so window sums fit in 64 bits.
const MaxShareBits = 60

// WindowShare is one accepted share as the window sees it.
type WindowShare struct {
	Owner      Address
	Difficulty uint64 // the share's own difficulty (2^share_bits)
}

// TIDESWindow returns the weights of the newest shares whose cumulative
// difficulty reaches target (window factor x the network difficulty frozen
// for the job). shares are newest first. Only the needed part of the oldest
// counted share counts. Owners are merged and the result is sorted by owner.
// If the shares do not reach target, every share counts in full.
func TIDESWindow(sharesNewestFirst []WindowShare, target uint64) ([]Weight, uint64, error) {
	if target == 0 {
		return nil, 0, errors.New("pulse: window target is zero")
	}
	acc := map[Address]uint64{}
	var cum uint64
	for _, s := range sharesNewestFirst {
		if s.Difficulty == 0 {
			continue
		}
		take := s.Difficulty
		if left := target - cum; take > left {
			take = left
		}
		acc[s.Owner] += take
		cum += take
		if cum >= target {
			break
		}
	}
	out := make([]Weight, 0, len(acc))
	for o, w := range acc {
		out = append(out, Weight{Owner: o, Weight: w})
	}
	SortWeights(out)
	return out, cum, nil
}

// WindowTarget is factor x networkDifficulty, refusing overflow.
func WindowTarget(factor, networkDifficulty uint64) (uint64, error) {
	hi, lo := bits.Mul64(factor, networkDifficulty)
	if hi != 0 || lo == 0 {
		return 0, errors.New("pulse: window target overflows or is zero")
	}
	return lo, nil
}
