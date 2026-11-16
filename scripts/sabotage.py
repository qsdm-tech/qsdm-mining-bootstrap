"""Sabotage checks: each case breaks one safety rule; the named tests must FAIL.
Every file is restored byte for byte. Usage: python -I scripts/sabotage.py"""
import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = [
    ("batch_root not checked", "internal/pool/pool.go",
     "\t\tif c == batchCount {\n\t\t\troot, found = r, true", "\t\tif true {\n\t\t\troot, found = r, true", "./internal/pool/"),
    ("duplicate shares accepted", "internal/pool/pool.go",
     "\tif p.seen[key] {", "\tif false && p.seen[key] {", "./internal/pool/"),
    ("register without address binding", "internal/pool/pool.go",
     "\tif pulse.AddressOf(pk) != l.Address {", "\tif false && pulse.AddressOf(pk) != l.Address {", "./internal/pool/"),
    ("settlement before activation", "internal/pool/pool.go",
     "\tif !active {\n\t\treturn nil, errors.New(\"the chain rule is not active", "\tif false {\n\t\treturn nil, errors.New(\"the chain rule is not active", "./internal/pool/"),
    ("missing fee recipient allowed", "internal/pool/pool.go",
     "\tif _, err := pulse.ParseAddress(c.FeeTo); err != nil {", "\tif _, err := pulse.ParseAddress(c.FeeTo); false && err != nil {", "./internal/pool/"),
    ("dust lost", "pulse/split.go",
     "\tfeeBal := in.Owed[in.FeeTo] + credit[in.FeeTo] + fee + dust", "\tfeeBal := in.Owed[in.FeeTo] + credit[in.FeeTo] + fee", "./pulse/"),
    ("sub-floor balance paid instead of carried", "pulse/split.go",
     "\t\tif bal < in.FloorDust {", "\t\tif false && bal < in.FloorDust {", "./pulse/"),
    ("cap ignored", "pulse/split.go",
     "\t\tif c := in.CapLeft(o); p > c {", "\t\tif c := in.CapLeft(o); false && p > c {", "./pulse/"),
    ("oldest share counted in full", "pulse/tides.go",
     "\t\tif left := target - cum; take > left {", "\t\tif left := target - cum; false && take > left {", "./pulse/"),
    ("trailing bytes accepted", "pulse/batch.go",
     "\tif r.Len() != 0 {", "\tif false && r.Len() != 0 {", "./pulse/"),
    ("batch for another pool's key", "pulse/batch.go",
     "\tif k.ID() != b.PoolID {", "\tif false && k.ID() != b.PoolID {", "./pulse/"),
    ("work-set root not rebuilt", "internal/pool/job.go",
     "\tif len(ws.Batches) == 0 || ws.Root() != root {", "\tif len(ws.Batches) == 0 {", "./internal/pool/"),
]


# phase 2 (2026-11-16)
CASES += [
    ("receipt verifies under any key", "pulse/tx.go",
     "\tif err != nil || AddressOf(pk) != r.Pool {", "\tif err != nil {", "./pulse/"),
    ("receipt signature not checked", "pulse/tx.go",
     "\treturn Verify(pk, ReceiptDomain, ReceiptBytes(r), sig)", "\treturn sig != nil", "./pulse/"),
    ("tx signing bytes drift from the node", "pulse/tx.go",
     "strconv.FormatFloat(fee, 'f', -1, 64)", "strconv.FormatFloat(fee, 'g', -1, 64)", "./pulse/"),
    ("fee above the network cap", "internal/pool/pool.go",
     "\tif c.FeeBPS > NetworkMaxFeeBPS || c.FeeNextBPS > NetworkMaxFeeBPS {", "\tif false {", "./internal/pool/"),
    ("fee change before its date", "internal/pool/pool.go",
     "&& !t.Before(from) {", "{", "./internal/pool/"),
    ("escrow of an owner outside the window settled", "internal/pool/pool.go",
     "e.Height <= height && inWindow[pulse.Address(e.Owner)] &&", "e.Height <= height &&", "./internal/pool/"),
    ("no receipt for an accepted share", "internal/pool/pool.go",
     "\tres.Receipt, res.ReceiptSig = &rc, sig", "\t_ = sig", "./internal/pool/"),
    ("window log not newest first", "internal/pool/pool.go",
     "\tfor i := len(p.shares) - 1; i >= 0 && sum < target; i-- {\n\t\ts := p.shares[i]", "\tfor i := 0; i < len(p.shares) && sum < target; i++ {\n\t\ts := p.shares[i]", "./internal/pool/"),
]


def main() -> int:
    env = dict(os.environ, GOFLAGS="-p=2")
    caught = 0
    for name, rel, old, new, pkg in CASES:
        p = ROOT / rel
        orig = p.read_bytes()
        h = hashlib.sha256(orig).hexdigest()
        text = orig.decode()
        assert text.count(old) == 1, (name, "anchor not found once")
        try:
            p.write_bytes(text.replace(old, new).encode())
            r = subprocess.run(["go", "test", pkg, "-count=1"], cwd=ROOT, env=env, capture_output=True, text=True)
            ok = r.returncode != 0
        finally:
            p.write_bytes(orig)
        assert hashlib.sha256(p.read_bytes()).hexdigest() == h, (name, "not restored")
        caught += ok
        print(("CAUGHT " if ok else "MISSED ") + name)
    print(f"sabotage: {caught} of {len(CASES)} caught")
    return 0 if caught == len(CASES) else 1


if __name__ == "__main__":
    sys.exit(main())
