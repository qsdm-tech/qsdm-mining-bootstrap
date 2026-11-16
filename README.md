# qsdm-mining-bootstrap

Open-source mining infrastructure for QSDM. The first part is **PULSE** (Payout, Utility & Ledger Settlement Engine), a non-custodial mining pool.

## PULSE in one paragraph

Members mine with their own enrolled NVIDIA GPU and wallet, exactly as solo miners do. They also send the pool easier "shares". The pool keeps a TIDES-style PPLNS window, the newest shares worth 8x the network difficulty by default. For each block in which members' proofs are paid, it signs a settlement batch with its ML-DSA-87 key. The **chain** then splits that reward among members by the batch's weights and pays each member directly. The pool never holds CELL.

**Status:** phase 1. The pool server, the protocol and their tests are here. The chain rule is a separate, inactive change to the QSDM node: it does nothing until a release sets its activation height. Until then the pool runs in preview and pays nothing.

## Defaults (all in the config)

| Setting | Default | Meaning |
| --- | --- | --- |
| `fee_bps` | 0 | Pool fee in basis points. |
| `fee_to` | none: required | Fee recipient. At 0 bps it receives only dust that cannot be paid. |
| `window_factor` | 8 | Window = newest shares worth this many times the network difficulty, frozen per job. Only the needed part of the oldest share counts. |
| `floor_dust` | none: required | Payout floor. A smaller balance carries forward on chain until it reaches the floor; if its shares leave the window first, it becomes dust for the fee recipient. |
| `preview_accept_shares` | false | Whether shares are accepted (and pay nothing) before the chain rule is active. |

## Build and test

```
go test ./...
python -I scripts/sabotage.py     # every safety check must be caught
go test ./pulse -run X -fuzz FuzzDecodeBatch -fuzztime 30s
```

## Run

```
pulse-pool keygen -out /var/lib/pulse/pool.key     # prints only the pool ID
pulse-pool serve -config /etc/pulse/pool.json
```

The server listens on loopback only; put nginx in front for `/pool/api/`. See [PROTOCOL.md](PROTOCOL.md) for the miner API.

## Provenance

`internal/qsdmpow` is QSDM's Mesh3D proof-of-work (`pkg/mining`, MIT). Tests pin it to vectors from the QSDM code and to a live work sample.

License: MIT.
