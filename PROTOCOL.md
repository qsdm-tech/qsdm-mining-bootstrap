# PULSE miner protocol v1

HTTP/JSON under `/pool/api/v1/` (the hosted pool: `https://qsdm.tech/pool/api/v1/`). Every byte field is lowercase hex.

## Identity

- **Login** = `<payout address>[.<worker>]`. The address is your QSDM wallet address (64 hex). The worker name is 1-32 letters, digits, `_` or `-`.
- **Password** carries difficulty hints, comma separated: `d=<difficulty>` fixes your share difficulty, `md=<difficulty>` sets a minimum. Other words are ignored.
- The pool pays **only** the address in the login. Unlike pools that take any username, PULSE checks that you hold that address's key, so you cannot mistype it into someone else's wallet.

## 1. Register

`POST /register` `{"login", "password", "public_key", "signature"}`

- `public_key` = your wallet's ML-DSA-87 public key (2,592 bytes). Its SHA-256 must equal the login's address.
- `signature` = ML-DSA-87 (empty context, as QSDM signs) over `"QSDM/pulse/register/v1\x00" || login`.
- Answer: `{"session": "<token>"}`. Send it as `Authorization: Bearer <token>`.

## 2. Get work

`GET /work` → `{"job_id", "share_difficulty", "network_difficulty", "window_target", "work"}`

`work` is the producer's `/api/v1/mining/work`, unchanged. Mine exactly as for the network (Mesh3D DAG walk, `batch_root` = the prefix root for your `batch_count`).

## 3. Send shares

`POST /shares` `{"job_id", "nonce", "batch_count"}`

A share is accepted when `SHA3(header || nonce || batch_root || mix_digest)` is below the target for your share difficulty, `batch_count` is allowed by the job, and the share is new. The answer is `{"accepted", "reason", "difficulty", "network_solution", "preview"}`.

`network_solution: true` means the nonce also meets the network target. The pool cannot submit it for you: a network proof needs your NVIDIA attestation and your operator signature. Submit it to the producer as you do today. Then:

## 4. Report the accepted proof

`POST /proofs` `{"proof_id"}`, with the ID the producer returned. The pool lists it in the next settlement batch. The chain pays the batch only if the producer accepted that proof for an owner in the batch.

## Public audit

| Endpoint | What it shows |
| --- | --- |
| `GET /info` | Pool ID and public key, fee, fee recipient, window factor, payout floor, mode (`preview`/`active`) and the chain status |
| `GET /stats` | Miners and workers (10 min), share hashrate, the window target and how full it is |
| `GET /window` | The current TIDES weights per address |
| `GET /batches?from=<seq>` | Every signed settlement (body + ML-DSA-87 signature), verifiable with the pool's public key |
| `GET /metrics` | Prometheus counters |

Owed balances and carry-forward are kept by the chain, not the pool. They are read from the chain once the rule is active.

## Settlement batch v1 (binary, big-endian)

`version u8 (1) | pool_id [32] | seq u64 | height u64 | fee_bps u16 | fee_to [32] | floor_dust u64 | n_proofs u32 | (len u16, id bytes)* | n_weights u32 | (owner [32], weight u64)*`, with weights sorted by owner and no trailing bytes. Signed as ML-DSA-87 over `"QSDM/pulse/batch/v1\x00" || body`.
