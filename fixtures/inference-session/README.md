# Inference Session — Synthetic Test Fixtures

Cross-implementation test vectors for CTEF v0.3.1 inference-session identity claims,
covering Ed25519 signing, JCS canonical JSON (RFC 8785), session determinism,
sequence_bound monotonicity, and cross-layer binding.

Proposed in [a2aproject/A2A#1786](https://github.com/a2aproject/A2A/issues/1786)
for the Cryptographic Agent Identity extension (CTEF).

## Files

| File | Purpose |
|------|---------|
| `inference-session-fixtures.json` | 7 test vectors with deterministic session_ids. Do not edit by hand. |
| `generate-fixtures.py` | Regenerates the fixture from seed. |
| `README.md` | This file. |

## Deterministic keypair

All signatures are produced by a keypair derived as:

```
seed = SHA-256("ctef-synthetic-fixture-v1")  // 32 bytes
private key = seed (RFC 8032 Ed25519 seed)
public key  = Ed25519 derivation of seed
```

## Deterministic session_id

Every `session_id` traces back to the seed via a documented transformation,
matching the bilateral-delegation v1 convention:

```
seed_bytes = SHA-256("ctef-synthetic-fixture-v1")  // 32 bytes
session_id = SHA-256(seed_bytes || b"session" || vector_index_be4)[:32]
```

where `vector_index_be4` is the vector's 0-based position in the JSON array
as a 4-byte big-endian unsigned integer. This ensures cross-language
reproducibility — any implementation deriving session_ids from the seed
produces byte-identical values.

## Test vectors

| # | Name | Expected | Description |
|---|------|----------|-------------|
| 0 | `valid-identity-claim` | ✅ verify | Standard identity claim with valid validity_window |
| 1 | `expired-validity-window` | ❌ reject | Expired validity_window — must fail verification |
| 2 | `rotated-key-claim` | ✅ verify | Identity after key rotation with rotation_attestation |
| 3 | `sequence-bound-continuity` | ✅ verify | 5-step monotonic sequence chain |
| 4 | `cross-layer-identity-transport` | ✅ verify | Combined identity + transport claim |
| 5 | `sequence-gap` | ❌ reject | Sequence jumps 1→5 (gap detected) |
| 6 | `replay-same-sequence` | ❌ reject | Duplicate sequence_number (replay detected) |

## Verification

```bash
pip install jcs==0.2.1 cryptography
python3 generate-fixtures.py
# Self-check runs automatically — verifies canonical bytes, SHA-256, and signatures
```
