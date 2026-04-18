# AgentNexus Track A Fixture Round-Trip Report

**Fixtures:** `interop/fixtures/agentnexus/happy-path.json`, `interop/fixtures/agentnexus/scope-expansion.json`
**Contributed in:** aeoess/agent-passport-system PR #17 (kevinkaylie)
**Verifier:** `interop/run-agentnexus-roundtrip.ts`
**Run date:** 2026-04-18
**Result:** **both fixtures match expected verification outcome**

## Fixture inventory

| Fixture | Bytes | Parent token | Child token | Expected child.valid |
|---|---:|---|---|---|
| `happy-path.json` | 12,971 | `ct_a1b2c3d4e5f6` | `ct_child_001` | `true` |
| `scope-expansion.json` | 8,251 | `ct_scope_parent` | `ct_scope_child_invalid` | `false` (SCOPE_EXPANSION) |

## Check matrix

Six APS checks per fixture. Each check aggregates parent and child where applicable.

| Check | `happy-path` | `scope-expansion` |
|---|---|---|
| canonicalization (JCS re-canon == declared `canonical_string`) | pass | pass |
| signature (Ed25519, parent → principal key, child → agent key) | pass | pass |
| validity (`child.not_before` ∈ both windows) | pass | pass |
| chain (child → parent linkage declared or inferred) | pass | pass |
| scope_is_subset (permissions ⊆, spend_limit ≤, max_delegation_depth ≤) | pass | **fail (expected)** |
| status (both tokens `active`) | pass | pass |
| **overall APS decision** | **accept** ✅ (matches expected `valid: true`) | **deny** ✅ (matches expected `SCOPE_EXPANSION`) |

## Canonicalization details

JCS re-canonicalization of the `canonicalized.*.input` object for both tokens in both fixtures matches the fixture-declared `canonical_string` byte-for-byte. No drift.

- `happy-path` → parent match: `true`, child match: `true`
- `scope-expansion` → parent match: `true`, child match: `true`

APS uses `canonicalizeJCS()` at `src/core/canonical-jcs.ts` (RFC 8785, null-preserving). Output matches the Python reference canonicalizer embedded in AgentNexus.

## Signature details

Both fixtures verify Ed25519 signatures against the canonical string (not hashed — Ed25519 operates on the message directly). Base64url signatures, hex public keys.

- `happy-path` parent (`principal` key `17a3defc…`): verified
- `happy-path` child (`agent` key `416d245c…`): verified
- `scope-expansion` parent (`principal` key `17a3defc…`): verified
- `scope-expansion` child (`agent` key `416d245c…`): verified

## Monotonic narrowing (scope-expansion)

The child token in `scope-expansion.json` fails the scope-subset check for three reasons — first one reported:

- `vault:write` not in parent permissions `[vault:read]`
- `spend_limit` 100 > parent 50
- `max_delegation_depth` 2 > parent 1

APS rejects the child token. Fixture expectation: `SCOPE_EXPANSION`. Match.

## Reproduce

```bash
cd ~/agent-passport-system
npx tsx interop/run-agentnexus-roundtrip.ts
# exits 0 on full match, 1 on any expectation mismatch
```

The script writes a machine-readable JSON report on stdout (`all_pass`, per-fixture `checks[]`, canonicalization diffs when present). Exit code is the CI gate.

## Takeaway

APS and AgentNexus produce identical JCS canonical bytes for Track A token shapes. APS correctly accepts the happy-path delegation and rejects the scope-expansion case at the monotonic-narrowing gate. No canonicalization drift, no signature verification issues, no chain reconstruction gaps.
