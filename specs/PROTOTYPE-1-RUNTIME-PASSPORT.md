# Prototype 1: Runtime Passport Local Enforcement

**Status:** Approved for implementation. Round 5 review closed.
**Target repo:** `agent-passport-system`.
**Companion deliverable:** Internal CLAIMS.md tier matrix entry (Section 18 of this spec).

## 1. Intent

Apply a well-known security pattern (short-lived signed capability + local verification + async audit) to agent governance. The pattern itself is not novel; it underlies mTLS sessions, SPIFFE/SPIRE, JWT bearer authentication, and bank card networks. SAGA (NDSS 2026) applies a related architecture to agent-to-agent access control.

What Prototype 1 establishes: APS-specific primitives — multi-hop scoped delegation with monotonic narrowing, per-action signed receipts, beneficiary attribution, risk-class-tiered durability and assurance — can be enforced locally without becoming friction in the agent execution path. The composition is what APS contributes.

One prototype. Narrow scope. Benchmark-driven. No claims before measurement.

## 2. Scope

### 2.1 In scope

1. Runtime Passport wire format (JSON, gateway-signed).
2. Action Descriptor wire format (packed binary, SDK-emitted).
3. Decision Result format (binary, verifier-emitted).
4. CompiledAuthority in-memory representation (reference implementation, non-normative).
5. Local verifier function: `aps_check(compiled_authority, action_descriptor) → decision`.
6. Sequence/replay protection (single-window).
7. Tool registry consistency mechanism (descriptor-hash addressing with local integer resolution).
8. Clock skew tolerance with risk-class-aware soft degradation.
9. Event durability with risk-class-aware modes (Mode A memory-buffered, Mode B1/B2 durable group-commit).
10. Passport lifetime defaults by risk class.
11. Crash recovery from durable local log.
12. Benchmark harness comparing against current gateway-bound enforcement.

### 2.2 Out of scope (Prototype 1)

- Receipt batch streaming and gateway ingest (Phase 2).
- ZK proofs for delegation chains (Phase 3).
- TEE-backed verifier, Tier 3 (Phase 3).
- Macaroon-style intra-passport sub-agent narrowing (Phase 2 spike).
- Predictive preflight / authority warm-up (Phase 2).
- Authority templates / workflow scope inference (Phase 2).
- Edge revocation distribution (Phase 2).
- Push-based revocation pub/sub (Prototype 1 uses poll-based revocation epoch).
- SIMD/AVX2-optimized crypto (Phase 2 optimization).
- HSM/SmartNIC paths (Phase 3).
- Parallel sequence windows for sublease workers (Phase 1.1 / Phase 2).
- R4 strict mode (returns `STRICT_MODE_REQUIRED`).

## 3. Four-Plane Architecture (Reminder)

**Issuance plane** (gateway, control-plane, slow): validates delegation chain, performs monotonic narrowing checks, looks up revocation status, classifies risk, allocates budget lease, enforces passport lifetime by risk class, issues signed Runtime Passport.

**Enforcement plane** (local, data-plane, fast): loads CompiledAuthority from the Runtime Passport once at session start; on each action, runs the hot-path check returning allow/deny/escalate.

**Evidence plane** (local + async): emits decision events to one of three durability modes (A: memory-buffered, B1: blocking group-commit, B2: queued group-commit); Prototype 1 implements local persistence only.

**Audit/control plane** (gateway, async, Phase 2): ingests receipt streams, detects sequence gaps, finalizes receipts, manages revocation broadcasts, publishes time anchors.

## 4. Runtime Passport (Wire Format, Normative)

Public format, JSON, JCS-canonicalized for signing, Ed25519-signed by gateway.

```json
{
  "type": "aps.runtime_passport",
  "version": "0.1",
  "passport_id": "rp_<ulid>",
  "agent_id": "ag_<ulid>",
  "principal_id": "pr_<ulid>",
  "beneficiary_id": "bn_<ulid>",
  "issuer": "https://gateway.aeoess.com",
  "issued_at": "2026-05-19T22:38:56.000Z",
  "expires_at": "2026-05-19T22:39:56.000Z",
  "max_clock_skew_ms": 1000,
  "policy_epoch": 42,
  "revocation_epoch": 1842,
  "tool_registry_root": "blake3:<32-byte-hex>",
  "delegation_chain_hash": "sha256:<32-byte-hex>",
  "effective_authority_hash": "blake3:<32-byte-hex>",
  "risk_class": "R2",
  "minimum_tier_required": "T2",
  "tier_attested": "T2",
  "verifier_instance_id": "vi_<ulid>",
  "verifier_build_hash": "blake3:<32-byte-hex>",
  "session_id": "sn_<ulid>",
  "sequence_start": 1000,
  "sequence_end": 1999,
  "budget_lease": {
    "lease_id": "bl_<ulid>",
    "max_actions": 1000,
    "max_cost_units": 50000,
    "sublease_parent": null
  },
  "authority_blob_encoding": "application/aps-authority+json",
  "authority_blob": {
    "allowed_tools": ["blake3:<32b>", "blake3:<32b>", "..."],
    "allowed_operations": ["read", "external_send"],
    "resource_scopes": ["customer/*", "invoice/vendor/acme/*"],
    "approval_rules": [
      {
        "predicate": "operation == external_send AND recipient NOT IN allowlist",
        "on_match": "escalate"
      }
    ]
  },
  "receipt_stream_id": "rs_<ulid>",
  "signature": "ed25519:<64-byte-hex>"
}
```

### 4.1 Required fields

All fields above are required. The signature covers the canonical JCS form of every field except `signature` itself.

### 4.2 Authority blob encoding

The `authority_blob` MAY be inlined as JSON within the passport for Prototype 1. Future versions MAY use CBOR or another compact encoding addressed via `authority_blob_hash` + external blob fetch. The `authority_blob_encoding` field specifies the format. Hot-path enforcement MUST use the CompiledAuthority representation, not the JSON authority_blob, regardless of encoding.

### 4.3 The five hardenings

1. `verifier_instance_id` and `verifier_build_hash` bind this passport to a specific verifier instance running a specific code version.
2. `sequence_start` and `sequence_end` define a per-session sequence window.
3. `minimum_tier_required` AND `tier_attested` are both present; the gateway refuses to issue if `tier_attested < minimum_tier_required`; the verifier double-checks at load.
4. `budget_lease.sublease_parent` supports parent-child lease reconciliation when used (sublease support deferred to Phase 1.1; field present from day one).
5. Action Descriptors (Section 5) carry nonce + monotonic sequence; replays denied immediately.

### 4.4 Tool addressing

`allowed_tools` is a list of 32-byte BLAKE3 hashes of canonical tool descriptors. Local integer IDs are NOT on the wire. The verifier resolves descriptor hashes against its local tool registry at passport load (Section 11.1).

`tool_registry_root` is the Merkle root of the registry version against which this passport was compiled. The verifier MUST hold the matching registry or refuse the passport.

## 5. Action Descriptor (Wire Format, Normative)

Packed canonical binary format. Implementations MUST serialize field-by-field in the specified order and MUST NOT rely on compiler struct layout or implicit padding. Total size: 204 bytes.

```
struct ActionDescriptor {
  version:              u8,           //   1 byte
  reserved:             [u8; 3],      //   3 bytes
  passport_id_hash:     [u8; 32],     //  32 bytes  (BLAKE3 of passport_id)
  tool_descriptor_hash: [u8; 32],     //  32 bytes  (BLAKE3 of canonical tool descriptor)
  local_tool_id:        u32,          //   4 bytes  (verifier-local integer, validated against hash)
  operation_id:         u16,          //   2 bytes  (from fixed operation enum)
  resource_type:        u16,          //   2 bytes  (from fixed resource type enum)
  risk_class:           u8,           //   1 byte   (R0..R4 as u8)
  resource_path_depth:  u8,           //   1 byte   (0..8)
  reserved2:            [u8; 2],      //   2 bytes
  cost_units:           u32,          //   4 bytes
  sequence_id:          u64,          //   8 bytes
  nonce:                [u8; 16],     //  16 bytes
  resource_path_hashes: [u64; 8],     //  64 bytes  (pre-hashed path components, 0-padded)
  action_hash:          [u8; 32],     //  32 bytes  (BLAKE3 of all preceding fields)
}
                                      // ---------
                                      // 204 bytes total
```

### 5.1 Field semantics

- `local_tool_id`: verifier-local integer for bitmap indexing. The verifier MUST validate `registry[local_tool_id].descriptor_hash == tool_descriptor_hash` before trusting the integer. If mismatch, deny with `REGISTRY_VERSION_MISMATCH`.
- `action_hash`: integrity and receipt-binding hash, computed as `BLAKE3(bytes[0..172])`. It detects accidental corruption of the descriptor in transit and binds the decision event to the specific action fields. It is NOT an authorization proof; authorization is established by the Runtime Passport signature and the verifier's compiled-authority check.

### 5.2 Sequencing

Prototype 1 implements single-window sequencing per Runtime Passport. The SDK MUST serialize action submission within a single passport session. Parallel sequence windows for sublease workers are deferred to Phase 1.1 / Phase 2.

### 5.3 Nonce

`nonce` is mandatory in the ActionDescriptor field. Nonce-replay tracking by the verifier is OPTIONAL in Prototype 1 because strict monotonic sequence already prevents replays. Implementations MAY enable nonce tracking as defense-in-depth; when enabled, the verifier maintains a bounded LRU of seen nonces within the current sequence window. Nonce tracking is REQUIRED if relaxed-sequence modes are introduced in later phases.

## 6. Decision Result (Wire Format, Normative)

Packed binary, 64 bytes.

```
struct Decision {
  decision_type:    u8,           //   1 byte   (0=Allow, 1=Deny, 2=Escalate)
  reason_code:      u8,           //   1 byte   (see Section 7)
  reserved:         [u8; 6],      //   6 bytes
  sequence_id:      u64,          //   8 bytes
  decision_id:      [u8; 16],     //  16 bytes  (ULID of decision event)
  event_mac:        [u8; 32],     //  32 bytes  (keyed BLAKE3 over canonical decision event)
}
```

### 6.1 Event MAC definition

```
event_mac = BLAKE3_keyed(receipt_stream_key, canonical_decision_event_bytes)
```

Where:
- `receipt_stream_key` is the 32-byte session key derived at passport load.
- `canonical_decision_event_bytes` is the byte concatenation of: `passport_id_hash || action_hash || sequence_id || decision_type || reason_code || decision_id || timestamp_unix_ns`.

## 7. Reason Codes (Normative)

| Code | Name | Meaning |
|---|---|---|
| 0x00 | OK | Allow |
| 0x01 | EXPIRED_PASSPORT | `now > expires_at + max_clock_skew_ms` |
| 0x02 | NOT_YET_VALID | `now < issued_at - max_clock_skew_ms` |
| 0x03 | STALE_REVOCATION_EPOCH | Verifier's revocation epoch older than threshold |
| 0x04 | REGISTRY_VERSION_MISMATCH | Tool registry root or local_tool_id resolution mismatch |
| 0x05 | TOOL_NOT_ALLOWED | Tool descriptor hash not in compiled bitmap |
| 0x06 | OPERATION_NOT_ALLOWED | Operation ID not in compiled mask |
| 0x07 | RESOURCE_OUT_OF_SCOPE | Resource path does not match any scope |
| 0x08 | RISK_TIER_TOO_LOW | Verifier's attested tier below passport's minimum_tier_required |
| 0x09 | RISK_CLASS_EXCEEDED | Action's risk_class higher than passport's risk_class |
| 0x0A | BUDGET_EXCEEDED | Action would exhaust remaining lease budget |
| 0x0B | SEQUENCE_REPLAY | sequence_id != expected_next or > sequence_end |
| 0x0C | NONCE_REPLAY | Nonce already seen in this session (if nonce tracking enabled) |
| 0x0D | APPROVAL_REQUIRED | Approval rule matched with on_match=escalate |
| 0x0E | DENIED_BY_RULE | Approval rule matched with on_match=deny |
| 0x0F | ACTION_HASH_INVALID | Computed action_hash does not match field |
| 0x10 | VERIFIER_INSTANCE_MISMATCH | Passport's verifier_instance_id != local instance |
| 0x11 | CLOCK_ANCHOR_STALE | R3+ action requires fresh gateway time anchor |
| 0x12 | SEQUENCE_RECOVERY_INVALID | Sequence below recovered floor after restart |
| 0x13 | STRICT_MODE_REQUIRED | Action requires R4 strict mode; Prototype 1 does not implement |

## 8. CompiledAuthority (Reference Implementation, Non-Normative)

Implementations MUST satisfy these properties on the hot path:

1. No heap allocations during `aps_check`.
2. No string operations or JSON parsing during `aps_check`.
3. Constant-time or near-constant-time evaluation per check.
4. Atomic decrement for budget counters.
5. Atomic CAS for sequence advancement.
6. Cache-aligned layout of frequently-accessed fields.

A reference Rust layout is provided in Appendix A. It is non-normative: implementations are free to benchmark alternative resource-scope structures (hashed-component radix trie, perfect hash table, bloom filter with fallback) and select the fastest measured option.

## 9. Hot Path Algorithm

```
fn aps_check(auth: &CompiledAuthority, action: &ActionDescriptor) -> Decision {
    // 0. Integrity
    if computed_action_hash(action) != action.action_hash:
        return Deny(ACTION_HASH_INVALID, action.sequence_id)

    // 1. Instance binding
    if auth.verifier_instance_id_hash != local_instance_hash():
        return Deny(VERIFIER_INSTANCE_MISMATCH, action.sequence_id)

    // 2. Temporal
    let now = current_time_ns()
    if now > auth.expires_at_unix_ns + auth.max_clock_skew_ns:
        return Deny(EXPIRED_PASSPORT, action.sequence_id)
    if now < auth.issued_at_unix_ns - auth.max_clock_skew_ns:
        return Deny(NOT_YET_VALID, action.sequence_id)

    // 3. Time anchor freshness for R3+
    if action.risk_class >= R3:
        if (now - auth.last_time_anchor_ns) > 30_000_000_000:  // 30s
            return Deny(CLOCK_ANCHOR_STALE, action.sequence_id)

    // 4. Revocation freshness
    if local_revocation_epoch() < auth.revocation_epoch:
        return Deny(STALE_REVOCATION_EPOCH, action.sequence_id)

    // 5. Tier
    if local_attested_tier() < auth.minimum_tier_required:
        return Deny(RISK_TIER_TOO_LOW, action.sequence_id)

    // 6. Risk class
    if action.risk_class > auth.risk_class:
        return Deny(RISK_CLASS_EXCEEDED, action.sequence_id)
    if action.risk_class >= R4:
        return Deny(STRICT_MODE_REQUIRED, action.sequence_id)

    // 7. Tool: validate hash matches local_tool_id, then bitmap check
    if auth.tool_registry[action.local_tool_id].descriptor_hash != action.tool_descriptor_hash:
        return Deny(REGISTRY_VERSION_MISMATCH, action.sequence_id)
    if !bitmap_get(auth.allowed_tool_bitmap, action.local_tool_id):
        return Deny(TOOL_NOT_ALLOWED, action.sequence_id)

    // 8. Operation
    if !(auth.allowed_op_mask & (1 << action.operation_id)):
        return Deny(OPERATION_NOT_ALLOWED, action.sequence_id)

    // 9. Resource scope (trie walk on pre-hashed components)
    if !resource_trie_match(auth.resource_trie, action.resource_path_hashes, action.resource_path_depth):
        return Deny(RESOURCE_OUT_OF_SCOPE, action.sequence_id)

    // 10. Sequence (atomic CAS)
    let expected = auth.sequence_next.load()
    if action.sequence_id != expected or action.sequence_id >= auth.sequence_end:
        return Deny(SEQUENCE_REPLAY, action.sequence_id)
    if !auth.sequence_next.compare_exchange(expected, expected + 1):
        return Deny(SEQUENCE_REPLAY, action.sequence_id)

    // 11. Budget (atomic decrement)
    if !try_decrement_budget(&auth.budget, action.cost_units):
        // Roll back sequence
        auth.sequence_next.store(expected)
        return Deny(BUDGET_EXCEEDED, action.sequence_id)

    // 12. Approval rules
    for rule in auth.approval_rules:
        if rule.matches(action):
            match rule.on_match:
                Escalate => return Escalate(generate_id(), action.sequence_id)
                Deny     => return Deny(DENIED_BY_RULE, action.sequence_id)

    // 13. Emit decision event per durability mode (Section 11.3)
    emit_decision_event(auth, action, ALLOW)

    return Allow(generate_id(), action.sequence_id)
}
```

## 10. Passport Lifetime Defaults by Risk Class (Normative)

Gateway MUST enforce maximum lifetime by risk class. Defaults below; customer policy MAY narrow but MUST NOT exceed.

| Risk Class | Max Lifetime | Additional Requirement |
|---|---|---|
| R0 | 15 minutes | None |
| R1 | 5 minutes | None |
| R2 | 60 seconds | None |
| R3 | 30 seconds | Fresh gateway time anchor required at issuance and during use |
| R4 | Strict mode only | Out of Prototype 1 scope |

Rationale: under network partition, the verifier continues to execute against a valid passport until `expires_at` is reached (Section 11.2). Bounded lifetimes by risk class cap the partition-attack window proportional to the action's reversibility.

## 11. Three Identified Problems and Mitigations

### 11.1 Tool registry consistency

**Problem:** Stale local registry could mis-resolve tool IDs to wrong descriptors.

**Solution:** Descriptor-hash addressing on the wire, local integer resolution validated against hash.

At passport load (slow path, once per session):
1. Verifier reads `tool_registry_root` from the passport.
2. If it does not match the verifier's local registry root, the verifier triggers a registry update via HTTPS poll against the gateway.
3. Verifier walks `allowed_tools`, resolving each descriptor hash to a local integer ID, and populates the CompiledAuthority bitmap.
4. If any descriptor hash is unknown after registry update, the verifier rejects the passport with `REGISTRY_VERSION_MISMATCH`.

On the hot path:
1. Action carries both `tool_descriptor_hash` and `local_tool_id`.
2. Verifier checks `registry[local_tool_id].descriptor_hash == tool_descriptor_hash` (single cache-line load, single 32-byte compare).
3. Verifier uses `local_tool_id` for bitmap indexing.

This avoids hot-path hash-map lookup while preserving registry-drift detection. Hash mismatch is caught and surfaced as `REGISTRY_VERSION_MISMATCH`.

### 11.2 Clock skew tolerance with risk-class-aware soft degradation

**Problem:** Naive time-anchor polling halts execution under network partition, defeating the local-execution value proposition.

**Solution:** Soft degradation up to `expires_at` for R0-R2; strict freshness requirement only for R3.

- The verifier tracks `last_gateway_time_anchor_received` from periodic gateway polls.
- For **R0-R2 actions**: verifier continues to execute against a valid passport (within `max_clock_skew_ms` of `expires_at`) even without fresh time anchors. The bounded passport lifetime by risk class (Section 10) caps partition-attack damage.
- For **R3 actions**: verifier requires a time anchor fresher than 30 seconds. Returns `CLOCK_ANCHOR_STALE` if older. Combined with the 30-second R3 passport lifetime, this means R3 effectively requires real-time gateway connectivity.
- For **R4 actions**: out of scope; returns `STRICT_MODE_REQUIRED`.

### 11.3 Sequence persistence and event durability modes

**Problem:** Mandatory fsync on every action saturates storage IOPS and confuses "local check latency" with "local check + durable storage latency."

**Solution:** Three durability modes, selected by risk class. Decision event durability is independent of the verification decision itself.

**Mode A: Memory-buffered (R0-R1)**
- Decision event appended to in-memory ring buffer.
- Background thread flushes to durable log periodically.
- Verifier returns Decision immediately after event MAC computed.
- Crash window: events in the buffer at crash time may be lost.
- Acceptable for R0 (read-only) and R1 (internally reversible).

**Mode B1: Blocking group-commit (R2-R3, conservative)**
- Decision event appended to ring buffer.
- Group commit fsync at batch boundary (default: 1ms window or 64 events, whichever first).
- Verifier returns Decision only after the containing batch is fsync'd.
- Strongest durability; throughput bounded by storage IOPS.

**Mode B2: Queued group-commit (R2-R3, fast)**
- Decision event appended to ring buffer.
- Event is admitted to the next group-commit queue and given a batch ID.
- Verifier returns Decision immediately after admission (before fsync completes).
- Crash window: events admitted but not yet fsync'd may be lost; the batch ID lets the gateway reconcile after recovery.
- Lower latency than B1; slightly weaker durability.

**Mode C: Strict (R4)**
- Out of Prototype 1 scope. Returns `STRICT_MODE_REQUIRED`.

The CompiledAuthority caches the mode per action class so dispatch is constant-time. The benchmark harness (Section 13) measures Mode A, B1, and B2 separately.

### 11.4 Crash recovery floor

On verifier restart, before accepting any new action:
1. Read the local durable log for the active passport.
2. Verify the rolling keyed BLAKE3 over the log.
3. Recover `last_committed_sequence_id`.
4. Set `sequence_next = last_committed_sequence_id + 1`.

Any incoming action with `sequence_id <= last_committed_sequence_id` returns `SEQUENCE_RECOVERY_INVALID`.

### 11.5 Local log tamper-resistance language

The local durable log protects against crash-replay and accidental corruption in **Tier 1**. It does NOT protect against a malicious host rewriting log contents and re-computing the keyed BLAKE3, because the host has access to the MAC key in Tier 1.

**Tier 2** (signed verifier build, deferred to Phase 2) provides tamper-evident execution streams tied to an approved verifier build hash.

**Tier 3** (TEE-backed, deferred to Phase 3) provides hardware-rooted enforcement.

State the assumed tier when claiming log tamper resistance.

## 12. Implementation Streams

Two-week target. Three parallel streams. B and C can begin against stubbed A.

### Stream A: Rust Core Verifier (`aps-verifier-core`)

- `CompiledAuthority` struct per Appendix A reference layout.
- `aps_check(auth, action) → Decision` function.
- Keyed BLAKE3 for event MAC and log rolling MAC.
- Ed25519 verification for passport signature (one-time, at load).
- Local durable log with three durability modes (Mode A, B1, B2).
- Crash recovery routine.
- Local tool registry with descriptor-hash → local-integer mapping.
- Gateway time anchor handler.
- Resource trie implementation.

### Stream B: TypeScript SDK Wrapper

- N-API binding to `aps-verifier-core`.
- Public API: `aps.loadPassport(passport)`, `aps.check(action)`, `aps.recoverSession()`.
- Action Descriptor builder (handles hashing, sequence allocation, nonce generation, local_tool_id lookup).
- Local tool registry sync client (HTTPS poll against gateway).
- Time anchor poll client.

### Stream C: Benchmark Harness

Measurements:

| Benchmark | Mode | What it measures |
|---|---|---|
| L0 | Rust core, hot cache, allow path, no event | Pure verification cost |
| L1 | Rust core, hot cache, deny path | Fast-reject cost |
| L2 | TS SDK via N-API, no event | FFI overhead |
| L3a | TS SDK + Mode A (memory-buffered) | Async event append |
| L3b1 | TS SDK + Mode B1 (blocking group-commit) | Durable, conservative |
| L3b2 | TS SDK + Mode B2 (queued group-commit) | Durable, fast-return |
| L4 | Current gateway baseline | Network-bound reference |

Throughput tests at varying concurrency. Tail latency reported at p50, p95, p99, p99.9. Workload: synthetic action stream simulating invoice reconciliation.

## 13. Benchmark Environments (Normative)

Three environments. The canonical published number is bare metal Linux.

### 13.1 Canonical: Bare metal Linux x86_64

- Ubuntu 24.04 LTS
- Intel Xeon or AMD EPYC (current generation), specify exact model in published numbers
- NVMe SSD storage
- ECC RAM
- No hypervisor
- Filesystem: ext4 with `data=ordered`
- Write cache enabled, log explicitly

### 13.2 Cloud reference: AWS EC2

- c7i.2xlarge or equivalent
- Ubuntu 24.04
- gp3 EBS, default IOPS (3000), single AZ
- Filesystem: ext4
- This number reveals storage-bounded Mode B latency under standard cloud constraints

### 13.3 Developer reference: Apple Silicon Mac

- M2 or M3 MacBook Pro
- Current macOS LTS
- Internal NVMe
- This number sets developer expectations during integration

### 13.4 Required storage configuration logging for Mode B results

Every Mode B benchmark MUST record:
- Disk type and model
- Filesystem and mount options
- Fsync / group commit batch size and window
- IOPS limit if cloud
- Write cache enabled/disabled
- Power loss protection if known
- Sample size and statistical methodology

Without this metadata, Mode B numbers are not comparable across environments.

## 14. Acceptance Criteria

Prototype 1 is complete when:

1. All wire formats (Sections 4, 5, 6) are implemented and round-trip stable across Rust core and TS SDK.
2. All reason codes (Section 7) are emitted correctly under matching adversarial test cases.
3. The five hardenings (Section 4.3) are enforced with passing test coverage.
4. The three trap mitigations (Sections 11.1, 11.2, 11.3) are implemented with adversarial test coverage:
   - Registry drift attack (stale local registry against fresh passport).
   - Clock partition attack (R0-R2 continues, R3 halts with `CLOCK_ANCHOR_STALE`).
   - Crash-replay attack (sequence floor recovered correctly).
5. Passport lifetime defaults (Section 10) are enforced at issuance.
6. Three durability modes (Section 11.3) are implemented and selectable by risk class.
7. Benchmark harness produces L0, L1, L2, L3a, L3b1, L3b2, L4 numbers with confidence intervals across all three environments (Section 13).
8. Internal CLAIMS.md tier matrix entry is drafted and approved by the project maintainer.

## 15. What Prototype 1 Does NOT Prove

- Full receipt finalization at scale (Phase 2).
- Gateway audit detection of defection (Phase 2).
- TEE attestation (Phase 3).
- Macaroon-style sub-agent narrowing (Phase 2 spike).
- System holds under production adversarial conditions.
- Latency targets hold under varying network and storage conditions beyond the three benchmark environments.

Prototype 1 proves one thing: **local authority enforcement against a pre-issued Runtime Passport is faster than gateway-bound enforcement by a measurable margin, with explicit handling of the three known traps and honest reporting of three durability modes.**

## 16. Latency Targets (Hypothesis, Not Claim)

| Configuration | Hypothesis | Status |
|---|---|---|
| L0 Rust core, hot cache, allow | low microseconds | hypothesis |
| L1 Rust core, hot cache, deny | sub-microsecond to low microseconds | hypothesis |
| L2 TS SDK via N-API, no event | 1-10 microseconds | hypothesis |
| L3a Mode A memory-buffered | 1-10 microseconds | hypothesis |
| L3b1 Mode B1 blocking commit | 0.5-5 milliseconds (storage-bound) | hypothesis |
| L3b2 Mode B2 queued commit | 10-200 microseconds | hypothesis |
| L4 Gateway-bound baseline | 2-50 milliseconds | known |

No public claim until L0-L4 measure across all three environments with reproducible numbers.

## 17. Out of Scope but Tracked

| Item | Deferred to | Notes |
|---|---|---|
| Receipt stream batching and gateway ingest | Phase 2 | Mode B2 batch IDs designed to support this |
| Macaroon-style sub-agent narrowing | Phase 2 spike | Two-week focused research |
| Push-based revocation pub/sub | Phase 2 | Prototype 1 uses poll |
| TEE-backed verifier (Tier 3) | Phase 3 | |
| ZK proofs for deep chains | Phase 3 | Control-plane only |
| SIMD-optimized crypto | Phase 2 optimization | |
| Edge revocation distribution | Phase 2 | CRLite-style |
| Authority templates / workflow scope | Phase 2 | Workato integration |
| Sublease workers / parallel sequence windows | Phase 1.1 | Schema ready, enforcement deferred |

## 18. Companion Deliverable: CLAIMS.md Tier Matrix

Draft entry for the internal CLAIMS.md register. Goes through normal CLAIMS.md review before any public surface uses tier language.

```
CLAIM: APS Runtime Passport tiered enforcement
STATUS: Drafted, pending Prototype 1 measurements
APPROVED FOR EXTERNAL USE: NO

Tier 1 (Local mode, untrusted host):
  APS specifies: local enforcement of compiled authority against
  short-lived gateway-issued passports, with durable local event log
  and asynchronous gateway audit.
  APS does NOT specify: protection against in-memory tampering of
  the verifier or log key on a host the operator does not control.
  Tier 1 is appropriate only for risk classes R0-R1.

Tier 2 (Attested mode, signed verifier build):
  APS specifies: enforcement bound to a verifier_build_hash that the
  gateway recognizes; gateway refuses to issue passports above
  configured risk classes to unattested verifiers; receipt streams
  are signed and tamper-evident.
  APS does NOT specify: protection against compromise of the host
  kernel or hypervisor. Tier 2 is appropriate for R2-R3.

Tier 3 (Strict mode, TEE-backed or synchronous gateway):
  APS specifies: hardware-rooted attestation OR synchronous gateway
  check for each action. Either path is appropriate for R4
  irreversible / regulated actions.
  APS does NOT specify: protection against hardware-level
  side-channel attacks on the TEE. The relevant TEE vendor's threat
  model applies.

LANGUAGE RULES:
- Never write "same cryptographic guarantees as" across tiers.
- Always specify the tier when stating a guarantee.
- Use APS verbs: specified, tested, validated, instantiated,
  implemented, exercised.
- Never use: proved, verified, guaranteed.

LATENCY CLAIMS:
No external latency claim is approved until Prototype 1 benchmarks
produce reproducible numbers. Any latency statement MUST include:
- mode: Mode A memory-buffered / Mode B1 blocking commit /
        Mode B2 queued commit / Mode C strict / gateway-bound
- runtime: Rust core direct / TS wrapper via N-API / gateway
- environment: CPU model, OS version, storage type and configuration
- percentile: p50, p95, p99, p99.9
- whether event durability is included in the measurement
- sample size and statistical methodology

Forbidden phrasing examples:
  "APS is sub-microsecond" (no mode, no env, no percentile)
  "APS is faster than competitors" (no comparable baseline)

Permitted phrasing example:
  "On bare metal Linux x86_64 (Ubuntu 24.04, Xeon Gold 6430, NVMe
  SSD), APS Mode A local verification returns in p99 of N
  microseconds across 1M samples, with event durability flushed
  asynchronously."
```

---

## Appendix A: CompiledAuthority Reference Layout (Rust, Non-Normative)

```rust
#[repr(C, align(64))]
struct CompiledAuthority {
    // Cache line 1: hot fields touched every action
    expires_at_unix_ns:          u64,
    issued_at_unix_ns:           u64,
    max_clock_skew_ns:           u64,
    revocation_epoch:            u32,
    risk_class:                  u8,
    minimum_tier_required:       u8,
    flags:                       u16,
    sequence_next:               AtomicU64,
    sequence_end:                u64,
    budget_remaining_actions:    AtomicU32,
    budget_remaining_cost_units: AtomicU64,
    allowed_op_mask:             u32,
    last_time_anchor_ns:         AtomicU64,

    // Cache line 2: identity hashes
    passport_id_hash:            [u8; 32],
    verifier_instance_id_hash:   [u8; 32],

    // Cache lines 3+: permissions
    allowed_tool_bitmap:         BitMap,            // sized by registry, typically 8KB
    tool_registry:               *const ToolEntry,  // local descriptor-hash → integer table
    tool_registry_size:          u32,

    // Pointers to off-struct compiled structures
    resource_trie:               *const TrieNode,
    approval_rules:              *const ApprovalRule,
    approval_rules_count:        u16,

    // Receipt stream
    receipt_stream_key:          [u8; 32],
    durability_mode:             DurabilityMode,   // A / B1 / B2 selector
}

#[repr(C)]
struct ToolEntry {
    descriptor_hash: [u8; 32],
    descriptor_ptr:  *const ToolDescriptor,
}

enum DurabilityMode {
    MemoryBuffered,        // Mode A
    BlockingGroupCommit,   // Mode B1
    QueuedGroupCommit,     // Mode B2
}
```
