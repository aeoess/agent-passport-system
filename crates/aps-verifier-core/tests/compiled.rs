//! Chunk-2 tests for [`CompiledAuthority`] + [`BitMap`] + [`ToolRegistry`].

use std::sync::atomic::Ordering;

use chrono::{DateTime, Utc};

use aps_verifier_core::{
    BitMap, CompileError, CompiledAuthority, DurabilityMode, RuntimePassport, ToolRegistry,
};

// -----------------------------------------------------------------------
// Test fixtures
// -----------------------------------------------------------------------

/// Build a passport JSON parametric on the fields that exercise
/// chunk-2 compile paths.
#[allow(clippy::too_many_arguments)]
fn passport_json(
    risk: &str,
    minimum: &str,
    attested: &str,
    operations: &[&str],
    tool_hashes_64hex: &[&str],
) -> String {
    let tools_block = tool_hashes_64hex
        .iter()
        .map(|h| format!("\"blake3:{h}\""))
        .collect::<Vec<_>>()
        .join(",");
    let ops_block = operations
        .iter()
        .map(|o| format!("\"{o}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{
  "type": "aps.runtime_passport",
  "version": "0.1",
  "passport_id": "rp_01HX0EXAMPLE000000000000000",
  "agent_id": "ag_01HX0AGENT000000000000000000",
  "principal_id": "pr_01HX0PRINCIPAL00000000000000",
  "beneficiary_id": "bn_01HX0BEN00000000000000000000",
  "issuer": "https://gateway.example.test",
  "issued_at": "2026-05-19T22:38:56.000Z",
  "expires_at": "2026-05-19T22:39:56.000Z",
  "max_clock_skew_ms": 1000,
  "policy_epoch": 42,
  "revocation_epoch": 1842,
  "tool_registry_root": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
  "delegation_chain_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "effective_authority_hash": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
  "risk_class": "{risk}",
  "minimum_tier_required": "{minimum}",
  "tier_attested": "{attested}",
  "verifier_instance_id": "vi_01HX0VI00000000000000000000",
  "verifier_build_hash": "blake3:1111111111111111111111111111111111111111111111111111111111111111",
  "session_id": "sn_01HX0SESS00000000000000000000",
  "sequence_start": 1000,
  "sequence_end": 2000,
  "budget_lease": {{
    "lease_id": "bl_01HX0LEASE0000000000000000000",
    "max_actions": 1000,
    "max_cost_units": 50000,
    "sublease_parent": null
  }},
  "authority_blob_encoding": "application/aps-authority+json",
  "authority_blob": {{
    "allowed_tools": [{tools_block}],
    "allowed_operations": [{ops_block}],
    "resource_scopes": ["customer/*"],
    "approval_rules": [
      {{"predicate": "operation == external_send", "on_match": "escalate"}}
    ]
  }},
  "receipt_stream_id": "rs_01HX0RS00000000000000000000",
  "signature": "ed25519:{sig}"
}}"#,
        sig = "0".repeat(128)
    )
}

fn hash_from_hex(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

const TOOL_HEX_0: &str = "abcd000000000000000000000000000000000000000000000000000000000000";
const TOOL_HEX_1: &str = "ef01000000000000000000000000000000000000000000000000000000000000";

fn standard_happy_passport() -> RuntimePassport {
    let json = passport_json(
        "R2",
        "T2",
        "T2",
        &["read", "external_send"],
        &[TOOL_HEX_0, TOOL_HEX_1],
    );
    RuntimePassport::from_json(&json).expect("happy passport parses")
}

// -----------------------------------------------------------------------
// BitMap
// -----------------------------------------------------------------------

#[test]
fn bitmap_set_get_clear() {
    let mut bm = BitMap::new(128);
    assert!(!bm.get(5));
    bm.set(5);
    assert!(bm.get(5));
    bm.clear(5);
    assert!(!bm.get(5));
}

#[test]
fn bitmap_capacity_rounding() {
    let bm = BitMap::new(100);
    // Capacity rounds up to the next multiple of 64, so >= 100, in fact 128.
    assert!(bm.capacity() >= 100);
    assert_eq!(bm.capacity() % 64, 0);
    // Bits in the asked-for range are all readable.
    for b in 0u32..100 {
        assert!(!bm.get(b), "bit {b} should start cleared");
    }
}

#[test]
#[should_panic(expected = "BitMap index out of range")]
fn bitmap_out_of_range_set_panics() {
    let mut bm = BitMap::new(64);
    // bm.capacity() == 64, valid bits are 0..=63; bit 64 is out of range.
    bm.set(64);
}

// -----------------------------------------------------------------------
// ToolRegistry
// -----------------------------------------------------------------------

#[test]
fn tool_registry_add_lookup() {
    let mut reg = ToolRegistry::new();
    let h = hash_from_hex(TOOL_HEX_0);
    reg.add(h, 7);
    assert_eq!(reg.get_by_hash(&h), Some(7));
    assert_eq!(reg.get_by_id(7), Some(&h));
    assert_eq!(reg.get_by_hash(&[0xFF; 32]), None);
    assert_eq!(reg.get_by_id(999), None);
    assert_eq!(reg.size(), 1);
    assert_eq!(reg.max_local_id(), Some(7));
}

// -----------------------------------------------------------------------
// CompiledAuthority::from_passport
// -----------------------------------------------------------------------

#[test]
fn compiled_authority_from_passport_happy() {
    let passport = standard_happy_passport();

    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0);
    reg.add(hash_from_hex(TOOL_HEX_1), 1);

    let auth = CompiledAuthority::from_passport(&passport, reg)
        .expect("happy from_passport");

    // Temporal conversion.
    let expected_expires: DateTime<Utc> = "2026-05-19T22:39:56.000Z".parse().unwrap();
    let expected_expires_ns = u64::try_from(expected_expires.timestamp_nanos_opt().unwrap()).unwrap();
    assert_eq!(auth.expires_at_unix_ns, expected_expires_ns);

    // Sequence / budget initial state.
    assert_eq!(auth.sequence_next.load(Ordering::Acquire), 1000);
    assert_eq!(auth.sequence_end, 2000);
    assert_eq!(auth.budget_remaining_actions.load(Ordering::Acquire), 1000);
    assert_eq!(auth.budget_remaining_cost_units.load(Ordering::Acquire), 50_000);

    // Operation mask: read (bit 0) + external_send (bit 3) => 0b1001 = 9.
    assert_eq!(auth.allowed_op_mask, (1 << 0) | (1 << 3));

    // Identity hash matches BLAKE3 of the passport_id string.
    let expected_pid_hash = *blake3::hash("rp_01HX0EXAMPLE000000000000000".as_bytes()).as_bytes();
    assert_eq!(auth.passport_id_hash, expected_pid_hash);

    // Tool bitmap: bit 0 and bit 1 set.
    assert!(auth.allowed_tool_bitmap.get(0));
    assert!(auth.allowed_tool_bitmap.get(1));
    assert!(!auth.allowed_tool_bitmap.get(2));

    // resource_trie now populated by chunk 3 (was None in chunk 2).
    assert!(auth.resource_trie.is_some());
    assert_eq!(auth.approval_rules.len(), 1);

    // Durability mode for R2.
    assert!(matches!(auth.durability_mode, DurabilityMode::BlockingGroupCommit));

    // Verifier-instance hash present and matches.
    let expected_vi_hash = *blake3::hash("vi_01HX0VI00000000000000000000".as_bytes()).as_bytes();
    assert_eq!(auth.verifier_instance_id_hash, expected_vi_hash);
}

#[test]
fn compiled_authority_unknown_tool_errors() {
    let passport = standard_happy_passport();
    // Empty registry: every tool reference is unknown.
    let reg = ToolRegistry::new();

    match CompiledAuthority::from_passport(&passport, reg) {
        Err(CompileError::UnknownTool { descriptor_hash }) => {
            // First (and only registered) tool hash should be the one that fails.
            assert_eq!(descriptor_hash, hash_from_hex(TOOL_HEX_0));
        }
        other => panic!("expected UnknownTool, got {other:?}"),
    }
}

#[test]
fn compiled_authority_unknown_operation_errors() {
    let json = passport_json(
        "R2",
        "T2",
        "T2",
        &["read", "frobnicate"],
        &[TOOL_HEX_0],
    );
    let passport = RuntimePassport::from_json(&json).expect("parse");
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0);

    match CompiledAuthority::from_passport(&passport, reg) {
        Err(CompileError::UnknownOperation { name }) => {
            assert_eq!(name, "frobnicate");
        }
        other => panic!("expected UnknownOperation, got {other:?}"),
    }
}

#[test]
fn durability_mode_by_risk_class() {
    // R3 requires minimum_tier_required >= T2 (no actual minimum_tier rule;
    // we just use T2). R4 likewise. We only need a valid passport that
    // parses and compiles; tools must resolve so we register one for each.
    for (risk, expected) in [
        ("R0", DurabilityMode::MemoryBuffered),
        ("R1", DurabilityMode::MemoryBuffered),
        ("R2", DurabilityMode::BlockingGroupCommit),
        ("R3", DurabilityMode::BlockingGroupCommit),
        ("R4", DurabilityMode::Strict),
    ] {
        let json = passport_json(risk, "T2", "T2", &["read"], &[TOOL_HEX_0]);
        let passport = RuntimePassport::from_json(&json)
            .unwrap_or_else(|e| panic!("parse failed for {risk}: {e}"));
        let mut reg = ToolRegistry::new();
        reg.add(hash_from_hex(TOOL_HEX_0), 0);
        let auth = CompiledAuthority::from_passport(&passport, reg)
            .unwrap_or_else(|e| panic!("compile failed for {risk}: {e}"));
        assert!(
            matches!(
                (auth.durability_mode, expected),
                (DurabilityMode::MemoryBuffered, DurabilityMode::MemoryBuffered)
                    | (DurabilityMode::BlockingGroupCommit, DurabilityMode::BlockingGroupCommit)
                    | (DurabilityMode::Strict, DurabilityMode::Strict)
            ),
            "wrong mode for {risk}: got {:?}, expected {expected:?}",
            auth.durability_mode
        );
    }
}

#[test]
fn atomic_decrement_workflow() {
    let passport = standard_happy_passport();
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0);
    reg.add(hash_from_hex(TOOL_HEX_1), 1);
    let auth = CompiledAuthority::from_passport(&passport, reg).unwrap();

    // First advance: from 1000 to 1001 succeeds.
    let n0 = auth.sequence_next.load(Ordering::Acquire);
    assert_eq!(n0, 1000);
    assert!(auth.try_advance_sequence(n0), "first advance should succeed");
    assert_eq!(auth.sequence_next.load(Ordering::Acquire), 1001);

    // Replay attempt: trying to advance from 1000 again now fails.
    assert!(
        !auth.try_advance_sequence(1000),
        "replay (re-using prior expected) must fail"
    );
    assert_eq!(
        auth.sequence_next.load(Ordering::Acquire),
        1001,
        "sequence must not move on a failed CAS"
    );

    // Next monotonic advance succeeds.
    assert!(auth.try_advance_sequence(1001));
    assert_eq!(auth.sequence_next.load(Ordering::Acquire), 1002);

    // Budget atomic decrement reflects initialization.
    assert_eq!(auth.budget_remaining_actions.load(Ordering::Acquire), 1000);
    auth.budget_remaining_actions.fetch_sub(1, Ordering::AcqRel);
    assert_eq!(auth.budget_remaining_actions.load(Ordering::Acquire), 999);
}
