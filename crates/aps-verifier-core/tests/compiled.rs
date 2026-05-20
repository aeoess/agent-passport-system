//! Chunk-2 (CompiledAuthority + BitMap + ToolRegistry) tests, updated
//! for chunk 5's registry-root validation and Result-returning add().

use std::sync::atomic::Ordering;

use chrono::{DateTime, Utc};

use aps_verifier_core::{
    BitMap, CompileError, CompiledAuthority, DurabilityMode, RuntimePassport, ToolRegistry,
};

// -----------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn passport_json(
    root_hex: &str,
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
  "tool_registry_root": "blake3:{root_hex}",
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

fn hex_encode(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
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

fn standard_happy_setup() -> (RuntimePassport, ToolRegistry) {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    reg.add(hash_from_hex(TOOL_HEX_1), 1).unwrap();
    let root_hex = hex_encode(&reg.current_root());
    let json = passport_json(
        &root_hex,
        "R2",
        "T2",
        "T2",
        &["read", "external_send"],
        &[TOOL_HEX_0, TOOL_HEX_1],
    );
    let passport = RuntimePassport::from_json(&json).expect("happy passport parses");
    (passport, reg)
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
    assert!(bm.capacity() >= 100);
    assert_eq!(bm.capacity() % 64, 0);
    for b in 0u32..100 {
        assert!(!bm.get(b), "bit {b} should start cleared");
    }
}

#[test]
#[should_panic(expected = "BitMap index out of range")]
fn bitmap_out_of_range_set_panics() {
    let mut bm = BitMap::new(64);
    bm.set(64);
}

// -----------------------------------------------------------------------
// ToolRegistry (chunk-2 surface, post-chunk-5 API)
// -----------------------------------------------------------------------

#[test]
fn tool_registry_add_lookup() {
    let mut reg = ToolRegistry::new();
    let h = hash_from_hex(TOOL_HEX_0);
    reg.add(h, 7).unwrap();
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
    let (passport, reg) = standard_happy_setup();
    let auth = CompiledAuthority::from_passport(&passport, reg)
        .expect("happy from_passport");

    let expected_expires: DateTime<Utc> = "2026-05-19T22:39:56.000Z".parse().unwrap();
    let expected_expires_ns =
        u64::try_from(expected_expires.timestamp_nanos_opt().unwrap()).unwrap();
    assert_eq!(auth.expires_at_unix_ns, expected_expires_ns);

    assert_eq!(auth.sequence_next.load(Ordering::Acquire), 1000);
    assert_eq!(auth.sequence_end, 2000);
    assert_eq!(auth.budget_remaining_actions.load(Ordering::Acquire), 1000);
    assert_eq!(auth.budget_remaining_cost_units.load(Ordering::Acquire), 50_000);

    // Operation mask: read (bit 0) + external_send (bit 3) => 0b1001 = 9.
    assert_eq!(auth.allowed_op_mask, (1 << 0) | (1 << 3));

    let expected_pid_hash = *blake3::hash("rp_01HX0EXAMPLE000000000000000".as_bytes()).as_bytes();
    assert_eq!(auth.passport_id_hash, expected_pid_hash);

    assert!(auth.allowed_tool_bitmap.get(0));
    assert!(auth.allowed_tool_bitmap.get(1));
    assert!(!auth.allowed_tool_bitmap.get(2));

    assert!(auth.resource_trie.is_some());
    assert_eq!(auth.approval_rules.len(), 1);

    assert!(matches!(auth.durability_mode, DurabilityMode::BlockingGroupCommit));

    let expected_vi_hash = *blake3::hash("vi_01HX0VI00000000000000000000".as_bytes()).as_bytes();
    assert_eq!(auth.verifier_instance_id_hash, expected_vi_hash);
}

#[test]
fn compiled_authority_unknown_tool_errors() {
    // Empty registry whose root matches the passport's claim, but whose
    // contents don't actually carry TOOL_HEX_0. The runtime catches the
    // mismatch as UnknownTool at the per-tool lookup step.
    let reg = ToolRegistry::new();
    let root_hex = hex_encode(&reg.current_root());
    let json = passport_json(
        &root_hex,
        "R2",
        "T2",
        "T2",
        &["read"],
        &[TOOL_HEX_0],
    );
    let passport = RuntimePassport::from_json(&json).expect("parse");

    match CompiledAuthority::from_passport(&passport, reg) {
        Err(CompileError::UnknownTool { descriptor_hash }) => {
            assert_eq!(descriptor_hash, hash_from_hex(TOOL_HEX_0));
        }
        other => panic!("expected UnknownTool, got {other:?}"),
    }
}

#[test]
fn compiled_authority_unknown_operation_errors() {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    let root_hex = hex_encode(&reg.current_root());
    let json = passport_json(
        &root_hex,
        "R2",
        "T2",
        "T2",
        &["read", "frobnicate"],
        &[TOOL_HEX_0],
    );
    let passport = RuntimePassport::from_json(&json).expect("parse");

    match CompiledAuthority::from_passport(&passport, reg) {
        Err(CompileError::UnknownOperation { name }) => {
            assert_eq!(name, "frobnicate");
        }
        other => panic!("expected UnknownOperation, got {other:?}"),
    }
}

#[test]
fn durability_mode_by_risk_class() {
    for (risk, expected) in [
        ("R0", DurabilityMode::MemoryBuffered),
        ("R1", DurabilityMode::MemoryBuffered),
        ("R2", DurabilityMode::BlockingGroupCommit),
        ("R3", DurabilityMode::BlockingGroupCommit),
        ("R4", DurabilityMode::Strict),
    ] {
        let mut reg = ToolRegistry::new();
        reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
        let root_hex = hex_encode(&reg.current_root());
        let json = passport_json(&root_hex, risk, "T2", "T2", &["read"], &[TOOL_HEX_0]);
        let passport = RuntimePassport::from_json(&json)
            .unwrap_or_else(|e| panic!("parse failed for {risk}: {e}"));
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
    let (passport, reg) = standard_happy_setup();
    let auth = CompiledAuthority::from_passport(&passport, reg).unwrap();

    let n0 = auth.sequence_next.load(Ordering::Acquire);
    assert_eq!(n0, 1000);
    assert!(auth.try_advance_sequence(n0), "first advance should succeed");
    assert_eq!(auth.sequence_next.load(Ordering::Acquire), 1001);

    assert!(
        !auth.try_advance_sequence(1000),
        "replay (re-using prior expected) must fail"
    );
    assert_eq!(auth.sequence_next.load(Ordering::Acquire), 1001);

    assert!(auth.try_advance_sequence(1001));
    assert_eq!(auth.sequence_next.load(Ordering::Acquire), 1002);

    assert_eq!(auth.budget_remaining_actions.load(Ordering::Acquire), 1000);
    auth.budget_remaining_actions.fetch_sub(1, Ordering::AcqRel);
    assert_eq!(auth.budget_remaining_actions.load(Ordering::Acquire), 999);
}

// -----------------------------------------------------------------------
// New chunk-5 tests: registry root validation
// -----------------------------------------------------------------------

#[test]
fn compiled_authority_accepts_matching_registry_root() {
    let (passport, reg) = standard_happy_setup();
    assert!(CompiledAuthority::from_passport(&passport, reg).is_ok());
}

#[test]
fn compiled_authority_rejects_registry_root_mismatch() {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    reg.add(hash_from_hex(TOOL_HEX_1), 1).unwrap();

    // Passport claims a wrong root (all zeros) while the verifier's
    // registry has its actual root.
    let wrong_root = "0".repeat(64);
    let json = passport_json(
        &wrong_root,
        "R2",
        "T2",
        "T2",
        &["read", "external_send"],
        &[TOOL_HEX_0, TOOL_HEX_1],
    );
    let passport = RuntimePassport::from_json(&json).expect("parse");

    match CompiledAuthority::from_passport(&passport, reg) {
        Err(CompileError::RegistryRootMismatch {
            passport_root,
            verifier_root,
        }) => {
            assert_eq!(passport_root, wrong_root);
            assert_ne!(verifier_root, wrong_root);
            assert_eq!(verifier_root.len(), 64);
        }
        other => panic!("expected RegistryRootMismatch, got {other:?}"),
    }
}
