//! Chunk-2 (CompiledAuthority + BitMap + ToolRegistry) tests, updated
//! for chunk 5's registry-root validation and Result-returning add().

mod common;

use std::sync::atomic::Ordering;

use chrono::{DateTime, Utc};

use aps_verifier_core::{
    ApprovalAction, BitMap, CompileError, CompiledAuthority, DurabilityMode, RuntimePassport,
    ToolRegistry,
};

use common::{hash_from_hex, PassportBuilder};

// -----------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------

const TOOL_HEX_0: &str = "abcd000000000000000000000000000000000000000000000000000000000000";
const TOOL_HEX_1: &str = "ef01000000000000000000000000000000000000000000000000000000000000";

fn standard_happy_setup() -> (RuntimePassport, ToolRegistry) {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    reg.add(hash_from_hex(TOOL_HEX_1), 1).unwrap();
    let root = reg.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_risk_class("R2")
        .with_tier("T2", "T2")
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0), hash_from_hex(TOOL_HEX_1)])
        .with_allowed_operations(vec!["read", "external_send"])
        .with_resource_scopes(vec!["customer/*"])
        .with_approval_rules(vec![(
            "operation == external_send".into(),
            ApprovalAction::Escalate,
        )])
        .build_json();
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
    let root = reg.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(vec!["customer/*"])
        .build_json();
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
    let root = reg.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read", "frobnicate"])
        .with_resource_scopes(vec!["customer/*"])
        .build_json();
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
        let root = reg.current_root();
        let json = PassportBuilder::new()
            .with_root(root)
            .with_risk_class(risk)
            .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
            .with_allowed_operations(vec!["read"])
            .with_resource_scopes(vec!["customer/*"])
            .build_json();
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
    let wrong_root = [0u8; 32];
    let wrong_root_hex = "0".repeat(64);
    let json = PassportBuilder::new()
        .with_root(wrong_root)
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0), hash_from_hex(TOOL_HEX_1)])
        .with_allowed_operations(vec!["read", "external_send"])
        .with_resource_scopes(vec!["customer/*"])
        .build_json();
    let passport = RuntimePassport::from_json(&json).expect("parse");

    match CompiledAuthority::from_passport(&passport, reg) {
        Err(CompileError::RegistryRootMismatch {
            passport_root,
            verifier_root,
        }) => {
            assert_eq!(passport_root, wrong_root_hex);
            assert_ne!(verifier_root, wrong_root_hex);
            assert_eq!(verifier_root.len(), 64);
        }
        other => panic!("expected RegistryRootMismatch, got {other:?}"),
    }
}
