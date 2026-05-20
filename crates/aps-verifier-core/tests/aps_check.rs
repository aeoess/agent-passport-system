//! Chunk-7 tests for `aps_check`: spec §9 happy path + every deny
//! reason + short-circuit ordering + decision integrity.

mod common;

use std::sync::atomic::Ordering;

use aps_verifier_core::{
    aps_check, ApprovalAction, Clock, CompiledAuthority, Decision, DecisionType, ReasonCode,
    RuntimePassport, Tier, ToolRegistry,
};

use common::{
    default_clock_ns, default_expires_at_ns, default_issued_at_ns, default_passport_id_hash,
    hash_from_hex, ActionBuilder, PassportBuilder, TestVerifier,
};

const TOOL_HEX_0: &str = "abcd000000000000000000000000000000000000000000000000000000000000";

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn happy_setup() -> (CompiledAuthority, ToolRegistry) {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    let registry_for_compile = ToolRegistry::from_entries(vec![aps_verifier_core::ToolEntry {
        descriptor_hash: hash_from_hex(TOOL_HEX_0),
        local_id: 0,
    }])
    .unwrap();
    let root = reg.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_risk_class("R2")
        .with_tier("T2", "T2")
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(vec!["customer/*"])
        .build_json();
    let passport = RuntimePassport::from_json(&json).unwrap();
    let auth = CompiledAuthority::from_passport(&passport, registry_for_compile).unwrap();
    (auth, reg)
}

fn happy_action() -> aps_verifier_core::ActionDescriptor {
    ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .build()
}

// -----------------------------------------------------------------------
// Happy paths
// -----------------------------------------------------------------------

#[test]
fn allow_minimal() {
    let (auth, _reg) = happy_setup();
    let action = happy_action();
    let v = TestVerifier::new();
    let d = aps_check(&auth, &action, &v.context());
    assert!(
        matches!(d.decision_type, DecisionType::Allow),
        "expected Allow, got reason 0x{:02X}",
        d.reason_code as u8
    );
    assert_eq!(d.reason_code as u8, ReasonCode::Ok as u8);
    assert_eq!(d.sequence_id, action.sequence_id);
    assert_ne!(d.event_mac, [0u8; 32], "Allow must carry a non-zero MAC");
}

#[test]
fn allow_event_mac_matches_recomputation() {
    let (auth, _reg) = happy_setup();
    let action = happy_action();
    let v = TestVerifier::new();
    let d = aps_check(&auth, &action, &v.context());
    // Compute the MAC independently using the same inputs aps_check used.
    let key = auth.receipt_stream_key;
    let pid = auth.passport_id_hash;
    let ah = action.action_hash;
    let ts = v.clock.now_unix_ns();
    let expected = d.compute_event_mac(&key, &pid, &ah, ts);
    assert_eq!(d.event_mac, expected);
}

// -----------------------------------------------------------------------
// Deny: spec §9 step 0
// -----------------------------------------------------------------------

#[test]
fn deny_action_hash_invalid() {
    let (auth, _reg) = happy_setup();
    let mut action = happy_action();
    // Tamper after finalize(): the stored action_hash no longer matches
    // the rest of the fields.
    action.sequence_id = action.sequence_id.wrapping_add(1);
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.decision_type as u8, DecisionType::Deny as u8);
    assert_eq!(d.reason_code as u8, ReasonCode::ActionHashInvalid as u8);
    assert_ne!(d.event_mac, [0u8; 32]);
}

// -----------------------------------------------------------------------
// Deny: step 1 (instance binding)
// -----------------------------------------------------------------------

#[test]
fn deny_verifier_instance_mismatch() {
    let (auth, _reg) = happy_setup();
    let action = happy_action();
    let v = TestVerifier::new().with_instance_hash([0u8; 32]);
    let d = aps_check(&auth, &action, &v.context());
    assert_eq!(d.reason_code as u8, ReasonCode::VerifierInstanceMismatch as u8);
}

// -----------------------------------------------------------------------
// Deny: step 2 (temporal)
// -----------------------------------------------------------------------

#[test]
fn deny_expired_passport() {
    let (auth, _reg) = happy_setup();
    let action = happy_action();
    let v = TestVerifier::new().with_clock_ns(default_expires_at_ns() + 60_000_000_000);
    let d = aps_check(&auth, &action, &v.context());
    assert_eq!(d.reason_code as u8, ReasonCode::ExpiredPassport as u8);
}

#[test]
fn deny_not_yet_valid() {
    let (auth, _reg) = happy_setup();
    let action = happy_action();
    // 60 seconds before issued_at, well outside the 1s skew.
    let v = TestVerifier::new().with_clock_ns(default_issued_at_ns() - 60_000_000_000);
    let d = aps_check(&auth, &action, &v.context());
    assert_eq!(d.reason_code as u8, ReasonCode::NotYetValid as u8);
}

// -----------------------------------------------------------------------
// Deny: step 3 (R3+ time-anchor freshness)
// -----------------------------------------------------------------------

#[test]
fn deny_clock_anchor_stale_for_r3_action() {
    // R2 authority lets an R2 action through normally; bump action's
    // risk_class to R3 so the freshness check fires, then advance the
    // clock well past the anchor.
    let (auth, _reg) = happy_setup();
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .with_risk_class(3)
        .build();
    // last_time_anchor_ns is initialized to issued_at; move "now" 60s
    // past it. R2 authority lets R3 action through risk check FAIL
    // (action.risk_class > auth.risk_class is the failure mode), so
    // actually for this to test step 3 we need authority R3.
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    let registry_for_compile = ToolRegistry::from_entries(vec![aps_verifier_core::ToolEntry {
        descriptor_hash: hash_from_hex(TOOL_HEX_0),
        local_id: 0,
    }])
    .unwrap();
    let root = reg.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_risk_class("R3")
        .with_tier("T2", "T2")
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(vec!["customer/*"])
        .build_json();
    let passport = RuntimePassport::from_json(&json).unwrap();
    let r3_auth = CompiledAuthority::from_passport(&passport, registry_for_compile).unwrap();
    let _ = auth;

    let v = TestVerifier::new().with_clock_ns(default_issued_at_ns() + 31_000_000_000);
    let d = aps_check(&r3_auth, &action, &v.context());
    assert_eq!(d.reason_code as u8, ReasonCode::ClockAnchorStale as u8);
}

// -----------------------------------------------------------------------
// Deny: step 4 (revocation)
// -----------------------------------------------------------------------

#[test]
fn deny_stale_revocation_epoch() {
    let (auth, _reg) = happy_setup();
    let action = happy_action();
    // authority.revocation_epoch is 1842 (from passport defaults); a
    // verifier carrying epoch 0 is stale.
    let v = TestVerifier::new().with_revocation_epoch(0);
    let d = aps_check(&auth, &action, &v.context());
    assert_eq!(d.reason_code as u8, ReasonCode::StaleRevocationEpoch as u8);
}

// -----------------------------------------------------------------------
// Deny: step 5 (tier)
// -----------------------------------------------------------------------

#[test]
fn deny_risk_tier_too_low() {
    let (auth, _reg) = happy_setup();
    let action = happy_action();
    let v = TestVerifier::new().with_tier(Tier::T1);
    let d = aps_check(&auth, &action, &v.context());
    assert_eq!(d.reason_code as u8, ReasonCode::RiskTierTooLow as u8);
}

// -----------------------------------------------------------------------
// Deny: step 6 (risk class + strict mode)
// -----------------------------------------------------------------------

#[test]
fn deny_risk_class_exceeded() {
    // Authority R2 + action R3 (but action R3 risk_class > auth's 2).
    let (auth, _reg) = happy_setup();
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .with_risk_class(3)
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::RiskClassExceeded as u8);
}

#[test]
fn deny_strict_mode_required_for_r4_action() {
    // Even if action.risk_class <= auth.risk_class, R4 always denies.
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    let registry_for_compile = ToolRegistry::from_entries(vec![aps_verifier_core::ToolEntry {
        descriptor_hash: hash_from_hex(TOOL_HEX_0),
        local_id: 0,
    }])
    .unwrap();
    let root = reg.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_risk_class("R4")
        .with_tier("T2", "T2")
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(vec!["customer/*"])
        .build_json();
    let passport = RuntimePassport::from_json(&json).unwrap();
    let r4_auth = CompiledAuthority::from_passport(&passport, registry_for_compile).unwrap();
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .with_risk_class(4)
        .build();
    let d = aps_check(&r4_auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::StrictModeRequired as u8);
}

// -----------------------------------------------------------------------
// Deny: step 7 (tool)
// -----------------------------------------------------------------------

#[test]
fn deny_registry_version_mismatch() {
    let (auth, _reg) = happy_setup();
    // Action carries a tool_descriptor_hash that doesn't match what the
    // authority's registry has at local_id 0.
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash([0xFF; 32])
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::RegistryVersionMismatch as u8);
}

#[test]
fn deny_tool_not_allowed() {
    // Set up an authority whose registry knows TWO tools but whose
    // allowed_tools bitmap only carries the first.
    let mut reg_for_passport = ToolRegistry::new();
    let other_hex = "ef01000000000000000000000000000000000000000000000000000000000000";
    reg_for_passport
        .add(hash_from_hex(TOOL_HEX_0), 0)
        .unwrap();
    reg_for_passport
        .add(hash_from_hex(other_hex), 1)
        .unwrap();
    let root = reg_for_passport.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_risk_class("R2")
        .with_tier("T2", "T2")
        // Only authorize TOOL_HEX_0; the registry still has both.
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(vec!["customer/*"])
        .build_json();
    let passport = RuntimePassport::from_json(&json).unwrap();
    let registry_for_compile = ToolRegistry::from_entries(vec![
        aps_verifier_core::ToolEntry { descriptor_hash: hash_from_hex(TOOL_HEX_0), local_id: 0 },
        aps_verifier_core::ToolEntry { descriptor_hash: hash_from_hex(other_hex), local_id: 1 },
    ])
    .unwrap();
    let auth = CompiledAuthority::from_passport(&passport, registry_for_compile).unwrap();

    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(other_hex))
        .with_local_tool_id(1)
        .with_resource_path(&["customer", "123"])
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::ToolNotAllowed as u8);
}

// -----------------------------------------------------------------------
// Deny: step 8 (operation)
// -----------------------------------------------------------------------

#[test]
fn deny_operation_not_allowed() {
    let (auth, _reg) = happy_setup();
    // Authority allows "read" (op_id 0); action uses "write" (op_id 1).
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .with_operation_id(1)
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::OperationNotAllowed as u8);
}

// -----------------------------------------------------------------------
// Deny: step 9 (resource scope)
// -----------------------------------------------------------------------

#[test]
fn deny_resource_out_of_scope() {
    let (auth, _reg) = happy_setup();
    // Authority allows "customer/*"; action targets "unrelated/path".
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["unrelated", "path"])
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::ResourceOutOfScope as u8);
}

// -----------------------------------------------------------------------
// Deny: step 10 (sequence)
// -----------------------------------------------------------------------

#[test]
fn deny_sequence_replay_below_window() {
    let (auth, _reg) = happy_setup();
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .with_sequence_id(999) // < sequence_start (1000)
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::SequenceReplay as u8);
}

#[test]
fn deny_sequence_replay_above_window() {
    let (auth, _reg) = happy_setup();
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .with_sequence_id(2000) // >= sequence_end (2000)
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::SequenceReplay as u8);
}

// -----------------------------------------------------------------------
// Deny: step 11 (budget)
// -----------------------------------------------------------------------

#[test]
fn deny_budget_exceeded_and_rolls_back_sequence() {
    let (auth, _reg) = happy_setup();
    // budget_remaining_cost_units default is 50_000; bump action cost
    // above that.
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .with_cost_units(100_000)
        .build();
    let pre_seq = auth.sequence_next.load(Ordering::Acquire);
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::BudgetExceeded as u8);
    // Sequence must NOT have advanced (or must have been rolled back).
    assert_eq!(auth.sequence_next.load(Ordering::Acquire), pre_seq);
}

// -----------------------------------------------------------------------
// Step 12 (approval rules): Escalate and Deny on_match
// -----------------------------------------------------------------------

fn auth_with_rule(predicate: &str, on_match: ApprovalAction) -> (CompiledAuthority, ToolRegistry) {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    let registry_for_compile = ToolRegistry::from_entries(vec![aps_verifier_core::ToolEntry {
        descriptor_hash: hash_from_hex(TOOL_HEX_0),
        local_id: 0,
    }])
    .unwrap();
    let root = reg.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_risk_class("R2")
        .with_tier("T2", "T2")
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(vec!["customer/*"])
        .with_approval_rules(vec![(predicate.into(), on_match)])
        .build_json();
    let passport = RuntimePassport::from_json(&json).unwrap();
    let auth = CompiledAuthority::from_passport(&passport, registry_for_compile).unwrap();
    (auth, reg)
}

#[test]
fn escalate_on_approval_required() {
    // Rule: operation == read AND cost_units > 0 → Escalate.
    let (auth, _) = auth_with_rule(
        "operation == read AND cost_units > 0",
        ApprovalAction::Escalate,
    );
    let action = happy_action(); // cost_units = 1
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.decision_type as u8, DecisionType::Escalate as u8);
    assert_eq!(d.reason_code as u8, ReasonCode::ApprovalRequired as u8);
}

#[test]
fn deny_denied_by_rule() {
    let (auth, _) = auth_with_rule(
        "operation == read AND cost_units > 0",
        ApprovalAction::Deny,
    );
    let action = happy_action();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.decision_type as u8, DecisionType::Deny as u8);
    assert_eq!(d.reason_code as u8, ReasonCode::DeniedByRule as u8);
}

// -----------------------------------------------------------------------
// Short-circuit ordering tests
// -----------------------------------------------------------------------

#[test]
fn short_circuits_action_hash_before_temporal() {
    // Both action_hash bad AND expired clock; expect ActionHashInvalid
    // (step 0 fires before step 2).
    let (auth, _reg) = happy_setup();
    let mut action = happy_action();
    action.sequence_id = action.sequence_id.wrapping_add(1); // tampers action_hash
    let v = TestVerifier::new().with_clock_ns(default_expires_at_ns() + 60_000_000_000);
    let d = aps_check(&auth, &action, &v.context());
    assert_eq!(d.reason_code as u8, ReasonCode::ActionHashInvalid as u8);
}

#[test]
fn short_circuits_tier_before_tool() {
    // T1 verifier (tier-too-low) AND bad tool hash; expect RiskTierTooLow.
    let (auth, _reg) = happy_setup();
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash([0xFF; 32]) // would otherwise trigger Registry mismatch
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .build();
    let v = TestVerifier::new().with_tier(Tier::T1);
    let d = aps_check(&auth, &action, &v.context());
    assert_eq!(d.reason_code as u8, ReasonCode::RiskTierTooLow as u8);
}

#[test]
fn short_circuits_tool_before_operation() {
    // Bad tool AND bad operation; expect RegistryVersionMismatch.
    let (auth, _reg) = happy_setup();
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash([0xFF; 32])
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .with_operation_id(1) // would otherwise trigger OperationNotAllowed
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::RegistryVersionMismatch as u8);
}

// -----------------------------------------------------------------------
// Decision integrity
// -----------------------------------------------------------------------

#[test]
fn deny_decisions_carry_event_mac() {
    let (auth, _reg) = happy_setup();
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["unrelated"]) // forces ResourceOutOfScope
        .build();
    let v = TestVerifier::new();
    let d = aps_check(&auth, &action, &v.context());
    assert_eq!(d.reason_code as u8, ReasonCode::ResourceOutOfScope as u8);
    assert_ne!(d.event_mac, [0u8; 32]);

    let ts = v.clock.now_unix_ns();
    let expected = d.compute_event_mac(
        &auth.receipt_stream_key,
        &auth.passport_id_hash,
        &action.action_hash,
        ts,
    );
    assert_eq!(d.event_mac, expected);
}

#[test]
fn decision_id_unique_across_calls() {
    let (auth, _reg) = happy_setup();
    let action = happy_action();
    let v = TestVerifier::new();
    let ctx = v.context();
    let mut ids = std::collections::HashSet::new();
    // The first call advances auth.sequence_next; subsequent calls
    // (with the same action.sequence_id = 1000) will hit SequenceReplay,
    // but decision_id still increments per call.
    for _ in 0..100 {
        let d = aps_check(&auth, &action, &ctx);
        ids.insert(d.decision_id);
    }
    assert_eq!(ids.len(), 100, "expected 100 distinct decision_ids");
}

// -----------------------------------------------------------------------
// Anchor: silence unused-import warnings, exercise passport_id alignment
// -----------------------------------------------------------------------

#[test]
fn passport_id_hash_matches_default_helper() {
    let (auth, _reg) = happy_setup();
    assert_eq!(auth.passport_id_hash, default_passport_id_hash());
    let _ = default_clock_ns();
    let _ = Decision::default_dummy();
}

trait DecisionDefault {
    fn default_dummy() -> Decision;
}
impl DecisionDefault for Decision {
    fn default_dummy() -> Decision {
        Decision {
            decision_type: DecisionType::Allow,
            reason_code: ReasonCode::Ok,
            reserved: [0; 6],
            sequence_id: 0,
            decision_id: [0; 16],
            event_mac: [0; 32],
        }
    }
}
