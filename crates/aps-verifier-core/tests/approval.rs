//! Chunk-4 tests for the approval-rule predicate compiler.

use aps_verifier_core::{
    ActionDescriptor, ApprovalAction, ApprovalCompileError, CompareOp, CompileError,
    CompiledApprovalRule, CompiledAuthority, CompiledPredicate, PredicateField, RuntimePassport,
    SetOp, ToolRegistry,
};

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn compile(predicate: &str) -> Result<CompiledApprovalRule, ApprovalCompileError> {
    CompiledApprovalRule::compile(predicate, ApprovalAction::Escalate)
}

fn must_compile(predicate: &str) -> CompiledApprovalRule {
    compile(predicate).unwrap_or_else(|e| panic!("compile failed for {predicate:?}: {e}"))
}

/// Minimal valid ActionDescriptor with all-zero fields except `version`,
/// to be mutated per test.
fn empty_action() -> ActionDescriptor {
    ActionDescriptor {
        version: 1,
        reserved: [0; 3],
        passport_id_hash: [0; 32],
        tool_descriptor_hash: [0; 32],
        local_tool_id: 0,
        operation_id: 0,
        resource_type: 0,
        risk_class: 0,
        resource_path_depth: 0,
        reserved2: [0; 2],
        cost_units: 0,
        sequence_id: 0,
        nonce: [0; 16],
        resource_path_hashes: [0; 8],
        action_hash: [0; 32],
    }
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

// -----------------------------------------------------------------------
// Lexer / parser happy paths
// -----------------------------------------------------------------------

#[test]
fn compile_simple_equality() {
    let r = must_compile("operation == external_send");
    assert_eq!(r.terms.len(), 1);
    match &r.terms[0] {
        CompiledPredicate::Compare { field, op, value } => {
            assert_eq!(*field, PredicateField::Operation);
            assert_eq!(*op, CompareOp::Eq);
            assert_eq!(*value, 3);
        }
        other => panic!("unexpected term: {other:?}"),
    }
}

#[test]
fn compile_numeric_comparison() {
    let r = must_compile("cost_units > 10000");
    assert_eq!(r.terms.len(), 1);
    match &r.terms[0] {
        CompiledPredicate::Compare { field, op, value } => {
            assert_eq!(*field, PredicateField::CostUnits);
            assert_eq!(*op, CompareOp::Gt);
            assert_eq!(*value, 10000);
        }
        other => panic!("unexpected term: {other:?}"),
    }
}

#[test]
fn compile_risk_class_ge() {
    let r = must_compile("risk_class >= R3");
    match &r.terms[0] {
        CompiledPredicate::Compare { field, op, value } => {
            assert_eq!(*field, PredicateField::RiskClass);
            assert_eq!(*op, CompareOp::Ge);
            assert_eq!(*value, 3);
        }
        other => panic!("unexpected term: {other:?}"),
    }
}

#[test]
fn compile_set_membership_in() {
    let r = must_compile("operation IN [read, write]");
    match &r.terms[0] {
        CompiledPredicate::SetMember { field, op, set } => {
            assert_eq!(*field, PredicateField::Operation);
            assert_eq!(*op, SetOp::In);
            assert_eq!(set, &vec![0u64, 1u64]);
        }
        other => panic!("unexpected term: {other:?}"),
    }
}

#[test]
fn compile_set_membership_not_in() {
    let r = must_compile("operation NOT IN [money_move]");
    match &r.terms[0] {
        CompiledPredicate::SetMember { field, op, set } => {
            assert_eq!(*field, PredicateField::Operation);
            assert_eq!(*op, SetOp::NotIn);
            assert_eq!(set, &vec![4u64]);
        }
        other => panic!("unexpected term: {other:?}"),
    }
}

#[test]
fn compile_conjunction() {
    let r = must_compile("operation == external_send AND cost_units > 1000");
    assert_eq!(r.terms.len(), 2);
}

#[test]
fn compile_three_terms_conjunction() {
    let r = must_compile("operation == external_send AND risk_class >= R3 AND cost_units > 1000");
    assert_eq!(r.terms.len(), 3);
}

// -----------------------------------------------------------------------
// Error paths
// -----------------------------------------------------------------------

#[test]
fn compile_empty_predicate() {
    assert!(matches!(compile(""), Err(ApprovalCompileError::EmptyPredicate)));
}

#[test]
fn compile_whitespace_only() {
    assert!(matches!(
        compile("   "),
        Err(ApprovalCompileError::EmptyPredicate)
    ));
}

#[test]
fn compile_unknown_field() {
    match compile("recipient NOT IN allowlist") {
        Err(ApprovalCompileError::UnknownField(s)) => assert_eq!(s, "recipient"),
        other => panic!("expected UnknownField, got {other:?}"),
    }
}

#[test]
fn compile_unknown_operation() {
    match compile("operation == frobnicate") {
        Err(ApprovalCompileError::UnknownOperation(s)) => assert_eq!(s, "frobnicate"),
        other => panic!("expected UnknownOperation, got {other:?}"),
    }
}

#[test]
fn compile_unknown_risk_class() {
    match compile("risk_class == R9") {
        Err(ApprovalCompileError::UnknownRiskClass(s)) => assert_eq!(s, "R9"),
        other => panic!("expected UnknownRiskClass, got {other:?}"),
    }
}

#[test]
fn compile_unsupported_operator_operation() {
    match compile("operation < external_send") {
        Err(ApprovalCompileError::UnsupportedOperator { field, op }) => {
            assert_eq!(field, PredicateField::Operation);
            assert_eq!(op, "<");
        }
        other => panic!("expected UnsupportedOperator, got {other:?}"),
    }
}

#[test]
fn compile_unsupported_set_field() {
    match compile("cost_units IN [100, 200]") {
        Err(ApprovalCompileError::UnsupportedOperator { field, op }) => {
            assert_eq!(field, PredicateField::CostUnits);
            assert_eq!(op, "IN");
        }
        other => panic!("expected UnsupportedOperator for cost_units IN, got {other:?}"),
    }
}

#[test]
fn compile_syntax_error_missing_op() {
    match compile("operation external_send") {
        Err(ApprovalCompileError::SyntaxError { .. }) => {}
        other => panic!("expected SyntaxError, got {other:?}"),
    }
}

#[test]
fn compile_syntax_error_unclosed_bracket() {
    match compile("operation IN [read, write") {
        Err(ApprovalCompileError::SyntaxError { .. }) => {}
        other => panic!("expected SyntaxError, got {other:?}"),
    }
}

#[test]
fn compile_lowercase_and_fails() {
    // Lowercase 'and' is read as an identifier, which then fails because
    // 'and' is not 'AND'. Surfaces as SyntaxError (not 'AND' or EOF).
    match compile("operation == read and cost_units > 1") {
        Err(ApprovalCompileError::SyntaxError { .. }) => {}
        other => panic!("expected SyntaxError on lowercase 'and', got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Match semantics
// -----------------------------------------------------------------------

#[test]
fn matches_eq_operation() {
    let r = must_compile("operation == external_send");
    let mut a = empty_action();
    a.operation_id = 3;
    assert!(r.matches(&a));
    a.operation_id = 4;
    assert!(!r.matches(&a));
}

#[test]
fn matches_numeric_gt() {
    let r = must_compile("cost_units > 1000");
    let mut a = empty_action();
    a.cost_units = 5000;
    assert!(r.matches(&a));
    a.cost_units = 1000;
    assert!(!r.matches(&a)); // strict
    a.cost_units = 999;
    assert!(!r.matches(&a));
}

#[test]
fn matches_set_in() {
    let r = must_compile("operation IN [read, write]");
    let mut a = empty_action();
    a.operation_id = 0; // read
    assert!(r.matches(&a));
    a.operation_id = 1; // write
    assert!(r.matches(&a));
    a.operation_id = 3; // external_send
    assert!(!r.matches(&a));
}

#[test]
fn matches_set_not_in() {
    let r = must_compile("operation NOT IN [money_move]");
    let mut a = empty_action();
    a.operation_id = 3; // external_send
    assert!(r.matches(&a));
    a.operation_id = 4; // money_move
    assert!(!r.matches(&a));
}

#[test]
fn matches_conjunction_both_true() {
    let r = must_compile("operation == external_send AND cost_units > 1000");
    let mut a = empty_action();
    a.operation_id = 3;
    a.cost_units = 5000;
    assert!(r.matches(&a));
}

#[test]
fn matches_conjunction_one_false() {
    let r = must_compile("operation == external_send AND cost_units > 1000");
    let mut a = empty_action();
    a.operation_id = 3;
    a.cost_units = 500;
    assert!(!r.matches(&a), "cost_units below threshold should deny");
    a.cost_units = 5000;
    a.operation_id = 4;
    assert!(!r.matches(&a), "wrong operation should deny");
}

// -----------------------------------------------------------------------
// Integration through CompiledAuthority::from_passport
// -----------------------------------------------------------------------

fn hex_encode(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn passport_with_rules(rules_json: &str, root_hex: &str) -> RuntimePassport {
    let json = format!(
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
  "risk_class": "R2",
  "minimum_tier_required": "T2",
  "tier_attested": "T2",
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
    "allowed_tools": ["blake3:{TOOL_HEX_0}"],
    "allowed_operations": ["read", "external_send"],
    "resource_scopes": ["customer/*"],
    "approval_rules": {rules_json}
  }},
  "receipt_stream_id": "rs_01HX0RS00000000000000000000",
  "signature": "ed25519:{sig}"
}}"#,
        sig = "0".repeat(128)
    );
    RuntimePassport::from_json(&json).expect("parse passport")
}

fn registry_with_tool0() -> (ToolRegistry, String) {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    let root_hex = hex_encode(&reg.current_root());
    (reg, root_hex)
}

#[test]
fn compiled_authority_with_approval_rules() {
    let (reg, root_hex) = registry_with_tool0();
    let passport = passport_with_rules(
        r#"[{"predicate": "operation == external_send", "on_match": "escalate"}]"#,
        &root_hex,
    );
    let auth = CompiledAuthority::from_passport(&passport, reg).unwrap();
    assert_eq!(auth.approval_rules.len(), 1);

    let mut a = empty_action();
    a.operation_id = 3;
    assert!(auth.approval_rules[0].matches(&a));
}

#[test]
fn compiled_authority_uncompilable_rule_rejects_passport() {
    let (reg, root_hex) = registry_with_tool0();
    let passport = passport_with_rules(
        r#"[{"predicate": "recipient NOT IN allowlist", "on_match": "escalate"}]"#,
        &root_hex,
    );
    match CompiledAuthority::from_passport(&passport, reg) {
        Err(CompileError::ApprovalRule(ApprovalCompileError::UnknownField(s))) => {
            assert_eq!(s, "recipient");
        }
        other => panic!("expected ApprovalRule(UnknownField), got {other:?}"),
    }
}

#[test]
fn compiled_authority_empty_approval_rules_ok() {
    let (reg, root_hex) = registry_with_tool0();
    let passport = passport_with_rules("[]", &root_hex);
    let auth = CompiledAuthority::from_passport(&passport, reg).unwrap();
    assert!(auth.approval_rules.is_empty());
}
