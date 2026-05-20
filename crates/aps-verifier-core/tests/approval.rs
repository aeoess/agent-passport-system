//! Chunk-4 tests for the approval-rule predicate compiler.

mod common;

use aps_verifier_core::{
    ApprovalAction, ApprovalCompileError, CompareOp, CompileError, CompiledApprovalRule,
    CompiledAuthority, CompiledPredicate, PredicateField, RuntimePassport, SetOp, ToolRegistry,
};

use common::{empty_action_descriptor as empty_action, hash_from_hex, PassportBuilder};

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn compile(predicate: &str) -> Result<CompiledApprovalRule, ApprovalCompileError> {
    CompiledApprovalRule::compile(predicate, ApprovalAction::Escalate)
}

fn must_compile(predicate: &str) -> CompiledApprovalRule {
    compile(predicate).unwrap_or_else(|e| panic!("compile failed for {predicate:?}: {e}"))
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

fn registry_with_tool0() -> (ToolRegistry, [u8; 32]) {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    let root = reg.current_root();
    (reg, root)
}

fn passport_for_approval_test(
    rules: Vec<(String, ApprovalAction)>,
    root: [u8; 32],
) -> RuntimePassport {
    let json = PassportBuilder::new()
        .with_root(root)
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read", "external_send"])
        .with_resource_scopes(vec!["customer/*"])
        .with_approval_rules(rules)
        .build_json();
    RuntimePassport::from_json(&json).expect("parse passport")
}

#[test]
fn compiled_authority_with_approval_rules() {
    let (reg, root) = registry_with_tool0();
    let passport = passport_for_approval_test(
        vec![("operation == external_send".into(), ApprovalAction::Escalate)],
        root,
    );
    let auth = CompiledAuthority::from_passport(&passport, reg).unwrap();
    assert_eq!(auth.approval_rules.len(), 1);

    let mut a = empty_action();
    a.operation_id = 3;
    assert!(auth.approval_rules[0].matches(&a));
}

#[test]
fn compiled_authority_uncompilable_rule_rejects_passport() {
    let (reg, root) = registry_with_tool0();
    let passport = passport_for_approval_test(
        vec![("recipient NOT IN allowlist".into(), ApprovalAction::Escalate)],
        root,
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
    let (reg, root) = registry_with_tool0();
    let passport = passport_for_approval_test(vec![], root);
    let auth = CompiledAuthority::from_passport(&passport, reg).unwrap();
    assert!(auth.approval_rules.is_empty());
}
