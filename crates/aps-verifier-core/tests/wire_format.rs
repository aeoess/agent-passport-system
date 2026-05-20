//! Wire-format round-trip and structural-validation tests, spec §4-§7.

use aps_verifier_core::{
    ApprovalAction, ApprovalRule, ActionDescriptor, ActionError, AuthorityBlob, BudgetLease,
    Decision, DecisionType, PassportError, ReasonCode, RiskClass, RuntimePassport, Tier,
    ACTION_DESCRIPTOR_SIZE, DECISION_SIZE,
};

#[allow(clippy::too_many_arguments)]
fn passport_json(
    issued: &str,
    expires: &str,
    attested: &str,
    minimum: &str,
    seq_start: u64,
    seq_end: u64,
) -> String {
    format!(
        r#"{{
  "type": "aps.runtime_passport",
  "version": "0.1",
  "passport_id": "rp_01HX0EXAMPLE000000000000000",
  "agent_id": "ag_01HX0AGENT000000000000000000",
  "principal_id": "pr_01HX0PRINCIPAL00000000000000",
  "beneficiary_id": "bn_01HX0BEN00000000000000000000",
  "issuer": "https://gateway.example.test",
  "issued_at": "{issued}",
  "expires_at": "{expires}",
  "max_clock_skew_ms": 1000,
  "policy_epoch": 42,
  "revocation_epoch": 1842,
  "tool_registry_root": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
  "delegation_chain_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "effective_authority_hash": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
  "risk_class": "R2",
  "minimum_tier_required": "{minimum}",
  "tier_attested": "{attested}",
  "verifier_instance_id": "vi_01HX0VI00000000000000000000",
  "verifier_build_hash": "blake3:1111111111111111111111111111111111111111111111111111111111111111",
  "session_id": "sn_01HX0SESS00000000000000000000",
  "sequence_start": {seq_start},
  "sequence_end": {seq_end},
  "budget_lease": {{
    "lease_id": "bl_01HX0LEASE0000000000000000000",
    "max_actions": 1000,
    "max_cost_units": 50000,
    "sublease_parent": null
  }},
  "authority_blob_encoding": "application/aps-authority+json",
  "authority_blob": {{
    "allowed_tools": ["blake3:abcd000000000000000000000000000000000000000000000000000000000000"],
    "allowed_operations": ["read", "external_send"],
    "resource_scopes": ["customer/*", "invoice/vendor/acme/*"],
    "approval_rules": [
      {{"predicate": "operation == external_send AND recipient NOT IN allowlist", "on_match": "escalate"}}
    ]
  }},
  "receipt_stream_id": "rs_01HX0RS00000000000000000000",
  "signature": "ed25519:{sig}"
}}"#,
        sig = "0".repeat(128)
    )
}

fn valid_passport_json() -> String {
    passport_json(
        "2026-05-19T22:38:56.000Z",
        "2026-05-19T22:39:56.000Z",
        "T2",
        "T2",
        1000,
        2000,
    )
}

// -----------------------------------------------------------------------
// passport
// -----------------------------------------------------------------------

#[test]
fn passport_round_trips() {
    let json = valid_passport_json();
    let p1 = RuntimePassport::from_json(&json).expect("first parse");

    let reserialized = serde_json::to_string(&p1).expect("serialize");
    let p2 = RuntimePassport::from_json(&reserialized).expect("second parse");

    assert_eq!(p1, p2);
    assert_eq!(p1.risk_class, RiskClass::R2);
    assert_eq!(p1.tier_attested, Tier::T2);
    assert_eq!(p1.minimum_tier_required, Tier::T2);
    assert_eq!(p1.sequence_start, 1000);
    assert_eq!(p1.sequence_end, 2000);
    assert_eq!(p1.authority_blob.approval_rules.len(), 1);
    assert_eq!(
        p1.authority_blob.approval_rules[0].on_match,
        ApprovalAction::Escalate
    );
}

#[test]
fn passport_rejects_expired_before_issued() {
    let json = passport_json(
        "2026-05-19T22:40:00.000Z",
        "2026-05-19T22:38:00.000Z",
        "T2",
        "T2",
        1000,
        2000,
    );
    match RuntimePassport::from_json(&json) {
        Err(PassportError::TemporalBoundsInvalid) => {}
        other => panic!("expected TemporalBoundsInvalid, got {other:?}"),
    }
}

#[test]
fn passport_rejects_tier_mismatch() {
    let json = passport_json(
        "2026-05-19T22:38:56.000Z",
        "2026-05-19T22:39:56.000Z",
        "T1",
        "T2",
        1000,
        2000,
    );
    match RuntimePassport::from_json(&json) {
        Err(PassportError::TierMismatch { attested, minimum }) => {
            assert_eq!(attested, Tier::T1);
            assert_eq!(minimum, Tier::T2);
        }
        other => panic!("expected TierMismatch, got {other:?}"),
    }
}

#[test]
fn passport_rejects_sequence_window_invalid() {
    let json = passport_json(
        "2026-05-19T22:38:56.000Z",
        "2026-05-19T22:39:56.000Z",
        "T2",
        "T2",
        2000,
        2000,
    );
    match RuntimePassport::from_json(&json) {
        Err(PassportError::SequenceWindowInvalid) => {}
        other => panic!("expected SequenceWindowInvalid, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// action descriptor
// -----------------------------------------------------------------------

#[test]
fn action_descriptor_size_constant_is_204() {
    assert_eq!(ACTION_DESCRIPTOR_SIZE, 204);
}

fn distinctive_action() -> ActionDescriptor {
    ActionDescriptor {
        version: 1,
        reserved: [0xAA, 0xBB, 0xCC],
        passport_id_hash: [0x11; 32],
        tool_descriptor_hash: [0x22; 32],
        local_tool_id: 0xDEAD_BEEF,
        operation_id: 0xCAFE,
        resource_type: 0xBABE,
        risk_class: 2,
        resource_path_depth: 3,
        reserved2: [0x55, 0x66],
        cost_units: 0x1234_5678,
        sequence_id: 0x0123_4567_89AB_CDEF,
        nonce: [0x77; 16],
        resource_path_hashes: [
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
            0x3132_3334_3536_3738,
            0x4142_4344_4546_4748,
            0x5152_5354_5556_5758,
            0x6162_6364_6566_6768,
            0x7172_7374_7576_7778,
        ],
        action_hash: [0x99; 32],
    }
}

#[test]
fn action_descriptor_round_trips() {
    let a1 = distinctive_action();
    let bytes = a1.to_bytes();
    assert_eq!(bytes.len(), ACTION_DESCRIPTOR_SIZE);
    let a2 = ActionDescriptor::from_bytes(&bytes).expect("from_bytes");
    assert_eq!(a1, a2);
}

#[test]
fn action_descriptor_le_encoding_stable() {
    // sequence_id sits at byte offset 84..92 per the §5 field order.
    let a = distinctive_action();
    let bytes = a.to_bytes();
    assert_eq!(
        &bytes[84..92],
        &[0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]
    );
}

#[test]
fn action_descriptor_rejects_invalid_version() {
    let mut bytes = distinctive_action().to_bytes();
    bytes[0] = 2;
    assert_eq!(
        ActionDescriptor::from_bytes(&bytes),
        Err(ActionError::InvalidVersion(2))
    );
}

#[test]
fn action_descriptor_rejects_invalid_risk_class() {
    let mut bytes = distinctive_action().to_bytes();
    bytes[76] = 5; // risk_class > 4
    assert_eq!(
        ActionDescriptor::from_bytes(&bytes),
        Err(ActionError::InvalidRiskClass(5))
    );
}

#[test]
fn action_descriptor_rejects_invalid_path_depth() {
    let mut bytes = distinctive_action().to_bytes();
    bytes[77] = 9; // resource_path_depth > 8
    assert_eq!(
        ActionDescriptor::from_bytes(&bytes),
        Err(ActionError::InvalidPathDepth(9))
    );
}

// -----------------------------------------------------------------------
// decision
// -----------------------------------------------------------------------

#[test]
fn decision_size_constant_is_64() {
    assert_eq!(DECISION_SIZE, 64);
}

#[test]
fn decision_round_trips() {
    let d1 = Decision {
        decision_type: DecisionType::Deny,
        reason_code: ReasonCode::ToolNotAllowed,
        reserved: [0; 6],
        sequence_id: 0xFEED_FACE_DEAD_BEEF,
        decision_id: [0xAB; 16],
        event_mac: [0xCD; 32],
    };
    let bytes = d1.to_bytes();
    assert_eq!(bytes.len(), DECISION_SIZE);
    let d2 = Decision::from_bytes(&bytes).expect("from_bytes");
    assert_eq!(d1, d2);
}

#[test]
fn reason_code_covers_20_variants() {
    let mapping: &[(ReasonCode, u8)] = &[
        (ReasonCode::Ok, 0x00),
        (ReasonCode::ExpiredPassport, 0x01),
        (ReasonCode::NotYetValid, 0x02),
        (ReasonCode::StaleRevocationEpoch, 0x03),
        (ReasonCode::RegistryVersionMismatch, 0x04),
        (ReasonCode::ToolNotAllowed, 0x05),
        (ReasonCode::OperationNotAllowed, 0x06),
        (ReasonCode::ResourceOutOfScope, 0x07),
        (ReasonCode::RiskTierTooLow, 0x08),
        (ReasonCode::RiskClassExceeded, 0x09),
        (ReasonCode::BudgetExceeded, 0x0A),
        (ReasonCode::SequenceReplay, 0x0B),
        (ReasonCode::NonceReplay, 0x0C),
        (ReasonCode::ApprovalRequired, 0x0D),
        (ReasonCode::DeniedByRule, 0x0E),
        (ReasonCode::ActionHashInvalid, 0x0F),
        (ReasonCode::VerifierInstanceMismatch, 0x10),
        (ReasonCode::ClockAnchorStale, 0x11),
        (ReasonCode::SequenceRecoveryInvalid, 0x12),
        (ReasonCode::StrictModeRequired, 0x13),
    ];
    assert_eq!(mapping.len(), 20);
    for (rc, expected) in mapping {
        assert_eq!(*rc as u8, *expected, "discriminant mismatch for {rc:?}");
    }
}

// -----------------------------------------------------------------------
// silence "imported but unused" warnings for types we re-export but don't
// directly call in this test file; using them in a no-op assertion keeps
// the imports honest under -D warnings.
// -----------------------------------------------------------------------

#[test]
fn types_are_publicly_re_exported() {
    let blob = AuthorityBlob {
        allowed_tools: vec![],
        allowed_operations: vec![],
        resource_scopes: vec![],
        approval_rules: vec![ApprovalRule {
            predicate: "x".into(),
            on_match: ApprovalAction::Deny,
        }],
    };
    let lease = BudgetLease {
        lease_id: "bl_x".into(),
        max_actions: 1,
        max_cost_units: 1,
        sublease_parent: None,
    };
    assert_eq!(blob.approval_rules.len(), 1);
    assert!(lease.sublease_parent.is_none());
}
