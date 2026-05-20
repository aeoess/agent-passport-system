//! Chunk-6 tests for the crypto layer: passport signature verification,
//! action_hash computation, event_mac, ClockAnchor signature.

mod common;

use ed25519_dalek::{Signer, SigningKey};

use aps_verifier_core::{
    canonical_signed_bytes, ApprovalAction, ClockAnchor, ClockError, Decision, DecisionType,
    PassportError, ReasonCode, RuntimePassport,
};

use common::{
    empty_action_descriptor, hex_encode_64, test_gateway_keypair, test_receipt_stream_key,
    PassportBuilder,
};

const TOOL_HEX_0: &str = "abcd000000000000000000000000000000000000000000000000000000000000";

fn tool_hash() -> [u8; 32] {
    let hex = TOOL_HEX_0;
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn standard_signed_json() -> (String, SigningKey, ed25519_dalek::VerifyingKey) {
    let (signing, verifying) = test_gateway_keypair();
    let json = PassportBuilder::new()
        .with_root([0u8; 32])
        .with_allowed_tools(vec![tool_hash()])
        .with_allowed_operations(vec!["read", "external_send"])
        .with_resource_scopes(vec!["customer/*"])
        .build_signed_json(&signing);
    (json, signing, verifying)
}

// -----------------------------------------------------------------------
// Passport signature verification
// -----------------------------------------------------------------------

#[test]
fn passport_signature_round_trip() {
    let (json, _signing, verifying) = standard_signed_json();
    let passport = RuntimePassport::from_json_and_verify(&json, &verifying)
        .expect("verification should succeed");
    assert_eq!(passport.passport_id, "rp_01HX0EXAMPLE000000000000000");
}

#[test]
fn passport_signature_wrong_key_fails() {
    let (json, _signing, _verifying) = standard_signed_json();
    let other = SigningKey::from_bytes(&[0x11; 32]).verifying_key();
    match RuntimePassport::from_json_and_verify(&json, &other) {
        Err(PassportError::SignatureInvalid) => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn passport_signature_tampered_field_fails() {
    let (json, _signing, verifying) = standard_signed_json();
    // Change a single character in the expires_at value. The minute
    // jumps from 39 to 49; both are still valid RFC 3339 and parse fine,
    // but the canonical bytes differ → signature invalid.
    let tampered = json.replacen("22:39:56.000Z", "22:49:56.000Z", 1);
    assert_ne!(tampered, json);
    match RuntimePassport::from_json_and_verify(&tampered, &verifying) {
        Err(PassportError::SignatureInvalid) => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn passport_signature_tampered_signature_fails() {
    let (json, _signing, verifying) = standard_signed_json();
    // Find the signature hex and flip the LAST hex character before the
    // closing quote. The "ed25519:" prefix sits at a known location.
    let needle = "\"ed25519:";
    let start = json.find(needle).unwrap() + needle.len();
    // Locate the closing quote of the signature value.
    let end = json[start..].find('"').unwrap() + start;
    let mut tampered = String::with_capacity(json.len());
    tampered.push_str(&json[..end - 1]);
    let flip = if json.as_bytes()[end - 1] == b'0' { '1' } else { '0' };
    tampered.push(flip);
    tampered.push_str(&json[end..]);
    match RuntimePassport::from_json_and_verify(&tampered, &verifying) {
        Err(PassportError::SignatureInvalid) => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn passport_signature_missing_field_fails() {
    let (json, _signing, verifying) = standard_signed_json();
    // Remove the signature field from the JSON.
    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    value.as_object_mut().unwrap().remove("signature");
    let no_sig = serde_json::to_string(&value).unwrap();
    match RuntimePassport::from_json_and_verify(&no_sig, &verifying) {
        Err(PassportError::MissingSignature) => {}
        other => panic!("expected MissingSignature, got {other:?}"),
    }
}

#[test]
fn passport_signature_malformed_decode_fails() {
    let (json, _signing, verifying) = standard_signed_json();
    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    value.as_object_mut().unwrap().insert(
        "signature".into(),
        serde_json::Value::String("ed25519:notHex".into()),
    );
    let bad_sig = serde_json::to_string(&value).unwrap();
    match RuntimePassport::from_json_and_verify(&bad_sig, &verifying) {
        Err(PassportError::SignatureDecode(_)) => {}
        other => panic!("expected SignatureDecode, got {other:?}"),
    }
}

#[test]
fn passport_canonical_bytes_deterministic() {
    let (json, _signing, _verifying) = standard_signed_json();
    let a = canonical_signed_bytes(&json).unwrap();
    let b = canonical_signed_bytes(&json).unwrap();
    assert_eq!(a, b);
}

#[test]
fn passport_canonical_bytes_unaffected_by_input_whitespace() {
    let (json_pretty, _signing, _verifying) = standard_signed_json();
    // Re-serialize without indentation.
    let value: serde_json::Value = serde_json::from_str(&json_pretty).unwrap();
    let compact = serde_json::to_string(&value).unwrap();
    assert_ne!(compact, json_pretty, "compact must differ from pretty");
    let a = canonical_signed_bytes(&json_pretty).unwrap();
    let b = canonical_signed_bytes(&compact).unwrap();
    assert_eq!(a, b, "JCS canonical form must be invariant under whitespace/order");
}

// -----------------------------------------------------------------------
// action_hash
// -----------------------------------------------------------------------

fn populated_action() -> aps_verifier_core::ActionDescriptor {
    let mut a = empty_action_descriptor();
    a.passport_id_hash = [0x11; 32];
    a.tool_descriptor_hash = [0x22; 32];
    a.local_tool_id = 0xDEAD_BEEF;
    a.operation_id = 3;
    a.resource_type = 0xABCD;
    a.risk_class = 2;
    a.resource_path_depth = 2;
    a.cost_units = 12345;
    a.sequence_id = 1000;
    a.nonce = [0x44; 16];
    a.resource_path_hashes = [1, 2, 3, 4, 5, 6, 7, 8];
    a
}

#[test]
fn action_hash_compute_deterministic() {
    let a = populated_action();
    assert_eq!(a.compute_action_hash(), a.compute_action_hash());
}

#[test]
fn action_hash_changes_on_field_change() {
    let mut a = populated_action();
    let h1 = a.compute_action_hash();
    a.sequence_id += 1;
    let h2 = a.compute_action_hash();
    assert_ne!(h1, h2);
}

#[test]
fn action_hash_finalize_sets_field() {
    let mut a = populated_action();
    a.action_hash = [0u8; 32];
    a.finalize();
    assert_eq!(a.action_hash, a.compute_action_hash());
}

#[test]
fn action_hash_verify_after_finalize() {
    let mut a = populated_action();
    a.finalize();
    assert!(a.verify_action_hash());
}

#[test]
fn action_hash_verify_detects_field_tamper() {
    let mut a = populated_action();
    a.finalize();
    a.sequence_id = a.sequence_id.wrapping_add(1);
    assert!(!a.verify_action_hash());
}

#[test]
fn action_hash_verify_detects_hash_tamper() {
    let mut a = populated_action();
    a.finalize();
    a.action_hash[0] ^= 0xFF;
    assert!(!a.verify_action_hash());
}

// -----------------------------------------------------------------------
// event_mac
// -----------------------------------------------------------------------

fn populated_decision() -> Decision {
    Decision {
        decision_type: DecisionType::Allow,
        reason_code: ReasonCode::Ok,
        reserved: [0; 6],
        sequence_id: 1000,
        decision_id: [0x55; 16],
        event_mac: [0; 32],
    }
}

#[test]
fn event_mac_compute_deterministic() {
    let d = populated_decision();
    let key = test_receipt_stream_key();
    let pid = [0x11; 32];
    let ah = [0x22; 32];
    let ts = 1_700_000_000_000_000_000u64;
    assert_eq!(
        d.compute_event_mac(&key, &pid, &ah, ts),
        d.compute_event_mac(&key, &pid, &ah, ts)
    );
}

#[test]
fn event_mac_changes_on_field_change() {
    let d = populated_decision();
    let key = test_receipt_stream_key();
    let pid = [0x11; 32];
    let ts = 1u64;
    let m1 = d.compute_event_mac(&key, &pid, &[0x22; 32], ts);
    let m2 = d.compute_event_mac(&key, &pid, &[0x33; 32], ts);
    assert_ne!(m1, m2);
}

#[test]
fn event_mac_changes_on_key_change() {
    let d = populated_decision();
    let pid = [0x11; 32];
    let ah = [0x22; 32];
    let ts = 1u64;
    let m1 = d.compute_event_mac(&[0x77; 32], &pid, &ah, ts);
    let m2 = d.compute_event_mac(&[0x99; 32], &pid, &ah, ts);
    assert_ne!(m1, m2);
}

#[test]
fn event_mac_finalize_sets_field() {
    let mut d = populated_decision();
    let key = test_receipt_stream_key();
    let pid = [0x11; 32];
    let ah = [0x22; 32];
    let ts = 1u64;
    d.event_mac = [0; 32];
    d.finalize_mac(&key, &pid, &ah, ts);
    assert_eq!(d.event_mac, d.compute_event_mac(&key, &pid, &ah, ts));
}

#[test]
fn event_mac_verify_after_finalize() {
    let mut d = populated_decision();
    let key = test_receipt_stream_key();
    let pid = [0x11; 32];
    let ah = [0x22; 32];
    let ts = 1u64;
    d.finalize_mac(&key, &pid, &ah, ts);
    assert!(d.verify_event_mac(&key, &pid, &ah, ts));
}

#[test]
fn event_mac_verify_detects_field_tamper() {
    let mut d = populated_decision();
    let key = test_receipt_stream_key();
    let pid = [0x11; 32];
    let ah = [0x22; 32];
    let ts = 1u64;
    d.finalize_mac(&key, &pid, &ah, ts);
    d.sequence_id = d.sequence_id.wrapping_add(1);
    assert!(!d.verify_event_mac(&key, &pid, &ah, ts));
}

// -----------------------------------------------------------------------
// ClockAnchor signature
// -----------------------------------------------------------------------

fn make_signed_anchor(timestamp_ns: u64, signing: &SigningKey) -> ClockAnchor {
    let sig = signing.sign(&timestamp_ns.to_le_bytes());
    ClockAnchor {
        timestamp_ns,
        signature: sig.to_bytes().to_vec(),
    }
}

#[test]
fn clock_anchor_signature_round_trip() {
    let (signing, verifying) = test_gateway_keypair();
    let anchor = make_signed_anchor(1_700_000_000_000_000_000u64, &signing);
    anchor
        .verify_signature(&verifying)
        .expect("matching key must verify");
}

#[test]
fn clock_anchor_signature_wrong_key_fails() {
    let (signing, _verifying) = test_gateway_keypair();
    let other = SigningKey::from_bytes(&[0x11; 32]).verifying_key();
    let anchor = make_signed_anchor(1u64, &signing);
    match anchor.verify_signature(&other) {
        Err(ClockError::SignatureInvalid) => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn clock_anchor_signature_tampered_timestamp_fails() {
    let (signing, verifying) = test_gateway_keypair();
    let mut anchor = make_signed_anchor(1u64, &signing);
    anchor.timestamp_ns = 2u64;
    match anchor.verify_signature(&verifying) {
        Err(ClockError::SignatureInvalid) => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Sanity: ApprovalAction import resolves (chunk 6 hasn't removed it)
// -----------------------------------------------------------------------

#[test]
fn approval_action_still_exported() {
    let _ = ApprovalAction::Escalate;
    let _ = hex_encode_64(&[0u8; 64]);
}
