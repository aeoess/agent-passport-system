//! Shared test helpers consumed by the integration tests via
//! `mod common;`. Each test crate is a separate compilation unit; the
//! directory form (`common/mod.rs`) keeps cargo from picking this up
//! as its own test binary.
//!
//! `#![allow(dead_code)]` is applied at module level because each
//! integration test crate compiles this module privately, and a helper
//! used by some test crates but not others would otherwise warn as
//! dead per-crate. This is the standard Rust idiom for cross-test-
//! crate shared helpers; it does not silence genuine dead code in
//! production (`src/`) which keeps the default lint posture.
#![allow(dead_code)]
//!
//! Helpers parked here cover surfaces that recurred across chunks 1-5:
//!
//! - hex encoding / decoding for 32-byte hashes,
//! - a minimal zero-filled [`ActionDescriptor`] for predicate / matcher
//!   tests,
//! - [`PassportBuilder`], a builder for the spec §4 Runtime Passport
//!   JSON used by every test that exercises
//!   [`CompiledAuthority::from_passport`].
//!
//! Production code is not imported beyond the public crate surface;
//! these helpers exercise only `aps_verifier_core::*`.

use std::sync::Mutex;

use aps_verifier_core::{
    canonical_signed_bytes, hash_path_component, ActionDescriptor, ApprovalAction, Decision,
    EmitOutcome, GroupCommitConfig, ManualClock, ReceiptError, ReceiptSink, Tier, VerifierContext,
};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

// -----------------------------------------------------------------------
// Hex helpers
// -----------------------------------------------------------------------

/// Lowercase hex encoding of a 32-byte hash (64 chars, no prefix).
pub fn hex_encode(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Lowercase hex encoding of a 64-byte Ed25519 signature (128 chars).
pub fn hex_encode_64(bytes: &[u8; 64]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(128);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Deterministic Ed25519 test keypair. Fixed seed for reproducible
/// test signatures. NEVER use in production.
pub fn test_gateway_keypair() -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::from_bytes(&[0x42; 32]);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// Deterministic 32-byte receipt-stream key for MAC tests.
pub fn test_receipt_stream_key() -> [u8; 32] {
    [0x77; 32]
}

// -----------------------------------------------------------------------
// Verifier + action builders (chunk 7)
// -----------------------------------------------------------------------

/// Unix-nanos for the `PassportBuilder` default `issued_at`. Computed
/// via chrono so the constant stays aligned with the JSON string the
/// builder embeds.
pub fn default_issued_at_ns() -> u64 {
    use chrono::{DateTime, Utc};
    let dt: DateTime<Utc> = "2026-05-19T22:38:56.000Z".parse().unwrap();
    u64::try_from(dt.timestamp_nanos_opt().unwrap()).unwrap()
}

pub fn default_expires_at_ns() -> u64 {
    use chrono::{DateTime, Utc};
    let dt: DateTime<Utc> = "2026-05-19T22:39:56.000Z".parse().unwrap();
    u64::try_from(dt.timestamp_nanos_opt().unwrap()).unwrap()
}

/// Default test clock: 5s into the 60s validity window.
pub fn default_clock_ns() -> u64 {
    default_issued_at_ns() + 5_000_000_000
}

/// BLAKE3 hash of the default `PassportBuilder` `verifier_instance_id`.
pub fn default_verifier_instance_id_hash() -> [u8; 32] {
    *blake3::hash("vi_01HX0VI00000000000000000000".as_bytes()).as_bytes()
}

/// BLAKE3 hash of the default `PassportBuilder` `passport_id`.
pub fn default_passport_id_hash() -> [u8; 32] {
    *blake3::hash("rp_01HX0EXAMPLE000000000000000".as_bytes()).as_bytes()
}

/// Test-side bundle of verifier state. `context()` produces a
/// `VerifierContext` that aps_check accepts.
pub struct TestVerifier {
    pub clock: ManualClock,
    pub instance_id_hash: [u8; 32],
    pub attested_tier: Tier,
    pub revocation_epoch: u32,
}

impl Default for TestVerifier {
    fn default() -> Self {
        TestVerifier {
            clock: ManualClock::new(default_clock_ns()),
            instance_id_hash: default_verifier_instance_id_hash(),
            attested_tier: Tier::T2,
            revocation_epoch: 1842,
        }
    }
}

impl TestVerifier {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_tier(mut self, tier: Tier) -> Self {
        self.attested_tier = tier;
        self
    }
    pub fn with_clock_ns(self, ns: u64) -> Self {
        self.clock.set(ns);
        self
    }
    pub fn with_instance_hash(mut self, hash: [u8; 32]) -> Self {
        self.instance_id_hash = hash;
        self
    }
    pub fn with_revocation_epoch(mut self, e: u32) -> Self {
        self.revocation_epoch = e;
        self
    }
    pub fn context(&self) -> VerifierContext<'_> {
        VerifierContext::new(
            &self.clock,
            self.instance_id_hash,
            self.attested_tier,
            self.revocation_epoch,
        )
    }
}

/// Builder for an [`ActionDescriptor`] that, paired with the default
/// happy-path authority, passes aps_check. Mutate one field for deny
/// tests.
pub struct ActionBuilder {
    descriptor: ActionDescriptor,
}

impl Default for ActionBuilder {
    fn default() -> Self {
        let mut d = empty_action_descriptor();
        d.passport_id_hash = default_passport_id_hash();
        // tool_descriptor_hash, local_tool_id, operation_id default to 0;
        // set explicitly with `with_*` methods per test.
        d.operation_id = 0; // "read"
        d.risk_class = 2; // R2
        d.cost_units = 1;
        d.resource_path_depth = 1;
        d.resource_path_hashes[0] = hash_path_component("customer");
        d.sequence_id = 1000;
        d.nonce = [0x55; 16];
        ActionBuilder { descriptor: d }
    }
}

impl ActionBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_sequence_id(mut self, id: u64) -> Self {
        self.descriptor.sequence_id = id;
        self
    }
    pub fn with_risk_class(mut self, r: u8) -> Self {
        self.descriptor.risk_class = r;
        self
    }
    pub fn with_operation_id(mut self, op: u16) -> Self {
        self.descriptor.operation_id = op;
        self
    }
    pub fn with_local_tool_id(mut self, id: u32) -> Self {
        self.descriptor.local_tool_id = id;
        self
    }
    pub fn with_tool_descriptor_hash(mut self, hash: [u8; 32]) -> Self {
        self.descriptor.tool_descriptor_hash = hash;
        self
    }
    pub fn with_passport_id_hash(mut self, hash: [u8; 32]) -> Self {
        self.descriptor.passport_id_hash = hash;
        self
    }
    pub fn with_resource_path(mut self, components: &[&str]) -> Self {
        let depth = components.len().min(8);
        self.descriptor.resource_path_depth = depth as u8;
        self.descriptor.resource_path_hashes = [0u64; 8];
        for (i, c) in components.iter().take(8).enumerate() {
            self.descriptor.resource_path_hashes[i] = hash_path_component(c);
        }
        self
    }
    pub fn with_cost_units(mut self, c: u32) -> Self {
        self.descriptor.cost_units = c;
        self
    }
    /// Finalize the action_hash and return the descriptor. Tests that
    /// want to deliberately tamper after build should do so AFTER this
    /// returns.
    pub fn build(mut self) -> ActionDescriptor {
        self.descriptor.finalize();
        self.descriptor
    }
}

// -----------------------------------------------------------------------
// Receipt sinks for tests
// -----------------------------------------------------------------------

/// In-memory `ReceiptSink` that records every decision passed to
/// `emit`. Tests assert on the recorded history.
#[derive(Default)]
pub struct RecordingSink {
    decisions: Mutex<Vec<Decision>>,
}

impl RecordingSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn recorded(&self) -> Vec<Decision> {
        self.decisions.lock().unwrap().clone()
    }
    pub fn count(&self) -> usize {
        self.decisions.lock().unwrap().len()
    }
}

impl ReceiptSink for RecordingSink {
    fn emit(&self, decision: &Decision) -> Result<EmitOutcome, ReceiptError> {
        self.decisions.lock().unwrap().push(decision.clone());
        Ok(EmitOutcome::default())
    }
}

/// Group-commit config tuned for fast tests: 5ms window, 64-event
/// batch size.
pub fn test_commit_config() -> GroupCommitConfig {
    GroupCommitConfig {
        max_batch_size: 64,
        max_batch_window: Duration::from_millis(5),
    }
}

// -----------------------------------------------------------------------
// Recovery test helpers
// -----------------------------------------------------------------------

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use aps_verifier_core::{DecisionType, LogWriter, ReasonCode};

/// Write a log file with `n_entries` valid decisions using the
/// canonical [`LogWriter`]. Sequence IDs start at `start_seq_id` and
/// increment. Returns the tempdir (drop it to clean up) and the path.
pub fn write_test_log(
    n_entries: u64,
    start_seq_id: u64,
    mac_key: &[u8; 32],
) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("receipts.log");
    let mut w = LogWriter::open(&path, *mac_key).expect("LogWriter::open");
    for i in 0..n_entries {
        let d = Decision {
            decision_type: DecisionType::Allow,
            reason_code: ReasonCode::Ok,
            reserved: [0; 6],
            sequence_id: start_seq_id + i,
            decision_id: [0; 16],
            event_mac: [0; 32],
        };
        w.append(&d).expect("LogWriter::append");
    }
    w.flush().expect("LogWriter::flush");
    drop(w);
    (dir, path)
}

/// XOR a single byte at `offset` to corrupt it. Returns the original
/// byte value.
pub fn corrupt_log_byte(path: &std::path::Path, offset: u64) -> std::io::Result<u8> {
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut byte = [0u8; 1];
    f.read_exact(&mut byte)?;
    let original = byte[0];
    byte[0] ^= 0xFF;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&byte)?;
    Ok(original)
}

/// Truncate file to `new_len` bytes.
pub fn truncate_log(path: &std::path::Path, new_len: u64) -> std::io::Result<()> {
    let f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.set_len(new_len)?;
    Ok(())
}

/// Parse a 64-char lowercase hex string into a 32-byte hash. Panics on
/// wrong length or non-hex characters (test-only convenience).
pub fn hash_from_hex(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "hash_from_hex expects 64 hex chars");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .expect("hash_from_hex: non-hex character");
    }
    out
}

// -----------------------------------------------------------------------
// ActionDescriptor stub
// -----------------------------------------------------------------------

/// All-zero [`ActionDescriptor`] with `version = 1`. Tests typically
/// mutate one or two fields and pass to [`aps_check`-driven helpers] /
/// [`CompiledApprovalRule::matches`].
pub fn empty_action_descriptor() -> ActionDescriptor {
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

// -----------------------------------------------------------------------
// PassportBuilder
// -----------------------------------------------------------------------

/// Builder for a spec §4 Runtime Passport JSON string. Defaults match
/// the chunk-5 happy-path fixture (R2/T2/T2, customer/*, single
/// approval rule). Override the fields each test cares about; the rest
/// stay at defaults.
///
/// Output is `String` (not `RuntimePassport`); callers pass it through
/// [`RuntimePassport::from_json`] so the parse step itself is still
/// exercised in every test.
#[derive(Debug, Clone)]
pub struct PassportBuilder {
    type_field: String,
    version: String,
    passport_id: String,
    agent_id: String,
    principal_id: String,
    beneficiary_id: String,
    issuer: String,
    issued_at: String,
    expires_at: String,
    max_clock_skew_ms: u32,
    policy_epoch: u32,
    revocation_epoch: u32,
    tool_registry_root: String,
    delegation_chain_hash: String,
    effective_authority_hash: String,
    risk_class: String,
    minimum_tier_required: String,
    tier_attested: String,
    verifier_instance_id: String,
    verifier_build_hash: String,
    session_id: String,
    sequence_start: u64,
    sequence_end: u64,
    budget_lease_id: String,
    budget_max_actions: u64,
    budget_max_cost_units: u64,
    sublease_parent: Option<String>,
    authority_blob_encoding: String,
    allowed_tools: Vec<String>,       // already in "blake3:<hex>" form
    allowed_operations: Vec<String>,
    resource_scopes: Vec<String>,
    approval_rules: Vec<(String, ApprovalAction)>,
    receipt_stream_id: String,
    signature: String,
}

impl Default for PassportBuilder {
    fn default() -> Self {
        PassportBuilder {
            type_field: "aps.runtime_passport".into(),
            version: "0.1".into(),
            passport_id: "rp_01HX0EXAMPLE000000000000000".into(),
            agent_id: "ag_01HX0AGENT000000000000000000".into(),
            principal_id: "pr_01HX0PRINCIPAL00000000000000".into(),
            beneficiary_id: "bn_01HX0BEN00000000000000000000".into(),
            issuer: "https://gateway.example.test".into(),
            issued_at: "2026-05-19T22:38:56.000Z".into(),
            expires_at: "2026-05-19T22:39:56.000Z".into(),
            max_clock_skew_ms: 1000,
            policy_epoch: 42,
            revocation_epoch: 1842,
            tool_registry_root: format!("blake3:{}", "0".repeat(64)),
            delegation_chain_hash: format!("sha256:{}", "0".repeat(64)),
            effective_authority_hash: format!("blake3:{}", "0".repeat(64)),
            risk_class: "R2".into(),
            minimum_tier_required: "T2".into(),
            tier_attested: "T2".into(),
            verifier_instance_id: "vi_01HX0VI00000000000000000000".into(),
            verifier_build_hash: format!("blake3:{}", "1".repeat(64)),
            session_id: "sn_01HX0SESS00000000000000000000".into(),
            sequence_start: 1000,
            sequence_end: 2000,
            budget_lease_id: "bl_01HX0LEASE0000000000000000000".into(),
            budget_max_actions: 1000,
            budget_max_cost_units: 50_000,
            sublease_parent: None,
            authority_blob_encoding: "application/aps-authority+json".into(),
            allowed_tools: Vec::new(),
            allowed_operations: Vec::new(),
            resource_scopes: Vec::new(),
            approval_rules: Vec::new(),
            receipt_stream_id: "rs_01HX0RS00000000000000000000".into(),
            signature: format!("ed25519:{}", "0".repeat(128)),
        }
    }
}

impl PassportBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(mut self, root: [u8; 32]) -> Self {
        self.tool_registry_root = format!("blake3:{}", hex_encode(&root));
        self
    }

    pub fn with_risk_class(mut self, risk: &str) -> Self {
        self.risk_class = risk.into();
        self
    }

    pub fn with_tier(mut self, minimum: &str, attested: &str) -> Self {
        self.minimum_tier_required = minimum.into();
        self.tier_attested = attested.into();
        self
    }

    pub fn with_temporal(mut self, issued_at: &str, expires_at: &str) -> Self {
        self.issued_at = issued_at.into();
        self.expires_at = expires_at.into();
        self
    }

    pub fn with_sequence_window(mut self, start: u64, end: u64) -> Self {
        self.sequence_start = start;
        self.sequence_end = end;
        self
    }

    pub fn with_allowed_tools(mut self, hashes: Vec<[u8; 32]>) -> Self {
        self.allowed_tools = hashes
            .iter()
            .map(|h| format!("blake3:{}", hex_encode(h)))
            .collect();
        self
    }

    pub fn with_allowed_operations(mut self, ops: Vec<&str>) -> Self {
        self.allowed_operations = ops.into_iter().map(String::from).collect();
        self
    }

    pub fn with_resource_scopes(mut self, scopes: Vec<&str>) -> Self {
        self.resource_scopes = scopes.into_iter().map(String::from).collect();
        self
    }

    pub fn with_approval_rules(
        mut self,
        rules: Vec<(String, ApprovalAction)>,
    ) -> Self {
        self.approval_rules = rules;
        self
    }

    /// Build the unsigned JSON, canonicalize via JCS, sign with the
    /// supplied key, reinsert the signature in `"ed25519:<hex>"` form,
    /// and return the final JSON. Simulates the gateway-side flow.
    pub fn build_signed_json(self, signing_key: &SigningKey) -> String {
        let unsigned_json = self.build_json();
        let canonical = canonical_signed_bytes(&unsigned_json)
            .expect("canonical_signed_bytes on builder output");
        let sig = signing_key.sign(&canonical);
        let sig_str = format!("ed25519:{}", hex_encode_64(&sig.to_bytes()));
        let mut value: serde_json::Value =
            serde_json::from_str(&unsigned_json).expect("re-parse unsigned JSON");
        if let Some(obj) = value.as_object_mut() {
            obj.insert("signature".into(), serde_json::Value::String(sig_str));
        }
        serde_json::to_string_pretty(&value).expect("re-serialize signed JSON")
    }

    pub fn build_json(self) -> String {
        let allowed_tools_block = self
            .allowed_tools
            .iter()
            .map(|s| serde_json::to_string(s).unwrap())
            .collect::<Vec<_>>()
            .join(",");
        let allowed_ops_block = self
            .allowed_operations
            .iter()
            .map(|s| serde_json::to_string(s).unwrap())
            .collect::<Vec<_>>()
            .join(",");
        let scopes_block = self
            .resource_scopes
            .iter()
            .map(|s| serde_json::to_string(s).unwrap())
            .collect::<Vec<_>>()
            .join(",");
        let approval_block = self
            .approval_rules
            .iter()
            .map(|(predicate, action)| {
                let pred = serde_json::to_string(predicate).unwrap();
                let act = match action {
                    ApprovalAction::Escalate => "\"escalate\"",
                    ApprovalAction::Deny => "\"deny\"",
                };
                format!("{{\"predicate\": {pred}, \"on_match\": {act}}}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let sublease_parent_json = match &self.sublease_parent {
            None => "null".to_string(),
            Some(s) => serde_json::to_string(s).unwrap(),
        };
        format!(
            r#"{{
  "type": "{type_field}",
  "version": "{version}",
  "passport_id": "{passport_id}",
  "agent_id": "{agent_id}",
  "principal_id": "{principal_id}",
  "beneficiary_id": "{beneficiary_id}",
  "issuer": "{issuer}",
  "issued_at": "{issued_at}",
  "expires_at": "{expires_at}",
  "max_clock_skew_ms": {max_clock_skew_ms},
  "policy_epoch": {policy_epoch},
  "revocation_epoch": {revocation_epoch},
  "tool_registry_root": "{tool_registry_root}",
  "delegation_chain_hash": "{delegation_chain_hash}",
  "effective_authority_hash": "{effective_authority_hash}",
  "risk_class": "{risk_class}",
  "minimum_tier_required": "{minimum_tier_required}",
  "tier_attested": "{tier_attested}",
  "verifier_instance_id": "{verifier_instance_id}",
  "verifier_build_hash": "{verifier_build_hash}",
  "session_id": "{session_id}",
  "sequence_start": {sequence_start},
  "sequence_end": {sequence_end},
  "budget_lease": {{
    "lease_id": "{budget_lease_id}",
    "max_actions": {budget_max_actions},
    "max_cost_units": {budget_max_cost_units},
    "sublease_parent": {sublease_parent_json}
  }},
  "authority_blob_encoding": "{authority_blob_encoding}",
  "authority_blob": {{
    "allowed_tools": [{allowed_tools_block}],
    "allowed_operations": [{allowed_ops_block}],
    "resource_scopes": [{scopes_block}],
    "approval_rules": [{approval_block}]
  }},
  "receipt_stream_id": "{receipt_stream_id}",
  "signature": "{signature}"
}}"#,
            type_field = self.type_field,
            version = self.version,
            passport_id = self.passport_id,
            agent_id = self.agent_id,
            principal_id = self.principal_id,
            beneficiary_id = self.beneficiary_id,
            issuer = self.issuer,
            issued_at = self.issued_at,
            expires_at = self.expires_at,
            max_clock_skew_ms = self.max_clock_skew_ms,
            policy_epoch = self.policy_epoch,
            revocation_epoch = self.revocation_epoch,
            tool_registry_root = self.tool_registry_root,
            delegation_chain_hash = self.delegation_chain_hash,
            effective_authority_hash = self.effective_authority_hash,
            risk_class = self.risk_class,
            minimum_tier_required = self.minimum_tier_required,
            tier_attested = self.tier_attested,
            verifier_instance_id = self.verifier_instance_id,
            verifier_build_hash = self.verifier_build_hash,
            session_id = self.session_id,
            sequence_start = self.sequence_start,
            sequence_end = self.sequence_end,
            budget_lease_id = self.budget_lease_id,
            budget_max_actions = self.budget_max_actions,
            budget_max_cost_units = self.budget_max_cost_units,
            authority_blob_encoding = self.authority_blob_encoding,
            receipt_stream_id = self.receipt_stream_id,
            signature = self.signature,
        )
    }
}
