//! Section 4: Runtime Passport wire format.
//!
//! JSON, JCS-canonicalized for signing, Ed25519-signed by gateway.
//! Chunk 1 implements typed parse plus structural validation only.
//! Signature verification and JCS canonicalization land in chunk 2.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Section 4 / Section 10 risk class. Wire form is the string `"R0"`..`"R4"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[repr(u8)]
pub enum RiskClass {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
}

impl From<RiskClass> for String {
    fn from(rc: RiskClass) -> Self {
        match rc {
            RiskClass::R0 => "R0",
            RiskClass::R1 => "R1",
            RiskClass::R2 => "R2",
            RiskClass::R3 => "R3",
            RiskClass::R4 => "R4",
        }
        .to_string()
    }
}

impl TryFrom<String> for RiskClass {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "R0" => Ok(RiskClass::R0),
            "R1" => Ok(RiskClass::R1),
            "R2" => Ok(RiskClass::R2),
            "R3" => Ok(RiskClass::R3),
            "R4" => Ok(RiskClass::R4),
            other => Err(format!("unknown risk_class: {other}")),
        }
    }
}

/// Verifier assurance tier (§11.5 / §18). Wire form is `"T1"`..`"T3"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[repr(u8)]
pub enum Tier {
    T1 = 1,
    T2 = 2,
    T3 = 3,
}

impl From<Tier> for String {
    fn from(t: Tier) -> Self {
        match t {
            Tier::T1 => "T1",
            Tier::T2 => "T2",
            Tier::T3 => "T3",
        }
        .to_string()
    }
}

impl TryFrom<String> for Tier {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "T1" => Ok(Tier::T1),
            "T2" => Ok(Tier::T2),
            "T3" => Ok(Tier::T3),
            other => Err(format!("unknown tier: {other}")),
        }
    }
}

/// Section 11.3 event durability mode. Selected per passport at issuance
/// based on risk class. `Strict` (Mode C) is reserved for R4 and returns
/// `STRICT_MODE_REQUIRED` in Prototype 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurabilityMode {
    MemoryBuffered,
    BlockingGroupCommit,
    QueuedGroupCommit,
    Strict,
}

/// Action taken when an approval rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalAction {
    Escalate,
    Deny,
}

/// One approval rule (§4 example schema). Predicate is an opaque string
/// in chunk 1; predicate parsing lands with the compiler in chunk 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRule {
    pub predicate: String,
    pub on_match: ApprovalAction,
}

/// The compiled authority blob inside a Runtime Passport (§4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityBlob {
    pub allowed_tools: Vec<String>,
    pub allowed_operations: Vec<String>,
    pub resource_scopes: Vec<String>,
    pub approval_rules: Vec<ApprovalRule>,
}

/// Budget lease attached to a passport (§4, §4.3 hardening 4). The
/// `sublease_parent` field is reserved for Phase 1.1 sub-lease support;
/// always `None` in Prototype 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLease {
    pub lease_id: String,
    pub max_actions: u64,
    pub max_cost_units: u64,
    pub sublease_parent: Option<String>,
}

/// Section 4 Runtime Passport, typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePassport {
    #[serde(rename = "type")]
    pub kind: String,
    pub version: String,
    pub passport_id: String,
    pub agent_id: String,
    pub principal_id: String,
    pub beneficiary_id: String,
    pub issuer: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_clock_skew_ms: u32,
    pub policy_epoch: u32,
    pub revocation_epoch: u32,
    pub tool_registry_root: String,
    pub delegation_chain_hash: String,
    pub effective_authority_hash: String,
    pub risk_class: RiskClass,
    pub minimum_tier_required: Tier,
    pub tier_attested: Tier,
    pub verifier_instance_id: String,
    pub verifier_build_hash: String,
    pub session_id: String,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub budget_lease: BudgetLease,
    pub authority_blob_encoding: String,
    pub authority_blob: AuthorityBlob,
    pub receipt_stream_id: String,
    pub signature: String,
}

#[derive(Debug, Error)]
pub enum PassportError {
    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid field value: {0}")]
    InvalidFieldValue(String),
    #[error("temporal bounds invalid: expires_at must be strictly after issued_at")]
    TemporalBoundsInvalid,
    #[error("tier mismatch: tier_attested ({attested:?}) below minimum_tier_required ({minimum:?})")]
    TierMismatch { attested: Tier, minimum: Tier },
    #[error("sequence window invalid: sequence_end must be strictly greater than sequence_start")]
    SequenceWindowInvalid,
    #[error("missing signature field")]
    MissingSignature,
    #[error("signature decoding failed: {0}")]
    SignatureDecode(String),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

// -----------------------------------------------------------------------
// Signature verification (chunk 6)
// -----------------------------------------------------------------------
//
// The passport signature is over the JCS-canonical (RFC 8785) form of the
// passport JSON with the `signature` key removed. The verifier MUST
// retain the original JSON string until after signature verification; the
// canonical bytes are computed from THAT string, not by re-serializing
// the typed struct (re-serialization can change field ordering or
// formatting, breaking byte-for-byte agreement with the gateway).

/// Compute the canonical bytes that the gateway signed. Parses the JSON,
/// removes the `signature` key, canonicalizes via JCS, returns the bytes.
pub fn canonical_signed_bytes(json_str: &str) -> Result<Vec<u8>, PassportError> {
    let mut value: serde_json::Value = serde_json::from_str(json_str)?;
    match value.as_object_mut() {
        Some(obj) => {
            obj.remove("signature");
        }
        None => {
            return Err(PassportError::Canonicalization(
                "passport JSON is not an object".into(),
            ));
        }
    }
    serde_jcs::to_vec(&value)
        .map_err(|e| PassportError::Canonicalization(e.to_string()))
}

/// Parse a signature string. Accepts `"ed25519:<hex>"` prefix-form or
/// bare hex. Returns the 64-byte signature.
pub(crate) fn decode_signature(sig: &str) -> Result<[u8; 64], PassportError> {
    let hex = match sig.split_once(':') {
        Some((_, rest)) => rest,
        None => sig,
    };
    if hex.len() != 128 {
        return Err(PassportError::SignatureDecode(format!(
            "expected 128 hex chars (64-byte signature), got {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        let chunk = hex.get(i * 2..i * 2 + 2).ok_or_else(|| {
            PassportError::SignatureDecode("hex slice failed".into())
        })?;
        *byte = u8::from_str_radix(chunk, 16)
            .map_err(|_| PassportError::SignatureDecode(format!("non-hex character in {sig:?}")))?;
    }
    Ok(out)
}

impl RuntimePassport {
    /// Verify the passport's Ed25519 signature against the canonical
    /// form of the supplied JSON string.
    ///
    /// `json_str` MUST be the original JSON received from the gateway,
    /// not a re-serialization of the parsed struct.
    /// `gateway_public_key` is the issuing gateway's Ed25519 verifying
    /// key (caller-supplied in Prototype 1; gateway discovery via
    /// `.well-known` is Phase 2).
    pub fn verify_signature(
        &self,
        json_str: &str,
        gateway_public_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), PassportError> {
        if self.signature.trim().is_empty() {
            return Err(PassportError::MissingSignature);
        }
        let sig_bytes = decode_signature(&self.signature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let canonical = canonical_signed_bytes(json_str)?;
        gateway_public_key
            .verify_strict(&canonical, &sig)
            .map_err(|_| PassportError::SignatureInvalid)
    }

    /// Parse JSON, validate structure, AND verify the Ed25519 signature
    /// against the supplied gateway public key. One-shot wrapper around
    /// `from_json` + `verify_signature`.
    pub fn from_json_and_verify(
        json_str: &str,
        gateway_public_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self, PassportError> {
        // Reject obviously-missing signature BEFORE running expensive
        // structural validation so the diagnostic is precise.
        let preview: serde_json::Value = serde_json::from_str(json_str)?;
        if preview
            .as_object()
            .map(|o| !o.contains_key("signature"))
            .unwrap_or(true)
        {
            return Err(PassportError::MissingSignature);
        }
        let passport = Self::from_json(json_str)?;
        passport.verify_signature(json_str, gateway_public_key)?;
        Ok(passport)
    }

    /// Parse a passport from JSON and run the structural checks of §4.3
    /// hardenings 2 and 3. Does NOT verify the signature; that's
    /// [`Self::verify_signature`] / [`Self::from_json_and_verify`].
    pub fn from_json(s: &str) -> Result<Self, PassportError> {
        let p: Self = serde_json::from_str(s)?;
        if p.expires_at <= p.issued_at {
            return Err(PassportError::TemporalBoundsInvalid);
        }
        if (p.tier_attested as u8) < (p.minimum_tier_required as u8) {
            return Err(PassportError::TierMismatch {
                attested: p.tier_attested,
                minimum: p.minimum_tier_required,
            });
        }
        if p.sequence_end <= p.sequence_start {
            return Err(PassportError::SequenceWindowInvalid);
        }
        Ok(p)
    }
}
