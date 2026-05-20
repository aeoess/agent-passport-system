//! Stream B chunk 2: AuthorityHandle + aps_check FFI.
//!
//! Chunk 2 lands the lifecycle pattern (`load_passport` → handle →
//! `check` → `close_authority`) and the end-to-end TS→Rust round
//! trip through `aps_check`. The handle is an opaque
//! `napi::bindgen_prelude::External<AuthorityHandle>` that keeps the
//! `CompiledAuthority` plus its supporting state (clock, sink,
//! verifier identity, attested tier, revocation epoch) alive across
//! TS calls.
//!
//! Chunk-1 `parse_passport_summary` stays as a quick-look API
//! without lifecycle ceremony.
//!
//! Subsequent chunks: TS-side ActionDescriptor builder, ReceiptSink
//! marshalling for real durability modes, full TS API surface
//! (`aps.loadPassport`, `aps.check`, `aps.recoverSession`).

#![deny(clippy::all)]

use std::sync::atomic::Ordering;

use napi::bindgen_prelude::{BigInt, External};
use napi_derive::napi;

use aps_verifier_core::{
    aps_check, ActionDescriptor, CompiledAuthority, DecisionType, NullSink, ReasonCode,
    RuntimePassport, SystemClock, Tier, ToolEntry, ToolRegistry, VerifierContext,
};

// -----------------------------------------------------------------------
// Chunk 1: parse-only API (kept for the simple smoke test)
// -----------------------------------------------------------------------

#[napi(object)]
pub struct PassportSummary {
    pub passport_id: String,
    pub agent_id: String,
    pub principal_id: String,
    pub beneficiary_id: String,
    pub risk_class: String,
    pub minimum_tier_required: String,
    pub tier_attested: String,
    pub sequence_start: i64,
    pub sequence_end: i64,
}

/// Parse a passport JSON string and return a typed summary. Does NOT
/// verify the signature. Use [`load_passport`] for the end-to-end
/// lifecycle including (optional) signature verification.
#[napi]
pub fn parse_passport_summary(json: String) -> napi::Result<PassportSummary> {
    let passport = RuntimePassport::from_json(&json)
        .map_err(|e| napi::Error::from_reason(format!("parse failed: {e}")))?;

    Ok(PassportSummary {
        passport_id: passport.passport_id,
        agent_id: passport.agent_id,
        principal_id: passport.principal_id,
        beneficiary_id: passport.beneficiary_id,
        risk_class: format!("{:?}", passport.risk_class),
        minimum_tier_required: format!("{:?}", passport.minimum_tier_required),
        tier_attested: format!("{:?}", passport.tier_attested),
        sequence_start: i64::try_from(passport.sequence_start)
            .map_err(|e| napi::Error::from_reason(format!("sequence_start overflow: {e}")))?,
        sequence_end: i64::try_from(passport.sequence_end)
            .map_err(|e| napi::Error::from_reason(format!("sequence_end overflow: {e}")))?,
    })
}

// -----------------------------------------------------------------------
// Chunk 2: lifecycle handle + check
// -----------------------------------------------------------------------

#[napi(object)]
pub struct ToolEntryInput {
    /// 64-char hex of the descriptor hash.
    pub descriptor_hash_hex: String,
    pub local_id: u32,
}

/// Opaque handle returned by [`load_passport`] and consumed by
/// [`check`]. Owns the CompiledAuthority and the verifier-side state
/// needed to construct a VerifierContext per call.
///
/// External<AuthorityHandle> drops when JS GCs the wrapper; explicit
/// release via [`close_authority`] is a no-op signaling the intent
/// (force-drop from TS isn't cleanly supported by napi-rs).
pub struct AuthorityHandle {
    authority: CompiledAuthority,
    clock: SystemClock,
    sink: NullSink,
    verifier_instance_id_hash: [u8; 32],
    attested_tier: Tier,
    revocation_epoch: u32,
}

#[napi(object)]
pub struct ActionInput {
    pub version: u8,
    /// 64-char hex.
    pub passport_id_hash_hex: String,
    /// 64-char hex.
    pub tool_descriptor_hash_hex: String,
    pub local_tool_id: u32,
    pub operation_id: u16,
    pub resource_type: u16,
    pub risk_class: u8,
    pub resource_path_depth: u8,
    pub cost_units: u32,
    /// u64 via BigInt (JS Number can't hold above 2^53 safely).
    pub sequence_id: BigInt,
    /// 32-char hex (16 bytes).
    pub nonce_hex: String,
    /// 8 u64 values via BigInt. Pre-hashed resource path components;
    /// see `aps_verifier_core::hash_path_component`.
    pub resource_path_hashes: Vec<BigInt>,
}

#[napi(object)]
pub struct DecisionOutput {
    /// `"Allow"`, `"Deny"`, or `"Escalate"`.
    pub decision_type: String,
    pub reason_code: u8,
    /// Human-readable reason name per spec §7 (e.g. `"OK"`,
    /// `"ACTION_HASH_INVALID"`).
    pub reason_name: String,
    pub sequence_id: BigInt,
    /// 32-char hex (16 bytes).
    pub decision_id_hex: String,
    /// 64-char hex (32 bytes).
    pub event_mac_hex: String,
}

/// Load a passport, build a [`CompiledAuthority`], return an opaque
/// handle.
///
/// - `passport_json`: the passport as received from the gateway.
/// - `tools`: descriptor-hash + local-id pairs the verifier's local
///   registry will be initialized with. The registry root MUST match
///   the passport's `tool_registry_root`, or compile fails.
/// - `gateway_public_key_hex`: optional 64-char hex of the gateway's
///   Ed25519 verifying key. If `null`/`None`, signature verification
///   is SKIPPED — use only for tests / dev. Production callers MUST
///   supply the key.
///
/// Chunk-2 simplifications:
/// - `clock` = `SystemClock` (wall clock; passports must be in-window)
/// - `sink` = `NullSink` (no durable receipt stream wiring yet)
/// - `verifier_instance_id_hash`, `attested_tier`, `revocation_epoch`
///   are taken from the passport itself. Real deployments derive
///   these from independent verifier-side state.
#[napi]
pub fn load_passport(
    passport_json: String,
    tools: Vec<ToolEntryInput>,
    gateway_public_key_hex: Option<String>,
) -> napi::Result<External<AuthorityHandle>> {
    // 1. Parse + (optional) verify the passport JSON.
    let passport = match gateway_public_key_hex {
        Some(hex) => {
            let key_bytes = hex_to_array::<32>(&hex)
                .map_err(|e| napi::Error::from_reason(format!("public_key_hex: {e}")))?;
            let verifying_key = ed25519_dalek_verifying_key(&key_bytes)?;
            RuntimePassport::from_json_and_verify(&passport_json, &verifying_key)
                .map_err(|e| napi::Error::from_reason(format!("passport verify: {e}")))?
        }
        None => RuntimePassport::from_json(&passport_json)
            .map_err(|e| napi::Error::from_reason(format!("passport parse: {e}")))?,
    };

    // 2. Build the verifier's local tool registry.
    let entries: napi::Result<Vec<ToolEntry>> = tools
        .into_iter()
        .map(|t| {
            let descriptor_hash = hex_to_array::<32>(&t.descriptor_hash_hex).map_err(|e| {
                napi::Error::from_reason(format!("tool descriptor_hash_hex: {e}"))
            })?;
            Ok(ToolEntry {
                descriptor_hash,
                local_id: t.local_id,
            })
        })
        .collect();
    let registry = ToolRegistry::from_entries(entries?)
        .map_err(|e| napi::Error::from_reason(format!("registry build: {e}")))?;

    // 3. Compile.
    let authority = CompiledAuthority::from_passport(&passport, registry)
        .map_err(|e| napi::Error::from_reason(format!("compile: {e}")))?;

    // 4. Pack into the opaque handle.
    let verifier_instance_id_hash =
        *blake3::hash(passport.verifier_instance_id.as_bytes()).as_bytes();

    let handle = AuthorityHandle {
        authority,
        clock: SystemClock,
        sink: NullSink,
        verifier_instance_id_hash,
        attested_tier: passport.tier_attested,
        revocation_epoch: passport.revocation_epoch,
    };
    Ok(External::new(handle))
}

/// Run `aps_check` against the loaded authority.
#[napi]
pub fn check(
    handle: External<AuthorityHandle>,
    action: ActionInput,
) -> napi::Result<DecisionOutput> {
    let descriptor = build_action_descriptor(&action)?;
    let ctx = VerifierContext::with_sink(
        &handle.clock,
        handle.verifier_instance_id_hash,
        handle.attested_tier,
        handle.revocation_epoch,
        &handle.sink,
    );
    let decision = aps_check(&handle.authority, &descriptor, &ctx);

    Ok(DecisionOutput {
        decision_type: decision_type_name(decision.decision_type).to_string(),
        reason_code: decision.reason_code as u8,
        reason_name: reason_code_name(decision.reason_code).to_string(),
        sequence_id: BigInt::from(decision.sequence_id),
        decision_id_hex: hex_encode_slice(&decision.decision_id),
        event_mac_hex: hex_encode_slice(&decision.event_mac),
    })
}

/// Signal that the caller is done with the handle. No-op in chunk 2:
/// the handle drops when JS GCs the wrapper. Kept as the
/// deterministic-lifecycle API surface; future chunks may wire
/// real teardown (background flush thread, log handle, etc.) and
/// will use this hook.
#[napi]
pub fn close_authority(_handle: External<AuthorityHandle>) -> napi::Result<()> {
    // _handle drops at end of scope, but napi-rs External owns the
    // inner state via the JS wrapper's lifetime, so this drop is
    // advisory only. Reaffirmed when later chunks add real teardown.
    let _ = Ordering::Acquire; // suppress unused-import lint on no-op path
    Ok(())
}

// -----------------------------------------------------------------------
// Helpers exposed for callers building actions and matching passports
// -----------------------------------------------------------------------

#[napi(object)]
pub struct AuthorityInfo {
    /// 64-char hex of the BLAKE3 hash of passport_id (matches
    /// `ActionInput.passport_id_hash_hex` for the active session).
    pub passport_id_hash_hex: String,
    /// 64-char hex of the verifier's current tool registry Merkle
    /// root.
    pub tool_registry_root_hex: String,
}

/// Read identity-hash fields off the loaded authority. Useful for
/// building [`ActionInput`] structures (passport_id_hash must match)
/// and for verifying the registry-root commitment.
#[napi]
pub fn authority_info(handle: External<AuthorityHandle>) -> AuthorityInfo {
    AuthorityInfo {
        passport_id_hash_hex: hex_encode_slice(&handle.authority.passport_id_hash),
        tool_registry_root_hex: hex_encode_slice(&handle.authority.tool_registry.current_root()),
    }
}

/// Compute the canonical registry Merkle root for a set of tools,
/// matching the verifier's [`ToolRegistry::current_root`] convention.
/// Callers use this to embed the right `tool_registry_root` value in
/// the passport they're issuing or verifying.
#[napi]
pub fn compute_registry_root(tools: Vec<ToolEntryInput>) -> napi::Result<String> {
    let entries: napi::Result<Vec<ToolEntry>> = tools
        .into_iter()
        .map(|t| {
            let descriptor_hash = hex_to_array::<32>(&t.descriptor_hash_hex)
                .map_err(|e| napi::Error::from_reason(format!("descriptor_hash_hex: {e}")))?;
            Ok(ToolEntry {
                descriptor_hash,
                local_id: t.local_id,
            })
        })
        .collect();
    let registry = ToolRegistry::from_entries(entries?)
        .map_err(|e| napi::Error::from_reason(format!("registry build: {e}")))?;
    Ok(hex_encode_slice(&registry.current_root()))
}

/// Hash a sequence of resource-path components into the 8 u64 slots
/// that fit [`ActionInput::resource_path_hashes`]. Pads with zeros
/// past the supplied components; rejects more than 8.
#[napi]
pub fn hash_resource_path(components: Vec<String>) -> napi::Result<Vec<BigInt>> {
    if components.len() > 8 {
        return Err(napi::Error::from_reason(
            "resource path is limited to 8 components (spec §5)".to_string(),
        ));
    }
    let mut out = vec![BigInt::from(0u64); 8];
    for (i, c) in components.iter().enumerate() {
        let h = aps_verifier_core::hash_path_component(c);
        out[i] = BigInt::from(h);
    }
    Ok(out)
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn build_action_descriptor(input: &ActionInput) -> napi::Result<ActionDescriptor> {
    let passport_id_hash = hex_to_array::<32>(&input.passport_id_hash_hex)
        .map_err(|e| napi::Error::from_reason(format!("passport_id_hash_hex: {e}")))?;
    let tool_descriptor_hash = hex_to_array::<32>(&input.tool_descriptor_hash_hex)
        .map_err(|e| napi::Error::from_reason(format!("tool_descriptor_hash_hex: {e}")))?;
    let nonce = hex_to_array::<16>(&input.nonce_hex)
        .map_err(|e| napi::Error::from_reason(format!("nonce_hex: {e}")))?;

    if input.resource_path_hashes.len() > 8 {
        return Err(napi::Error::from_reason(
            "resource_path_hashes accepts at most 8 elements (spec §5)".to_string(),
        ));
    }
    let mut resource_path_hashes = [0u64; 8];
    for (i, h) in input.resource_path_hashes.iter().enumerate() {
        // napi 2.16 BigInt::get_u64 returns `(sign_bit, value, lossless)`
        // -- the second element is the u64 value.
        let (_sign, value, _lossless) = h.get_u64();
        resource_path_hashes[i] = value;
    }

    let mut descriptor = ActionDescriptor {
        version: input.version,
        reserved: [0; 3],
        passport_id_hash,
        tool_descriptor_hash,
        local_tool_id: input.local_tool_id,
        operation_id: input.operation_id,
        resource_type: input.resource_type,
        risk_class: input.risk_class,
        resource_path_depth: input.resource_path_depth,
        reserved2: [0; 2],
        cost_units: input.cost_units,
        sequence_id: {
            let (_sign, value, _lossless) = input.sequence_id.get_u64();
            value
        },
        nonce,
        resource_path_hashes,
        action_hash: [0; 32],
    };
    descriptor.finalize();
    Ok(descriptor)
}

fn decision_type_name(d: DecisionType) -> &'static str {
    match d {
        DecisionType::Allow => "Allow",
        DecisionType::Deny => "Deny",
        DecisionType::Escalate => "Escalate",
    }
}

fn reason_code_name(r: ReasonCode) -> &'static str {
    match r {
        ReasonCode::Ok => "OK",
        ReasonCode::ExpiredPassport => "EXPIRED_PASSPORT",
        ReasonCode::NotYetValid => "NOT_YET_VALID",
        ReasonCode::StaleRevocationEpoch => "STALE_REVOCATION_EPOCH",
        ReasonCode::RegistryVersionMismatch => "REGISTRY_VERSION_MISMATCH",
        ReasonCode::ToolNotAllowed => "TOOL_NOT_ALLOWED",
        ReasonCode::OperationNotAllowed => "OPERATION_NOT_ALLOWED",
        ReasonCode::ResourceOutOfScope => "RESOURCE_OUT_OF_SCOPE",
        ReasonCode::RiskTierTooLow => "RISK_TIER_TOO_LOW",
        ReasonCode::RiskClassExceeded => "RISK_CLASS_EXCEEDED",
        ReasonCode::BudgetExceeded => "BUDGET_EXCEEDED",
        ReasonCode::SequenceReplay => "SEQUENCE_REPLAY",
        ReasonCode::NonceReplay => "NONCE_REPLAY",
        ReasonCode::ApprovalRequired => "APPROVAL_REQUIRED",
        ReasonCode::DeniedByRule => "DENIED_BY_RULE",
        ReasonCode::ActionHashInvalid => "ACTION_HASH_INVALID",
        ReasonCode::VerifierInstanceMismatch => "VERIFIER_INSTANCE_MISMATCH",
        ReasonCode::ClockAnchorStale => "CLOCK_ANCHOR_STALE",
        ReasonCode::SequenceRecoveryInvalid => "SEQUENCE_RECOVERY_INVALID",
        ReasonCode::StrictModeRequired => "STRICT_MODE_REQUIRED",
    }
}

fn hex_to_array<const N: usize>(hex: &str) -> Result<[u8; N], String> {
    if hex.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, hex.len()));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("non-hex character at {i}: {e}"))?;
    }
    Ok(out)
}

fn hex_encode_slice(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn ed25519_dalek_verifying_key(bytes: &[u8; 32]) -> napi::Result<ed25519_dalek::VerifyingKey> {
    ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map_err(|e| napi::Error::from_reason(format!("verifying key from bytes: {e}")))
}
