//! Stream B chunk 3: sink bindings + L2/L3 benchmark surface.
//!
//! Adds [`SinkMode`] / [`SinkConfig`] selection to [`load_passport`]
//! and a [`shutdown_authority`] entry point that drains pending
//! writes for Mode A / B1 / B2. The sink is held inside the
//! [`AuthorityHandle`] as an `enum SinkVariant` under a `Mutex` so
//! shutdown can consume the mode-specific value; `check` borrows
//! `&dyn ReceiptSink` from the locked variant.
//!
//! Also exposes [`capture_environment`] so the TS-side benchmark
//! runner can write spec §13.4 / §13.3 environment metadata into the
//! L2/L3 result JSON without duplicating the probe logic across
//! crates.

#![deny(clippy::all)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Duration;

use napi::bindgen_prelude::{BigInt, External};
use napi_derive::napi;

use aps_verifier_core::{
    aps_check, ActionDescriptor, CompiledAuthority, DecisionType, GroupCommitConfig,
    ModeAReceiptSink, ModeB1ReceiptSink, ModeB2ReceiptSink, NullSink, ReasonCode, ReceiptSink,
    RuntimePassport, SystemClock, Tier, ToolEntry, ToolRegistry, VerifierContext,
};

// -----------------------------------------------------------------------
// Chunk 1: parse-only API
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
/// verify the signature; see [`load_passport`] for the full lifecycle.
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
// Chunk 3: sink configuration
// -----------------------------------------------------------------------

#[napi(string_enum)]
pub enum SinkMode {
    Null,
    ModeA,
    ModeB1,
    ModeB2,
}

#[napi(object)]
pub struct SinkConfig {
    pub mode: SinkMode,
    /// Filesystem path for the durable receipt log. Required when
    /// `mode != Null`; ignored otherwise.
    pub log_path: Option<String>,
    /// Buffer capacity. Defaults: Mode A 4096, Mode B1/B2 1024.
    pub buffer_capacity: Option<u32>,
    /// Mode A flush interval in milliseconds. Default 100. Ignored
    /// for Null and Mode B.
    pub flush_interval_ms: Option<u32>,
    /// Mode B1/B2 max batch size. Default 64. Ignored for Null and
    /// Mode A.
    pub max_batch_size: Option<u32>,
    /// Mode B1/B2 max batch window in milliseconds. Default 1.
    /// Ignored for Null and Mode A.
    pub max_batch_window_ms: Option<u32>,
}

// Internal enum dispatching sink-specific behavior (the chunk-8/9a
// ReceiptSink trait does not include `shutdown`, so we keep concrete
// variants here and call mode-specific shutdown in `shutdown_authority`).
enum SinkVariant {
    Null(NullSink),
    ModeA(ModeAReceiptSink),
    ModeB1(ModeB1ReceiptSink),
    ModeB2(ModeB2ReceiptSink),
}

impl SinkVariant {
    fn as_sink(&self) -> &dyn ReceiptSink {
        match self {
            SinkVariant::Null(s) => s,
            SinkVariant::ModeA(s) => s,
            SinkVariant::ModeB1(s) => s,
            SinkVariant::ModeB2(s) => s,
        }
    }

    fn shutdown(self) -> Result<(), String> {
        match self {
            SinkVariant::Null(_) => Ok(()),
            SinkVariant::ModeA(s) => s.shutdown().map_err(|e| e.to_string()),
            SinkVariant::ModeB1(s) => s.shutdown().map_err(|e| e.to_string()),
            SinkVariant::ModeB2(s) => s.shutdown().map_err(|e| e.to_string()),
        }
    }
}

fn build_sink_variant(cfg: &SinkConfig, receipt_key: [u8; 32]) -> napi::Result<SinkVariant> {
    match cfg.mode {
        SinkMode::Null => Ok(SinkVariant::Null(NullSink)),
        SinkMode::ModeA => {
            let path = cfg
                .log_path
                .as_ref()
                .ok_or_else(|| napi::Error::from_reason("log_path required for Mode A".to_string()))?;
            let capacity = cfg.buffer_capacity.unwrap_or(4096) as usize;
            let interval = Duration::from_millis(u64::from(cfg.flush_interval_ms.unwrap_or(100)));
            let sink = ModeAReceiptSink::new(&PathBuf::from(path), receipt_key, capacity, interval)
                .map_err(|e| napi::Error::from_reason(format!("Mode A new: {e}")))?;
            Ok(SinkVariant::ModeA(sink))
        }
        SinkMode::ModeB1 => {
            let path = cfg.log_path.as_ref().ok_or_else(|| {
                napi::Error::from_reason("log_path required for Mode B1".to_string())
            })?;
            let capacity = cfg.buffer_capacity.unwrap_or(1024) as usize;
            let commit_cfg = GroupCommitConfig {
                max_batch_size: cfg.max_batch_size.unwrap_or(64) as usize,
                max_batch_window: Duration::from_millis(u64::from(
                    cfg.max_batch_window_ms.unwrap_or(1),
                )),
            };
            let sink = ModeB1ReceiptSink::new(
                &PathBuf::from(path),
                receipt_key,
                capacity,
                commit_cfg,
            )
            .map_err(|e| napi::Error::from_reason(format!("Mode B1 new: {e}")))?;
            Ok(SinkVariant::ModeB1(sink))
        }
        SinkMode::ModeB2 => {
            let path = cfg.log_path.as_ref().ok_or_else(|| {
                napi::Error::from_reason("log_path required for Mode B2".to_string())
            })?;
            let capacity = cfg.buffer_capacity.unwrap_or(1024) as usize;
            let commit_cfg = GroupCommitConfig {
                max_batch_size: cfg.max_batch_size.unwrap_or(64) as usize,
                max_batch_window: Duration::from_millis(u64::from(
                    cfg.max_batch_window_ms.unwrap_or(1),
                )),
            };
            let sink = ModeB2ReceiptSink::new(
                &PathBuf::from(path),
                receipt_key,
                capacity,
                commit_cfg,
            )
            .map_err(|e| napi::Error::from_reason(format!("Mode B2 new: {e}")))?;
            Ok(SinkVariant::ModeB2(sink))
        }
    }
}

// -----------------------------------------------------------------------
// Handle + lifecycle
// -----------------------------------------------------------------------

#[napi(object)]
pub struct ToolEntryInput {
    pub descriptor_hash_hex: String,
    pub local_id: u32,
}

pub struct AuthorityHandle {
    authority: CompiledAuthority,
    clock: SystemClock,
    /// `Option<SinkVariant>` so `shutdown_authority` can take and
    /// consume the variant for mode-specific drain. `Mutex` serializes
    /// the borrow used by `check`.
    sink: Mutex<Option<SinkVariant>>,
    verifier_instance_id_hash: [u8; 32],
    attested_tier: Tier,
    revocation_epoch: u32,
}

#[napi(object)]
pub struct ActionInput {
    pub version: u8,
    pub passport_id_hash_hex: String,
    pub tool_descriptor_hash_hex: String,
    pub local_tool_id: u32,
    pub operation_id: u16,
    pub resource_type: u16,
    pub risk_class: u8,
    pub resource_path_depth: u8,
    pub cost_units: u32,
    pub sequence_id: BigInt,
    pub nonce_hex: String,
    pub resource_path_hashes: Vec<BigInt>,
}

#[napi(object)]
pub struct DecisionOutput {
    pub decision_type: String,
    pub reason_code: u8,
    pub reason_name: String,
    pub sequence_id: BigInt,
    pub decision_id_hex: String,
    pub event_mac_hex: String,
}

#[napi]
pub fn load_passport(
    passport_json: String,
    tools: Vec<ToolEntryInput>,
    gateway_public_key_hex: Option<String>,
    sink_config: SinkConfig,
) -> napi::Result<External<AuthorityHandle>> {
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

    let entries: napi::Result<Vec<ToolEntry>> = tools
        .into_iter()
        .map(|t| {
            let descriptor_hash = hex_to_array::<32>(&t.descriptor_hash_hex)
                .map_err(|e| napi::Error::from_reason(format!("tool descriptor_hash_hex: {e}")))?;
            Ok(ToolEntry {
                descriptor_hash,
                local_id: t.local_id,
            })
        })
        .collect();
    let registry = ToolRegistry::from_entries(entries?)
        .map_err(|e| napi::Error::from_reason(format!("registry build: {e}")))?;

    let authority = CompiledAuthority::from_passport(&passport, registry)
        .map_err(|e| napi::Error::from_reason(format!("compile: {e}")))?;

    let receipt_key = authority.receipt_stream_key;
    let sink = build_sink_variant(&sink_config, receipt_key)?;

    let verifier_instance_id_hash =
        *blake3::hash(passport.verifier_instance_id.as_bytes()).as_bytes();

    Ok(External::new(AuthorityHandle {
        authority,
        clock: SystemClock,
        sink: Mutex::new(Some(sink)),
        verifier_instance_id_hash,
        attested_tier: passport.tier_attested,
        revocation_epoch: passport.revocation_epoch,
    }))
}

#[napi]
pub fn check(
    handle: External<AuthorityHandle>,
    action: ActionInput,
) -> napi::Result<DecisionOutput> {
    let descriptor = build_action_descriptor(&action)?;
    let guard = handle
        .sink
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("sink mutex poisoned: {e}")))?;
    let sink_variant = guard
        .as_ref()
        .ok_or_else(|| napi::Error::from_reason("authority has been shut down".to_string()))?;
    let sink_ref: &dyn ReceiptSink = sink_variant.as_sink();
    let ctx = VerifierContext::with_sink(
        &handle.clock,
        handle.verifier_instance_id_hash,
        handle.attested_tier,
        handle.revocation_epoch,
        sink_ref,
    );
    let decision = aps_check(&handle.authority, &descriptor, &ctx);
    drop(guard);

    Ok(DecisionOutput {
        decision_type: decision_type_name(decision.decision_type).to_string(),
        reason_code: decision.reason_code as u8,
        reason_name: reason_code_name(decision.reason_code).to_string(),
        sequence_id: BigInt::from(decision.sequence_id),
        decision_id_hex: hex_encode_slice(&decision.decision_id),
        event_mac_hex: hex_encode_slice(&decision.event_mac),
    })
}

/// Release the handle without draining. The sink continues running in
/// the background until JS GCs the wrapper; for deterministic drain,
/// use [`shutdown_authority`].
#[napi]
pub fn close_authority(_handle: External<AuthorityHandle>) -> napi::Result<()> {
    let _ = Ordering::Acquire;
    Ok(())
}

/// Drain the sink (flush Mode A buffer, wait for Mode B pending
/// batches) and close. After this returns the durable log reflects
/// every successfully `emit`'d decision.
#[napi]
pub fn shutdown_authority(handle: External<AuthorityHandle>) -> napi::Result<()> {
    let variant = {
        let mut guard = handle
            .sink
            .lock()
            .map_err(|e| napi::Error::from_reason(format!("sink mutex poisoned: {e}")))?;
        guard.take()
    };
    if let Some(v) = variant {
        v.shutdown()
            .map_err(|e| napi::Error::from_reason(format!("shutdown: {e}")))?;
    }
    Ok(())
}

// -----------------------------------------------------------------------
// Helpers exposed for callers building actions
// -----------------------------------------------------------------------

#[napi(object)]
pub struct AuthorityInfo {
    pub passport_id_hash_hex: String,
    pub tool_registry_root_hex: String,
}

#[napi]
pub fn authority_info(handle: External<AuthorityHandle>) -> AuthorityInfo {
    AuthorityInfo {
        passport_id_hash_hex: hex_encode_slice(&handle.authority.passport_id_hash),
        tool_registry_root_hex: hex_encode_slice(&handle.authority.tool_registry.current_root()),
    }
}

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
// Environment capture (host metadata for benchmark JSON output)
// -----------------------------------------------------------------------

#[napi(object)]
pub struct EnvHost {
    pub cpu_brand: String,
    pub cpu_arch: String,
    pub os_name: String,
    pub os_version: String,
    pub hostname: String,
    pub memory_bytes: i64,
}

#[napi(object)]
pub struct EnvSnapshot {
    pub label: String,
    pub spec_section: String,
    pub canonical: bool,
    pub host: EnvHost,
}

/// Capture host environment metadata for the active machine. macOS-
/// only in chunk 3; Linux capture lands with the canonical benchmark
/// target.
#[napi]
pub fn capture_environment() -> EnvSnapshot {
    EnvSnapshot {
        label: "mac-apple-silicon".into(),
        spec_section: "13.3".into(),
        canonical: false,
        host: EnvHost {
            cpu_brand: sysctl_string("machdep.cpu.brand_string"),
            cpu_arch: shell_string("uname", &["-m"]),
            os_name: shell_string("sw_vers", &["-productName"]),
            os_version: shell_string("sw_vers", &["-productVersion"]),
            hostname: shell_string("hostname", &[]),
            memory_bytes: sysctl_string("hw.memsize").parse::<i64>().unwrap_or(0),
        },
    }
}

// -----------------------------------------------------------------------
// Internals
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

fn sysctl_string(name: &str) -> String {
    shell_string("sysctl", &["-n", name])
}

fn shell_string(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into())
}
