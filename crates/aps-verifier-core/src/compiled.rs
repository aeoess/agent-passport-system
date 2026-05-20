//! Section 8 and Appendix A: CompiledAuthority in-memory layout.
//!
//! Section 8 normative properties the hot path MUST satisfy:
//!   1. No heap allocations during `aps_check`.
//!   2. No string operations or JSON parsing during `aps_check`.
//!   3. Constant-time or near-constant-time evaluation per check.
//!   4. Atomic decrement for budget counters.
//!   5. Atomic CAS for sequence advancement.
//!   6. Cache-aligned layout of frequently-accessed fields.
//!
//! Appendix A provides a reference Rust layout. It is non-normative:
//! implementations are free to benchmark alternative shapes (radix
//! trie, perfect hash, bloom + fallback for resource scopes) as long
//! as the six properties above hold. This module implements the
//! reference layout.
//!
//! Layout notes:
//!
//! - `#[repr(C, align(64))]` puts the hot fields on their own cache
//!   line. The alignment is a performance hint, not a wire-format
//!   requirement; nothing on disk or on the network references this
//!   layout. Authority moves over the wire as a signed Runtime
//!   Passport (§4), then is COMPILED into this struct at passport
//!   load.
//!
//! - The struct holds `AtomicU64` / `AtomicU32` counters and owning
//!   collections (`Vec`, `Option<Box<...>>`); it is NOT `Copy` and
//!   cannot be `memcpy`'d. Construction goes through
//!   [`CompiledAuthority::from_passport`], which is the slow path
//!   (run once per session).
//!
//! Fixed operation enum (Prototype 1):
//!
//! | Operation        | Mask bit |
//! | ---------------- | -------- |
//! | `read`           | 0        |
//! | `write`          | 1        |
//! | `delete`         | 2        |
//! | `external_send`  | 3        |
//! | `money_move`     | 4        |
//! | `data_export`    | 5        |
//! | `approval_request` | 6      |
//!
//! Expansion beyond these seven operations is deferred to Phase 2.

use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use thiserror::Error;

use crate::approval::{
    operation_id_from_name, ApprovalCompileError, CompiledApprovalRule,
};
use crate::passport::{DurabilityMode, PassportError, RiskClass, RuntimePassport};
use crate::recovery::{recover_log, RecoveryError, RecoveryReport, RecoveryStatus};
use crate::registry::ToolRegistry;
use crate::resource_trie::TrieNode;

// -----------------------------------------------------------------------
// BitMap
// -----------------------------------------------------------------------

/// Bit-vector backed by `Vec<u64>`. Capacity is rounded up to the next
/// multiple of 64 bits at construction; bit indices in `[0, capacity)`
/// are valid.
#[derive(Debug, Clone)]
pub struct BitMap {
    words: Vec<u64>,
    capacity_bits: usize,
}

impl BitMap {
    /// Create a new bitmap with at least `capacity_bits` bits. Actual
    /// capacity is rounded up to a multiple of 64.
    pub fn new(capacity_bits: usize) -> Self {
        let word_count = capacity_bits.div_ceil(64).max(1);
        BitMap {
            words: vec![0u64; word_count],
            capacity_bits: word_count * 64,
        }
    }

    /// Set bit `bit`. Panics if `bit` is outside `[0, capacity())`.
    pub fn set(&mut self, bit: u32) {
        let (word, mask) = self.index(bit);
        self.words[word] |= mask;
    }

    /// Clear bit `bit`. Panics if out of range.
    pub fn clear(&mut self, bit: u32) {
        let (word, mask) = self.index(bit);
        self.words[word] &= !mask;
    }

    /// Read bit `bit`. Panics if out of range.
    pub fn get(&self, bit: u32) -> bool {
        let (word, mask) = self.index(bit);
        (self.words[word] & mask) != 0
    }

    /// Capacity in bits, rounded up to a multiple of 64.
    pub fn capacity(&self) -> usize {
        self.capacity_bits
    }

    fn index(&self, bit: u32) -> (usize, u64) {
        let bit = bit as usize;
        assert!(
            bit < self.capacity_bits,
            "BitMap index out of range: bit {bit} >= capacity {cap}",
            cap = self.capacity_bits
        );
        (bit / 64, 1u64 << (bit % 64))
    }
}

// -----------------------------------------------------------------------
// CompiledAuthority
// -----------------------------------------------------------------------

/// Section 8 / Appendix A reference layout. Hot fields share a single
/// cache line via `#[repr(C, align(64))]`.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct CompiledAuthority {
    // Cache line 1: hot fields touched every action.
    pub expires_at_unix_ns: u64,
    pub issued_at_unix_ns: u64,
    pub max_clock_skew_ns: u64,
    pub revocation_epoch: u32,
    pub risk_class: u8,
    pub minimum_tier_required: u8,
    pub flags: u16,
    pub sequence_next: AtomicU64,
    pub sequence_end: u64,
    pub budget_remaining_actions: AtomicU32,
    pub budget_remaining_cost_units: AtomicU64,
    pub allowed_op_mask: u32,
    pub last_time_anchor_ns: AtomicU64,

    // Cache line 2: identity hashes.
    pub passport_id_hash: [u8; 32],
    pub verifier_instance_id_hash: [u8; 32],

    // Permissions (chunk 2 owns the tool bitmap and registry).
    pub allowed_tool_bitmap: BitMap,
    pub tool_registry: ToolRegistry,

    // Stubs for later chunks.
    pub resource_trie: Option<Box<TrieNode>>,
    /// Compiled approval rules (chunk 4). Empty Vec when the passport
    /// carries no rules.
    pub approval_rules: Vec<CompiledApprovalRule>,

    // Mode dispatch.
    pub durability_mode: DurabilityMode,

    // Receipt stream (chunk 5 populates the real key).
    pub receipt_stream_key: [u8; 32],

    /// Spec §11.4 recovery floor. `0` is the no-recovery / fresh-start
    /// sentinel — gateway-allocated sequence windows start above 0 (see
    /// spec §4 example: `sequence_start: 1000`), so a recovered
    /// `last_committed_sequence_id` of 0 is unreachable in practice.
    /// The aps_check step 10 only consults this field when it is > 0.
    pub recovered_floor: AtomicU64,
}

// -----------------------------------------------------------------------
// Compile errors
// -----------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("unknown tool descriptor (not in local registry): 0x{}", hex32(.descriptor_hash))]
    UnknownTool { descriptor_hash: [u8; 32] },
    #[error("unknown operation: {name:?} (not in Prototype 1 fixed operation enum)")]
    UnknownOperation { name: String },
    #[error("invalid passport: {0}")]
    InvalidPassport(#[from] PassportError),
    #[error("approval rule compile error: {0}")]
    ApprovalRule(#[from] ApprovalCompileError),
    #[error("tool registry root mismatch: passport has {passport_root}, verifier has {verifier_root}")]
    RegistryRootMismatch {
        passport_root: String,
        verifier_root: String,
    },
    #[error("invalid field value in passport: {0}")]
    InvalidFieldValue(String),
    #[error("recovery failed: {0}")]
    RecoveryFailed(#[from] RecoveryError),
    #[error("log/passport mismatch: recovered_floor={recovered_floor} outside sequence window [{sequence_start}, {sequence_end})")]
    LogPassportMismatch {
        recovered_floor: u64,
        sequence_start: u64,
        sequence_end: u64,
    },
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// -----------------------------------------------------------------------
// Durability mode selection (default by risk class, spec §11.3)
// -----------------------------------------------------------------------

fn default_durability_for(risk: RiskClass) -> DurabilityMode {
    match risk {
        RiskClass::R0 | RiskClass::R1 => DurabilityMode::MemoryBuffered,
        RiskClass::R2 | RiskClass::R3 => DurabilityMode::BlockingGroupCommit,
        RiskClass::R4 => DurabilityMode::Strict,
    }
}

// -----------------------------------------------------------------------
// Builder
// -----------------------------------------------------------------------

impl CompiledAuthority {
    /// Compile a parsed [`RuntimePassport`] into the hot-path layout.
    /// Slow path; runs once per session at passport load.
    ///
    /// - Temporal fields convert `DateTime<Utc>` to unix nanoseconds.
    /// - `last_time_anchor_ns` is initialized to `issued_at` (the best
    ///   fresh anchor known at session start); the verifier updates it
    ///   when the gateway anchor poll lands.
    /// - `allowed_op_mask` is built from the §4 fixed operation enum;
    ///   unknown operation names are rejected with `UnknownOperation`.
    /// - `allowed_tool_bitmap` capacity is `max(tool_registry.size(),
    ///   65_536)`; each allowed tool's descriptor hash is resolved
    ///   against `tool_registry` and its local id sets the bit. Unknown
    ///   tools are rejected with `UnknownTool`.
    /// - `durability_mode` defaults to [`default_durability_for`] per
    ///   risk class (R0/R1 memory-buffered, R2/R3 blocking commit, R4
    ///   strict).
    /// - `resource_trie`, the parsed approval rules, and
    ///   `receipt_stream_key` are placeholders filled by chunks 3-5.
    pub fn from_passport(
        passport: &RuntimePassport,
        tool_registry: ToolRegistry,
    ) -> Result<Self, CompileError> {
        // Registry root MUST match the passport's tool_registry_root.
        // Validated FIRST: a mismatched registry means every downstream
        // tool resolution would be untrustworthy.
        let verifier_root = tool_registry.current_root();
        let passport_root_bytes = decode_hash_field(&passport.tool_registry_root)?;
        if verifier_root != passport_root_bytes {
            return Err(CompileError::RegistryRootMismatch {
                passport_root: hex32(&passport_root_bytes),
                verifier_root: hex32(&verifier_root),
            });
        }

        // Temporal conversion: DateTime<Utc> to unix ns.
        let issued_at_unix_ns = datetime_to_unix_ns(passport.issued_at);
        let expires_at_unix_ns = datetime_to_unix_ns(passport.expires_at);
        let max_clock_skew_ns = u64::from(passport.max_clock_skew_ms) * 1_000_000;

        // Identity hashes (BLAKE3 of the id strings).
        let passport_id_hash = blake3_32(passport.passport_id.as_bytes());
        let verifier_instance_id_hash = blake3_32(passport.verifier_instance_id.as_bytes());

        // Allowed operation mask (bit position == operation id, fixed
        // enum shared with `approval::operation_id_from_name`).
        let mut allowed_op_mask: u32 = 0;
        for op in &passport.authority_blob.allowed_operations {
            let id = operation_id_from_name(op).ok_or_else(|| {
                CompileError::UnknownOperation { name: op.clone() }
            })?;
            allowed_op_mask |= 1u32 << u32::from(id);
        }

        // Allowed-tool bitmap.
        let bitmap_capacity = tool_registry
            .max_local_id()
            .map(|m| (m as usize).saturating_add(1))
            .unwrap_or(0)
            .max(65_536);
        let mut allowed_tool_bitmap = BitMap::new(bitmap_capacity);
        for tool_hash_str in &passport.authority_blob.allowed_tools {
            let descriptor_hash = parse_blake3_field(tool_hash_str)
                .ok_or(CompileError::UnknownTool {
                    descriptor_hash: [0u8; 32],
                })?;
            let local_id = tool_registry
                .get_by_hash(&descriptor_hash)
                .ok_or(CompileError::UnknownTool { descriptor_hash })?;
            allowed_tool_bitmap.set(local_id);
        }

        // Approval rules: compile each predicate (chunk 4). Fail-closed:
        // any uncompilable rule rejects the entire passport. The gateway
        // is responsible for issuing only predicates the verifier can
        // compile (either by narrowing rules at issuance time or by
        // knowing the verifier's DSL capability set).
        let mut approval_rules = Vec::with_capacity(passport.authority_blob.approval_rules.len());
        for r in &passport.authority_blob.approval_rules {
            approval_rules.push(CompiledApprovalRule::compile(&r.predicate, r.on_match)?);
        }

        Ok(CompiledAuthority {
            expires_at_unix_ns,
            issued_at_unix_ns,
            max_clock_skew_ns,
            revocation_epoch: passport.revocation_epoch,
            risk_class: passport.risk_class as u8,
            minimum_tier_required: passport.minimum_tier_required as u8,
            flags: 0,
            sequence_next: AtomicU64::new(passport.sequence_start),
            sequence_end: passport.sequence_end,
            budget_remaining_actions: AtomicU32::new(
                u32::try_from(passport.budget_lease.max_actions).unwrap_or(u32::MAX),
            ),
            budget_remaining_cost_units: AtomicU64::new(passport.budget_lease.max_cost_units),
            allowed_op_mask,
            last_time_anchor_ns: AtomicU64::new(issued_at_unix_ns),
            passport_id_hash,
            verifier_instance_id_hash,
            allowed_tool_bitmap,
            tool_registry,
            resource_trie: Some(Box::new(TrieNode::build(
                &passport.authority_blob.resource_scopes,
            ))),
            approval_rules,
            durability_mode: default_durability_for(passport.risk_class),
            receipt_stream_key: [0u8; 32],
            recovered_floor: AtomicU64::new(0),
        })
    }

    /// Compile a passport with crash recovery against the durable log
    /// at `log_path`. Spec §11.4. On clean recovery, `sequence_next`
    /// resumes at `last_committed_sequence_id + 1`; on fresh start,
    /// behaves identically to [`Self::from_passport`].
    ///
    /// `log_path` is the receipt log for THIS passport's session. The
    /// mapping from passport to log path is a caller responsibility.
    /// `mac_key` MUST be the same `receipt_stream_key` used when the
    /// log was originally written.
    pub fn from_passport_with_recovery(
        passport: &RuntimePassport,
        registry: &ToolRegistry,
        log_path: &Path,
        mac_key: [u8; 32],
    ) -> Result<(Self, RecoveryReport), CompileError> {
        let report = recover_log(log_path, mac_key)?;

        // Validate recovered floor against the passport's window.
        let validated_floor = match &report.status {
            RecoveryStatus::FreshStart => None,
            RecoveryStatus::CleanRecovery | RecoveryStatus::PartialRecovery { .. } => {
                let floor = report.last_committed_sequence_id;
                if floor != 0 && floor < passport.sequence_start {
                    return Err(CompileError::LogPassportMismatch {
                        recovered_floor: floor,
                        sequence_start: passport.sequence_start,
                        sequence_end: passport.sequence_end,
                    });
                }
                if floor >= passport.sequence_end {
                    return Err(CompileError::LogPassportMismatch {
                        recovered_floor: floor,
                        sequence_start: passport.sequence_start,
                        sequence_end: passport.sequence_end,
                    });
                }
                Some(floor)
            }
        };

        let auth = Self::from_passport(passport, registry.clone())?;
        if let Some(floor) = validated_floor {
            auth.recovered_floor.store(floor, Ordering::Release);
            auth.sequence_next.store(floor + 1, Ordering::Release);
        }
        Ok((auth, report))
    }
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn datetime_to_unix_ns(dt: chrono::DateTime<chrono::Utc>) -> u64 {
    // Negative timestamps are not meaningful for a runtime passport.
    let nanos = dt.timestamp_nanos_opt().unwrap_or(0);
    u64::try_from(nanos).unwrap_or(0)
}

fn blake3_32(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Parse `"blake3:<64-hex>"` (or any `"<prefix>:<64-hex>"`) into a
/// 32-byte hash. Returns `None` on any structural failure.
fn parse_blake3_field(s: &str) -> Option<[u8; 32]> {
    let (_prefix, hex) = s.split_once(':')?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let chunk = hex.get(i * 2..i * 2 + 2)?;
        *byte = u8::from_str_radix(chunk, 16).ok()?;
    }
    Some(out)
}

/// Parse a 32-byte hash field that may carry either a `"<prefix>:<hex>"`
/// or a bare hex form. Used for `tool_registry_root` and similar fields
/// where Prototype 1 accepts both shapes.
fn decode_hash_field(s: &str) -> Result<[u8; 32], CompileError> {
    let hex = match s.split_once(':') {
        Some((_, rest)) => rest,
        None => s,
    };
    if hex.len() != 64 {
        return Err(CompileError::InvalidFieldValue(format!(
            "expected 64 hex chars, got {} for {s:?}",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let chunk = hex.get(i * 2..i * 2 + 2).ok_or_else(|| {
            CompileError::InvalidFieldValue(format!("hex slice failed for {s:?}"))
        })?;
        *byte = u8::from_str_radix(chunk, 16).map_err(|_| {
            CompileError::InvalidFieldValue(format!("non-hex character in {s:?}"))
        })?;
    }
    Ok(out)
}

// -----------------------------------------------------------------------
// Hot-path sequence helpers (small surface needed by chunk 5 and tests)
// -----------------------------------------------------------------------

impl CompiledAuthority {
    /// Attempt to advance `sequence_next` from `expected` to `expected +
    /// 1`. Returns `true` on success. Caller is responsible for the
    /// monotonic-replay check (`action.sequence_id == expected`).
    pub fn try_advance_sequence(&self, expected: u64) -> bool {
        self.sequence_next
            .compare_exchange(
                expected,
                expected + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Monotonically update the last received gateway time anchor.
    /// Concurrent-safe via a CAS loop: under contention the final
    /// stored value is the maximum of all attempted updates.
    pub fn update_time_anchor(&self, new_anchor_ns: u64) {
        let mut current = self.last_time_anchor_ns.load(Ordering::Acquire);
        while new_anchor_ns > current {
            match self.last_time_anchor_ns.compare_exchange(
                current,
                new_anchor_ns,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
}
