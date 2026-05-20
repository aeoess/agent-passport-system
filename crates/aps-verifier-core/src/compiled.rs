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

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use thiserror::Error;

use crate::passport::{ApprovalAction, DurabilityMode, PassportError, RiskClass, RuntimePassport};
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
// ToolRegistry (chunk-2 scope)
// -----------------------------------------------------------------------

/// Local descriptor-hash → local-integer-id table. Chunk 4 replaces this
/// with a synced registry sourced from the gateway; chunk 2 ships the
/// minimum needed for the compiler.
#[derive(Debug, Clone, Default)]
pub struct ToolRegistry {
    entries: Vec<ToolEntry>,
}

#[derive(Debug, Clone, Copy)]
pub struct ToolEntry {
    pub descriptor_hash: [u8; 32],
    pub local_id: u32,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a (hash, id) pair. Does not deduplicate; chunk 4 takes that
    /// responsibility.
    pub fn add(&mut self, descriptor_hash: [u8; 32], local_id: u32) {
        self.entries.push(ToolEntry {
            descriptor_hash,
            local_id,
        });
    }

    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<u32> {
        self.entries
            .iter()
            .find(|e| &e.descriptor_hash == hash)
            .map(|e| e.local_id)
    }

    pub fn get_by_id(&self, id: u32) -> Option<&[u8; 32]> {
        self.entries
            .iter()
            .find(|e| e.local_id == id)
            .map(|e| &e.descriptor_hash)
    }

    /// Number of entries currently registered.
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Maximum local_id currently registered, or `None` if empty.
    pub fn max_local_id(&self) -> Option<u32> {
        self.entries.iter().map(|e| e.local_id).max()
    }
}

// -----------------------------------------------------------------------
// Approval-rule stub (chunk 3 compiles the predicate)
// -----------------------------------------------------------------------

/// Raw approval rule carried unparsed. Chunk 3 compiles the predicate
/// string into an executable form. `TrieNode` lives in
/// [`crate::resource_trie`] and is re-used here as a hot-field pointer
/// inside [`CompiledAuthority`].
#[derive(Debug, Clone)]
pub struct RawApprovalRule {
    pub predicate: String,
    pub on_match: ApprovalAction,
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
    pub approval_rules: Vec<RawApprovalRule>,

    // Mode dispatch.
    pub durability_mode: DurabilityMode,

    // Receipt stream (chunk 5 populates the real key).
    pub receipt_stream_key: [u8; 32],
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
// Operation mapping (Prototype 1 fixed enum)
// -----------------------------------------------------------------------

fn operation_bit(name: &str) -> Option<u32> {
    match name {
        "read" => Some(0),
        "write" => Some(1),
        "delete" => Some(2),
        "external_send" => Some(3),
        "money_move" => Some(4),
        "data_export" => Some(5),
        "approval_request" => Some(6),
        _ => None,
    }
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
        // Temporal conversion: DateTime<Utc> to unix ns.
        let issued_at_unix_ns = datetime_to_unix_ns(passport.issued_at);
        let expires_at_unix_ns = datetime_to_unix_ns(passport.expires_at);
        let max_clock_skew_ns = u64::from(passport.max_clock_skew_ms) * 1_000_000;

        // Identity hashes (BLAKE3 of the id strings).
        let passport_id_hash = blake3_32(passport.passport_id.as_bytes());
        let verifier_instance_id_hash = blake3_32(passport.verifier_instance_id.as_bytes());

        // Allowed operation mask.
        let mut allowed_op_mask: u32 = 0;
        for op in &passport.authority_blob.allowed_operations {
            let bit = operation_bit(op).ok_or_else(|| CompileError::UnknownOperation {
                name: op.clone(),
            })?;
            allowed_op_mask |= 1u32 << bit;
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

        // Approval rules: carry raw, compile in chunk 3.
        let approval_rules = passport
            .authority_blob
            .approval_rules
            .iter()
            .map(|r| RawApprovalRule {
                predicate: r.predicate.clone(),
                on_match: r.on_match,
            })
            .collect();

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
            resource_trie: None,
            approval_rules,
            durability_mode: default_durability_for(passport.risk_class),
            receipt_stream_key: [0u8; 32],
        })
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
}
