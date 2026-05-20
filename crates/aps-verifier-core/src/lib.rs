//! APS Runtime Passport local verifier core (Prototype 1, Stream A).
//!
//! Implements the spec at `specs/PROTOTYPE-1-RUNTIME-PASSPORT.md`.
//! Module map mirrors the spec sections:
//!
//! - [`passport`]     Section 4: Runtime Passport wire format.
//! - [`action`]       Section 5: Action Descriptor wire format.
//! - [`decision`]     Section 6 and 7: Decision result and reason codes.
//! - [`compiled`]     Section 8 and Appendix A: CompiledAuthority layout.
//! - [`check`]        Section 9: `aps_check` hot-path algorithm.
//! - [`registry`]     Section 11.1: tool registry consistency.
//! - [`clock`]        Section 11.2: time-anchor handling.
//! - [`durability`]   Section 11.3: Mode A / B1 / B2 event durability.
//! - [`recovery`]     Section 11.4: crash recovery floor.
//! - [`resource_trie`] Section 8: resource-scope matcher.

pub mod passport;
pub mod action;
pub mod decision;
pub mod approval;
pub mod compiled;
pub mod check;
pub mod registry;
pub mod clock;
pub mod durability;
pub mod receipt_log;
pub mod recovery;
pub mod resource_trie;

pub use action::{ActionDescriptor, ActionError, ACTION_DESCRIPTOR_SIZE};
pub use approval::{
    operation_id_from_name, risk_class_value_from_name, ApprovalCompileError, CompareOp,
    CompiledApprovalRule, CompiledPredicate, PredicateField, SetOp,
};
pub use check::{aps_check, Clock, ManualClock, SystemClock, VerifierContext};
pub use durability::{
    EmitOutcome, GroupCommitConfig, ModeAReceiptSink, ModeB1ReceiptSink, ModeB2ReceiptSink,
    NullSink, ReceiptError, ReceiptSink,
};
pub use receipt_log::{LogError, LogWriter, LOG_ENTRY_BYTES, LOG_ENTRY_PAYLOAD};
pub use recovery::{
    recover_log, RecoveryError, RecoveryReport, RecoveryStatus, TruncationReason,
};
pub use clock::{
    time_anchor_freshness, ClockAnchor, ClockAnchorPoller, ClockError, FreshnessVerdict,
    MockClockAnchorPoller, R3_MAX_ANCHOR_AGE_NS,
};
pub use compiled::{BitMap, CompileError, CompiledAuthority};
pub use registry::{
    MockRegistryFetcher, RegistryError, RegistryFetcher, SyncError, ToolEntry, ToolRegistry,
};
pub use resource_trie::{hash_path_component, parse_scope, ParsedScope, TrieNode};
pub use decision::{Decision, DecisionError, DecisionType, ReasonCode, DECISION_SIZE};
pub use passport::{
    canonical_signed_bytes, ApprovalAction, ApprovalRule, AuthorityBlob, BudgetLease,
    DurabilityMode, PassportError, RiskClass, RuntimePassport, Tier,
};
pub use action::ACTION_HASH_OFFSET;
pub use decision::CANONICAL_DECISION_EVENT_LEN;
