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
pub mod compiled;
pub mod check;
pub mod registry;
pub mod clock;
pub mod durability;
pub mod recovery;
pub mod resource_trie;

pub use action::{ActionDescriptor, ActionError, ACTION_DESCRIPTOR_SIZE};
pub use decision::{Decision, DecisionError, DecisionType, ReasonCode, DECISION_SIZE};
pub use passport::{
    ApprovalAction, ApprovalRule, AuthorityBlob, BudgetLease, DurabilityMode, PassportError,
    RiskClass, RuntimePassport, Tier,
};
