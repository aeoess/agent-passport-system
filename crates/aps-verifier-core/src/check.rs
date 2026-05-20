//! Section 9: `aps_check` hot-path algorithm.
//!
//! Order of checks is normative: integrity, instance binding, temporal,
//! R3+ time-anchor freshness, revocation freshness, tier, risk class,
//! tool (hash-validated bitmap), operation mask, resource trie, sequence
//! (atomic CAS), budget (atomic decrement with sequence rollback on
//! failure), approval rules, then emit decision event per durability
//! mode (Section 11.3).
//!
//! TODO: implement the full pipeline. Skeleton returns `unimplemented!()`.

use crate::action::ActionDescriptor;
use crate::compiled::CompiledAuthority;
use crate::decision::Decision;

/// Hot-path verifier. See Section 9 of the spec for the full algorithm.
pub fn aps_check(_auth: &CompiledAuthority, _action: &ActionDescriptor) -> Decision {
    unimplemented!("Section 9 hot path: implementation lands in Stream A follow-up commit")
}
