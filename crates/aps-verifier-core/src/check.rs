//! Section 9: `aps_check` hot-path algorithm.
//!
//! Order of checks is normative (spec §9, steps 0-13):
//! 0. integrity (`action_hash`)
//! 1. instance binding (verifier_instance_id_hash)
//! 2. temporal (expires_at, issued_at within max_clock_skew)
//! 3. R3+ time-anchor freshness
//! 4. revocation freshness
//! 5. tier
//! 6. risk class (R4 → STRICT_MODE_REQUIRED unconditionally)
//! 7. tool (registry hash mismatch → REGISTRY_VERSION_MISMATCH; bitmap
//!    miss → TOOL_NOT_ALLOWED)
//! 8. operation mask
//! 9. resource trie
//! 10. sequence (atomic CAS)
//! 11. budget (atomic decrement, rolls back sequence on failure)
//! 12. approval rules (Escalate → APPROVAL_REQUIRED, Deny → DENIED_BY_RULE)
//! 13. emit decision event (durability mode handled in chunks 8-9)
//!
//! Both Allow and Deny decisions carry `event_mac` (the receipt stream
//! records every decision for audit).
//!
//! `VerifierContext` bundles the verifier-side state the spec calls out
//! as external (`local_instance_hash`, `current_time_ns`,
//! `local_revocation_epoch`, `local_attested_tier`). Allocated once at
//! verifier startup, passed by reference to every `aps_check` call.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::action::ActionDescriptor;
use crate::compiled::CompiledAuthority;
use crate::decision::{Decision, DecisionType, ReasonCode};
use crate::durability::{NullSink, ReceiptSink};
use crate::passport::{ApprovalAction, Tier};

const R3_MAX_ANCHOR_AGE_NS: u64 = 30 * 1_000_000_000;

// -----------------------------------------------------------------------
// Clock trait
// -----------------------------------------------------------------------

/// Source of current time for the verifier. Abstracted so tests can
/// drive aps_check at arbitrary clock positions without touching the
/// real system clock.
pub trait Clock: Send + Sync {
    /// Current time in unix nanoseconds.
    fn now_unix_ns(&self) -> u64;
}

/// Real wall-clock source, backed by `std::time::SystemTime`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ns(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// Test-only manually-advanced clock.
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(initial_ns: u64) -> Self {
        ManualClock(AtomicU64::new(initial_ns))
    }
    pub fn set(&self, ns: u64) {
        self.0.store(ns, Ordering::Release);
    }
}

impl Clock for ManualClock {
    fn now_unix_ns(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

// -----------------------------------------------------------------------
// VerifierContext
// -----------------------------------------------------------------------

/// Verifier-side state held across all `aps_check` calls. Spec §9 names
/// the external helpers (`local_instance_hash`, `current_time_ns`,
/// `local_revocation_epoch`, `local_attested_tier`); they are bundled
/// here, alongside the chunk-8 [`ReceiptSink`] for the §9 step-13 emit.
pub struct VerifierContext<'a> {
    pub clock: &'a dyn Clock,
    pub verifier_instance_id_hash: [u8; 32],
    pub attested_tier: Tier,
    pub revocation_epoch: u32,
    /// Sink that receives Allow decisions per spec §9 step 13. Defaults
    /// to [`NullSink`] when constructed via `VerifierContext::new`;
    /// production use plugs in a [`crate::durability::ModeAReceiptSink`]
    /// or chunk-9 Mode B variant.
    pub receipt_sink: &'a dyn ReceiptSink,
    /// Monotonic decision-id counter. Encoded as the lower 8 bytes of
    /// each generated `decision_id`; the upper 8 bytes are zero in
    /// Prototype 1. Real-world deployments may swap for a UUID generator
    /// or randomness source.
    pub decision_id_counter: AtomicU64,
}

/// Singleton `NullSink` used by [`VerifierContext::new`] when no sink is
/// supplied. `'static` lifetime since it's a unit struct with no state.
static NULL_SINK: NullSink = NullSink;

impl<'a> VerifierContext<'a> {
    /// Construct with a [`NullSink`] receipt sink. Use
    /// [`VerifierContext::with_sink`] to wire a real durability mode.
    pub fn new(
        clock: &'a dyn Clock,
        verifier_instance_id_hash: [u8; 32],
        attested_tier: Tier,
        revocation_epoch: u32,
    ) -> Self {
        VerifierContext {
            clock,
            verifier_instance_id_hash,
            attested_tier,
            revocation_epoch,
            receipt_sink: &NULL_SINK,
            decision_id_counter: AtomicU64::new(0),
        }
    }

    /// Construct with an explicit receipt sink (Mode A / B1 / B2).
    pub fn with_sink(
        clock: &'a dyn Clock,
        verifier_instance_id_hash: [u8; 32],
        attested_tier: Tier,
        revocation_epoch: u32,
        receipt_sink: &'a dyn ReceiptSink,
    ) -> Self {
        VerifierContext {
            clock,
            verifier_instance_id_hash,
            attested_tier,
            revocation_epoch,
            receipt_sink,
            decision_id_counter: AtomicU64::new(0),
        }
    }

    fn next_decision_id(&self) -> [u8; 16] {
        let n = self.decision_id_counter.fetch_add(1, Ordering::Relaxed);
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&n.to_le_bytes());
        out
    }
}

// -----------------------------------------------------------------------
// aps_check
// -----------------------------------------------------------------------

/// Hot path: evaluate `action` against `authority` and return a signed
/// (event-MAC'd) `Decision`. Spec §9.
pub fn aps_check(
    authority: &CompiledAuthority,
    action: &ActionDescriptor,
    ctx: &VerifierContext,
) -> Decision {
    // Step 0: integrity.
    if !action.verify_action_hash() {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::ActionHashInvalid,
            action,
        );
    }

    // Step 1: instance binding.
    if authority.verifier_instance_id_hash != ctx.verifier_instance_id_hash {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::VerifierInstanceMismatch,
            action,
        );
    }

    // Step 2: temporal bounds.
    let now = ctx.clock.now_unix_ns();
    if now > authority.expires_at_unix_ns.saturating_add(authority.max_clock_skew_ns) {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::ExpiredPassport,
            action,
        );
    }
    let issued_floor = authority
        .issued_at_unix_ns
        .saturating_sub(authority.max_clock_skew_ns);
    if now < issued_floor {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::NotYetValid,
            action,
        );
    }

    // Step 3: R3+ time-anchor freshness.
    if action.risk_class >= 3 {
        let anchor = authority.last_time_anchor_ns.load(Ordering::Acquire);
        if now.saturating_sub(anchor) > R3_MAX_ANCHOR_AGE_NS {
            return finalize(
                ctx,
                authority,
                action.sequence_id,
                DecisionType::Deny,
                ReasonCode::ClockAnchorStale,
                action,
            );
        }
    }

    // Step 4: revocation freshness.
    if ctx.revocation_epoch < authority.revocation_epoch {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::StaleRevocationEpoch,
            action,
        );
    }

    // Step 5: tier.
    if (ctx.attested_tier as u8) < authority.minimum_tier_required {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::RiskTierTooLow,
            action,
        );
    }

    // Step 6: risk class.
    if action.risk_class > authority.risk_class {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::RiskClassExceeded,
            action,
        );
    }
    if action.risk_class >= 4 {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::StrictModeRequired,
            action,
        );
    }

    // Step 7: tool (registry hash + bitmap).
    let local_id = action.local_tool_id;
    match authority.tool_registry.get_by_id(local_id) {
        Some(hash) if hash == &action.tool_descriptor_hash => { /* match */ }
        _ => {
            return finalize(
                ctx,
                authority,
                action.sequence_id,
                DecisionType::Deny,
                ReasonCode::RegistryVersionMismatch,
                action,
            );
        }
    }
    if local_id as usize >= authority.allowed_tool_bitmap.capacity()
        || !authority.allowed_tool_bitmap.get(local_id)
    {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::ToolNotAllowed,
            action,
        );
    }

    // Step 8: operation mask.
    if action.operation_id >= 32
        || (authority.allowed_op_mask & (1u32 << action.operation_id)) == 0
    {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::OperationNotAllowed,
            action,
        );
    }

    // Step 9: resource trie.
    let path_depth = action.resource_path_depth as usize;
    let path = &action.resource_path_hashes[..path_depth.min(8)];
    let trie_match = match &authority.resource_trie {
        Some(trie) => trie.matches(path),
        None => false,
    };
    if !trie_match {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::ResourceOutOfScope,
            action,
        );
    }

    // Step 10a: recovery floor (spec §11.4). `recovered_floor` is 0
    // on fresh-start authorities so this gate is a no-op for sessions
    // that never crashed. After recovery, any `sequence_id <= floor`
    // means the action was already committed pre-crash; deny with
    // `SEQUENCE_RECOVERY_INVALID` rather than the general
    // `SEQUENCE_REPLAY` so the gateway can distinguish in audit.
    let floor = authority.recovered_floor.load(Ordering::Relaxed);
    if floor > 0 && action.sequence_id <= floor {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::SequenceRecoveryInvalid,
            action,
        );
    }

    // Step 10: sequence (atomic CAS).
    let expected = authority.sequence_next.load(Ordering::Acquire);
    if action.sequence_id != expected || action.sequence_id >= authority.sequence_end {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::SequenceReplay,
            action,
        );
    }
    if authority
        .sequence_next
        .compare_exchange(expected, expected + 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::SequenceReplay,
            action,
        );
    }

    // Step 11: budget (atomic decrement, rolls back sequence on failure).
    if !try_decrement_budget(authority, action.cost_units) {
        // Roll back the sequence advance: best-effort store of the prior
        // value. Under contention another action may already have moved
        // forward; in that case, we accept the higher value.
        let _ = authority.sequence_next.compare_exchange(
            expected + 1,
            expected,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        return finalize(
            ctx,
            authority,
            action.sequence_id,
            DecisionType::Deny,
            ReasonCode::BudgetExceeded,
            action,
        );
    }

    // Step 12: approval rules.
    for rule in &authority.approval_rules {
        if rule.matches(action) {
            return match rule.on_match {
                ApprovalAction::Escalate => finalize(
                    ctx,
                    authority,
                    action.sequence_id,
                    DecisionType::Escalate,
                    ReasonCode::ApprovalRequired,
                    action,
                ),
                ApprovalAction::Deny => finalize(
                    ctx,
                    authority,
                    action.sequence_id,
                    DecisionType::Deny,
                    ReasonCode::DeniedByRule,
                    action,
                ),
            };
        }
    }

    // Step 13: emit decision event per spec §9 LITERAL — Allow path
    // only. Deny and Escalate paths return at their respective steps
    // above and do NOT call emit. Spec §11.3 frames durability as
    // "independent of the decision itself", which arguably contradicts
    // §9's Allow-only emit; following the §9 literal here. If buffer
    // is full, that means the flush thread is starved (configuration
    // bug), so `expect` panics loudly — there is no internal-error
    // reason code in spec §7 to encode this otherwise.
    let decision = finalize(
        ctx,
        authority,
        action.sequence_id,
        DecisionType::Allow,
        ReasonCode::Ok,
        action,
    );
    ctx.receipt_sink
        .emit(&decision)
        .expect("receipt sink emit failed (buffer full or shutdown)");
    decision
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn try_decrement_budget(authority: &CompiledAuthority, cost_units: u32) -> bool {
    // Decrement the actions counter first; if cost_units check fails,
    // roll the actions counter back.
    let mut current_actions = authority.budget_remaining_actions.load(Ordering::Acquire);
    loop {
        if current_actions == 0 {
            return false;
        }
        match authority.budget_remaining_actions.compare_exchange(
            current_actions,
            current_actions - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(actual) => current_actions = actual,
        }
    }

    let cost = u64::from(cost_units);
    let mut current_cost = authority.budget_remaining_cost_units.load(Ordering::Acquire);
    loop {
        if current_cost < cost {
            authority.budget_remaining_actions.fetch_add(1, Ordering::AcqRel);
            return false;
        }
        match authority.budget_remaining_cost_units.compare_exchange(
            current_cost,
            current_cost - cost,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => current_cost = actual,
        }
    }
}

fn finalize(
    ctx: &VerifierContext,
    authority: &CompiledAuthority,
    sequence_id: u64,
    decision_type: DecisionType,
    reason_code: ReasonCode,
    action: &ActionDescriptor,
) -> Decision {
    let timestamp_ns = ctx.clock.now_unix_ns();
    let mut decision = Decision {
        decision_type,
        reason_code,
        reserved: [0u8; 6],
        sequence_id,
        decision_id: ctx.next_decision_id(),
        event_mac: [0u8; 32],
    };
    decision.finalize_mac(
        &authority.receipt_stream_key,
        &authority.passport_id_hash,
        &action.action_hash,
        timestamp_ns,
    );
    decision
}
