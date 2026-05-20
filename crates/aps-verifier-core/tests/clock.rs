//! Chunk-5 tests for clock anchor, freshness, and `update_time_anchor`
//! on [`CompiledAuthority`].

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use aps_verifier_core::{
    time_anchor_freshness, ClockAnchor, ClockAnchorPoller, CompiledAuthority, FreshnessVerdict,
    MockClockAnchorPoller, RuntimePassport, ToolRegistry, R3_MAX_ANCHOR_AGE_NS,
};

use common::{hash_from_hex, PassportBuilder};

const TOOL_HEX_0: &str = "abcd000000000000000000000000000000000000000000000000000000000000";

fn make_authority() -> Arc<CompiledAuthority> {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    let root = reg.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(vec!["customer/*"])
        .build_json();
    let passport = RuntimePassport::from_json(&json).expect("parse");
    Arc::new(CompiledAuthority::from_passport(&passport, reg).expect("compile"))
}

// -----------------------------------------------------------------------
// ClockAnchor + mock poller
// -----------------------------------------------------------------------

#[test]
fn clock_anchor_construction() {
    let a = ClockAnchor {
        timestamp_ns: 1_000_000,
        signature: vec![],
    };
    assert_eq!(a.timestamp_ns, 1_000_000);
    assert!(a.signature.is_empty());
}

#[test]
fn mock_poller_returns_anchor() {
    let anchor = ClockAnchor {
        timestamp_ns: 42,
        signature: vec![1, 2, 3],
    };
    let poller = MockClockAnchorPoller::new(anchor);
    let got = poller.poll_anchor().unwrap();
    assert_eq!(got.timestamp_ns, 42);
    assert_eq!(got.signature, vec![1, 2, 3]);
}

// -----------------------------------------------------------------------
// Freshness
// -----------------------------------------------------------------------

#[test]
fn freshness_r0_not_required() {
    assert_eq!(
        time_anchor_freshness(0, 999_999_999_999_999, 0),
        FreshnessVerdict::NotRequired
    );
}

#[test]
fn freshness_r1_not_required() {
    assert_eq!(
        time_anchor_freshness(0, 999_999_999_999_999, 1),
        FreshnessVerdict::NotRequired
    );
}

#[test]
fn freshness_r2_not_required() {
    assert_eq!(
        time_anchor_freshness(0, 999_999_999_999_999, 2),
        FreshnessVerdict::NotRequired
    );
}

#[test]
fn freshness_r3_within_30s_fresh() {
    let now = 100_000_000_000;
    let anchor = now - 10_000_000_000; // 10s old
    assert_eq!(
        time_anchor_freshness(anchor, now, 3),
        FreshnessVerdict::Fresh
    );
}

#[test]
fn freshness_r3_at_30s_boundary_stale() {
    let now = 100_000_000_000;
    let anchor = now - R3_MAX_ANCHOR_AGE_NS; // exactly 30s old
    assert_eq!(
        time_anchor_freshness(anchor, now, 3),
        FreshnessVerdict::Stale
    );
}

#[test]
fn freshness_r3_beyond_30s_stale() {
    let now = 100_000_000_000;
    let anchor = now - 31_000_000_000; // 31s old
    assert_eq!(
        time_anchor_freshness(anchor, now, 3),
        FreshnessVerdict::Stale
    );
}

#[test]
fn freshness_r4_always_stale() {
    assert_eq!(time_anchor_freshness(0, 0, 4), FreshnessVerdict::Stale);
    assert_eq!(time_anchor_freshness(100, 100, 4), FreshnessVerdict::Stale);
}

#[test]
fn freshness_invalid_risk_class_stale() {
    assert_eq!(time_anchor_freshness(0, 0, 9), FreshnessVerdict::Stale);
}

#[test]
fn freshness_clock_skew_backward_treated_as_fresh() {
    // now < anchor (local clock drifted backward relative to gateway).
    let anchor = 200_000_000_000;
    let now = 100_000_000_000;
    assert_eq!(
        time_anchor_freshness(anchor, now, 3),
        FreshnessVerdict::Fresh,
        "backward skew should not penalize the anchor"
    );
}

// -----------------------------------------------------------------------
// CompiledAuthority::update_time_anchor
// -----------------------------------------------------------------------

#[test]
fn compiled_authority_initial_anchor_is_issued_at() {
    let auth = make_authority();
    let initial = auth.last_time_anchor_ns.load(Ordering::Acquire);
    assert_eq!(initial, auth.issued_at_unix_ns);
}

#[test]
fn compiled_authority_update_time_anchor_monotonic() {
    let auth = make_authority();
    let base = auth.last_time_anchor_ns.load(Ordering::Acquire);

    auth.update_time_anchor(base + 1_000);
    assert_eq!(auth.last_time_anchor_ns.load(Ordering::Acquire), base + 1_000);

    auth.update_time_anchor(base + 500);
    assert_eq!(
        auth.last_time_anchor_ns.load(Ordering::Acquire),
        base + 1_000,
        "older anchor must not move the atomic"
    );

    auth.update_time_anchor(base + 5_000);
    assert_eq!(auth.last_time_anchor_ns.load(Ordering::Acquire), base + 5_000);
}

#[test]
fn compiled_authority_update_time_anchor_concurrent() {
    let auth = make_authority();
    let base = auth.last_time_anchor_ns.load(Ordering::Acquire);
    let smaller = base + 1_000;
    let larger = base + 10_000;

    let a1 = Arc::clone(&auth);
    let a2 = Arc::clone(&auth);
    let t1 = thread::spawn(move || {
        for _ in 0..1000 {
            a1.update_time_anchor(smaller);
        }
    });
    let t2 = thread::spawn(move || {
        for _ in 0..1000 {
            a2.update_time_anchor(larger);
        }
    });
    t1.join().unwrap();
    t2.join().unwrap();

    let final_value = auth.last_time_anchor_ns.load(Ordering::Acquire);
    assert_eq!(
        final_value, larger,
        "max-monotonic CAS must end at the larger of the two"
    );
}
