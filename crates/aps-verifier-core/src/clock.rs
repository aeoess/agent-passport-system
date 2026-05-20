//! Section 11.2: clock-skew tolerance with risk-class-aware soft
//! degradation.
//!
//! Spec rule (§11.2):
//!
//! - R0..R2: verifier continues to execute against a valid passport
//!   even without fresh time anchors, bounded by `expires_at +
//!   max_clock_skew_ms`. The bounded passport lifetime (§10) caps
//!   partition-attack damage.
//! - R3: requires a time anchor fresher than 30 seconds. Returns
//!   `CLOCK_ANCHOR_STALE` (reason 0x11) if older. Combined with the
//!   30-second R3 passport lifetime this effectively requires
//!   real-time gateway connectivity.
//! - R4: out of Prototype 1 scope; the hot path returns
//!   `STRICT_MODE_REQUIRED` (reason 0x13).
//!
//! Anchor signature verification is deferred to chunk 6 (with the
//! crypto layer). Chunk 5 carries the signature opaquely.

use thiserror::Error;

/// Maximum age of a clock anchor for an R3 action, per spec §11.2.
pub const R3_MAX_ANCHOR_AGE_NS: u64 = 30 * 1_000_000_000;

/// Gateway-issued clock anchor. The verifier polls these periodically
/// and surfaces freshness via [`time_anchor_freshness`].
#[derive(Debug, Clone)]
pub struct ClockAnchor {
    /// Gateway-claimed timestamp in unix nanoseconds.
    pub timestamp_ns: u64,
    /// Ed25519 signature over `timestamp_ns.to_le_bytes()`. Verification
    /// lands with the crypto layer in chunk 6.
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ClockError {
    #[error("poller error: {0}")]
    Poller(String),
    #[error("clock anchor signature invalid")]
    SignatureInvalid,
    #[error("signature decoding failed: {0}")]
    SignatureDecode(String),
}

impl ClockAnchor {
    /// Verify the Ed25519 signature on the anchor's `timestamp_ns`.
    /// The signed message is the 8 little-endian bytes of `timestamp_ns`.
    pub fn verify_signature(
        &self,
        gateway_public_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), ClockError> {
        if self.signature.len() != 64 {
            return Err(ClockError::SignatureDecode(format!(
                "expected 64-byte Ed25519 signature, got {} bytes",
                self.signature.len()
            )));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let message = self.timestamp_ns.to_le_bytes();
        gateway_public_key
            .verify_strict(&message, &sig)
            .map_err(|_| ClockError::SignatureInvalid)
    }
}

/// Polls the gateway for fresh clock anchors. The HTTPS-backed
/// implementation lands in chunk 6.
pub trait ClockAnchorPoller {
    fn poll_anchor(&self) -> Result<ClockAnchor, ClockError>;
}

/// Test-only poller that returns a pre-canned anchor.
#[derive(Debug, Clone)]
pub struct MockClockAnchorPoller {
    anchor: ClockAnchor,
}

impl MockClockAnchorPoller {
    pub fn new(anchor: ClockAnchor) -> Self {
        MockClockAnchorPoller { anchor }
    }
}

impl ClockAnchorPoller for MockClockAnchorPoller {
    fn poll_anchor(&self) -> Result<ClockAnchor, ClockError> {
        Ok(self.anchor.clone())
    }
}

/// Result of a freshness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessVerdict {
    /// Anchor is fresh enough for the action's risk class.
    Fresh,
    /// Anchor is too stale for the action's risk class.
    Stale,
    /// Freshness is not required for this risk class (R0..R2 per spec
    /// §11.2 soft degradation).
    NotRequired,
}

/// Decide whether the verifier's last received gateway time anchor is
/// fresh enough for an action of `risk_class`.
///
/// - R0..R2 → [`FreshnessVerdict::NotRequired`].
/// - R3 → [`FreshnessVerdict::Fresh`] when
///   `now_ns - last_anchor_ns < R3_MAX_ANCHOR_AGE_NS` (saturating
///   subtract); else [`FreshnessVerdict::Stale`].
/// - R4 → always [`FreshnessVerdict::Stale`] (the hot path is expected
///   to translate this into `STRICT_MODE_REQUIRED`).
/// - Any out-of-range risk class → [`FreshnessVerdict::Stale`]
///   (defensive).
///
/// Backward clock skew (`now_ns < last_anchor_ns`) is handled
/// conservatively: saturating subtract returns 0, yielding `Fresh` for
/// R3. The assumption is that if local time has drifted behind the
/// gateway anchor, the anchor was effectively received "in the future"
/// from local time's perspective and we should not penalize it.
pub fn time_anchor_freshness(
    last_anchor_ns: u64,
    now_ns: u64,
    risk_class: u8,
) -> FreshnessVerdict {
    match risk_class {
        0..=2 => FreshnessVerdict::NotRequired,
        3 => {
            let age = now_ns.saturating_sub(last_anchor_ns);
            if age < R3_MAX_ANCHOR_AGE_NS {
                FreshnessVerdict::Fresh
            } else {
                FreshnessVerdict::Stale
            }
        }
        _ => FreshnessVerdict::Stale,
    }
}
