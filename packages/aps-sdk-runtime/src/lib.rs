//! Stream B chunk 1: minimal FFI surface.
//!
//! Lands the napi-rs binding scaffold and ONE round-trip from
//! TypeScript into the Rust verifier crate: pass a passport JSON
//! string, parse it via `aps_verifier_core::RuntimePassport::from_json`,
//! return a typed summary struct.
//!
//! Subsequent chunks layer on: ActionDescriptor marshalling,
//! CompiledAuthority lifecycle, `aps_check` binding, ReceiptSink
//! wrappers, and the full TS API surface (`aps.loadPassport`,
//! `aps.check`, `aps.recoverSession`).

#![deny(clippy::all)]

use napi_derive::napi;

/// Summary of a parsed passport. Fields are a minimal subset chosen
/// to exercise the type-marshalling surface (string, integer, nested
/// scalar). Subsequent chunks expand this into the full passport
/// shape.
///
/// `sequence_start` and `sequence_end` are `i64` because JavaScript
/// `Number` cannot losslessly hold values above 2^53. Real passport
/// sequence IDs fit in i64 with margin; if a future use exceeds
/// that, switch to BigInt via napi's `BigInt` type.
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

/// Parse a passport JSON string and return a summary. Validates the
/// JSON structure and the chunk-1 structural checks
/// ([`aps_verifier_core::RuntimePassport::from_json`]) but does NOT
/// verify the Ed25519 signature; the signature path arrives in a
/// later chunk along with the gateway public-key parameter.
#[napi]
pub fn parse_passport_summary(json: String) -> napi::Result<PassportSummary> {
    let passport = aps_verifier_core::RuntimePassport::from_json(&json)
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
