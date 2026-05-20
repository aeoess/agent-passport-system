//! Section 4: Runtime Passport wire format (JSON, JCS-canonicalized,
//! Ed25519-signed by gateway). Parsed into a typed representation before
//! compilation into a [`crate::compiled::CompiledAuthority`].
//!
//! TODO: full JCS canonicalization, signature verification at load, and
//! mapping of `authority_blob.allowed_tools` (descriptor hashes) into
//! local integer tool IDs per Section 4.4 / Section 11.1.

/// Parsed Runtime Passport, Section 4 wire format.
///
/// Field set is intentionally incomplete in this skeleton; the full shape
/// is fixed by Section 4 of the spec.
pub struct RuntimePassport {
    pub passport_id: String,
    pub issued_at_unix_ns: u64,
    pub expires_at_unix_ns: u64,
    pub max_clock_skew_ms: u32,
    pub revocation_epoch: u32,
    pub risk_class: u8,
    pub minimum_tier_required: u8,
    pub tier_attested: u8,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub signature: [u8; 64],
}
