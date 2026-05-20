//! Section 6: Decision result (packed binary, 64 bytes) and Section 7:
//! reason codes (`0x00`..`0x13`).
//!
//! TODO: keyed BLAKE3 event MAC per Section 6.1, and the canonical
//! decision-event byte concatenation
//! `passport_id_hash || action_hash || sequence_id || decision_type ||
//!  reason_code || decision_id || timestamp_unix_ns`.

#[repr(u8)]
pub enum DecisionType {
    Allow = 0,
    Deny = 1,
    Escalate = 2,
}

/// Reason codes (Section 7). Discriminants are normative.
#[repr(u8)]
pub enum ReasonCode {
    Ok = 0x00,
    ExpiredPassport = 0x01,
    NotYetValid = 0x02,
    StaleRevocationEpoch = 0x03,
    RegistryVersionMismatch = 0x04,
    ToolNotAllowed = 0x05,
    OperationNotAllowed = 0x06,
    ResourceOutOfScope = 0x07,
    RiskTierTooLow = 0x08,
    RiskClassExceeded = 0x09,
    BudgetExceeded = 0x0A,
    SequenceReplay = 0x0B,
    NonceReplay = 0x0C,
    ApprovalRequired = 0x0D,
    DeniedByRule = 0x0E,
    ActionHashInvalid = 0x0F,
    VerifierInstanceMismatch = 0x10,
    ClockAnchorStale = 0x11,
    SequenceRecoveryInvalid = 0x12,
    StrictModeRequired = 0x13,
}

/// Section 6 Decision result.
#[repr(C)]
pub struct Decision {
    pub decision_type: u8,
    pub reason_code: u8,
    pub reserved: [u8; 6],
    pub sequence_id: u64,
    pub decision_id: [u8; 16],
    pub event_mac: [u8; 32],
}
