//! Section 6: Decision result (packed binary, 64 bytes).
//! Section 7: 20 reason codes, exact hex discriminants.
//!
//! `event_mac` computation (§6.1, keyed BLAKE3 over the canonical
//! decision event) lands in chunk 2. Chunk 1 carries the MAC as an
//! opaque 32-byte field.

use thiserror::Error;

pub const DECISION_SIZE: usize = 64;

/// Section 6 decision kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DecisionType {
    Allow = 0,
    Deny = 1,
    Escalate = 2,
}

impl DecisionType {
    fn from_u8(v: u8) -> Result<Self, DecisionError> {
        match v {
            0 => Ok(DecisionType::Allow),
            1 => Ok(DecisionType::Deny),
            2 => Ok(DecisionType::Escalate),
            other => Err(DecisionError::InvalidDecisionType(other)),
        }
    }
}

/// Section 7 reason codes. Discriminant hex values are normative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl ReasonCode {
    fn from_u8(v: u8) -> Result<Self, DecisionError> {
        match v {
            0x00 => Ok(ReasonCode::Ok),
            0x01 => Ok(ReasonCode::ExpiredPassport),
            0x02 => Ok(ReasonCode::NotYetValid),
            0x03 => Ok(ReasonCode::StaleRevocationEpoch),
            0x04 => Ok(ReasonCode::RegistryVersionMismatch),
            0x05 => Ok(ReasonCode::ToolNotAllowed),
            0x06 => Ok(ReasonCode::OperationNotAllowed),
            0x07 => Ok(ReasonCode::ResourceOutOfScope),
            0x08 => Ok(ReasonCode::RiskTierTooLow),
            0x09 => Ok(ReasonCode::RiskClassExceeded),
            0x0A => Ok(ReasonCode::BudgetExceeded),
            0x0B => Ok(ReasonCode::SequenceReplay),
            0x0C => Ok(ReasonCode::NonceReplay),
            0x0D => Ok(ReasonCode::ApprovalRequired),
            0x0E => Ok(ReasonCode::DeniedByRule),
            0x0F => Ok(ReasonCode::ActionHashInvalid),
            0x10 => Ok(ReasonCode::VerifierInstanceMismatch),
            0x11 => Ok(ReasonCode::ClockAnchorStale),
            0x12 => Ok(ReasonCode::SequenceRecoveryInvalid),
            0x13 => Ok(ReasonCode::StrictModeRequired),
            other => Err(DecisionError::InvalidReasonCode(other)),
        }
    }
}

/// Section 6 Decision result. 64 bytes on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub decision_type: DecisionType,
    pub reason_code: ReasonCode,
    pub reserved: [u8; 6],
    pub sequence_id: u64,
    pub decision_id: [u8; 16],
    pub event_mac: [u8; 32],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecisionError {
    #[error("invalid decision_type: {0}")]
    InvalidDecisionType(u8),
    #[error("invalid reason_code: 0x{0:02X}")]
    InvalidReasonCode(u8),
}

/// Length of the canonical decision-event byte layout that feeds the
/// keyed BLAKE3 MAC. Spec §6.1:
/// `passport_id_hash(32) || action_hash(32) || sequence_id(8 LE) ||
/// decision_type(1) || reason_code(1) || decision_id(16) ||
/// timestamp_unix_ns(8 LE)`.
pub const CANONICAL_DECISION_EVENT_LEN: usize = 32 + 32 + 8 + 1 + 1 + 16 + 8;

/// Pack the canonical decision-event bytes (§6.1) into `buf`.
fn pack_canonical_event(
    decision: &Decision,
    passport_id_hash: &[u8; 32],
    action_hash: &[u8; 32],
    timestamp_ns: u64,
    buf: &mut [u8; CANONICAL_DECISION_EVENT_LEN],
) {
    buf[0..32].copy_from_slice(passport_id_hash);
    buf[32..64].copy_from_slice(action_hash);
    buf[64..72].copy_from_slice(&decision.sequence_id.to_le_bytes());
    buf[72] = decision.decision_type as u8;
    buf[73] = decision.reason_code as u8;
    buf[74..90].copy_from_slice(&decision.decision_id);
    buf[90..98].copy_from_slice(&timestamp_ns.to_le_bytes());
}

impl Decision {
    /// Compute the keyed BLAKE3 MAC over the canonical decision-event
    /// representation. Spec §6.1.
    pub fn compute_event_mac(
        &self,
        receipt_stream_key: &[u8; 32],
        passport_id_hash: &[u8; 32],
        action_hash: &[u8; 32],
        timestamp_ns: u64,
    ) -> [u8; 32] {
        let mut buf = [0u8; CANONICAL_DECISION_EVENT_LEN];
        pack_canonical_event(self, passport_id_hash, action_hash, timestamp_ns, &mut buf);
        let mut hasher = blake3::Hasher::new_keyed(receipt_stream_key);
        hasher.update(&buf);
        *hasher.finalize().as_bytes()
    }

    /// Set `event_mac` to the computed value over the supplied
    /// pre-hash inputs.
    pub fn finalize_mac(
        &mut self,
        receipt_stream_key: &[u8; 32],
        passport_id_hash: &[u8; 32],
        action_hash: &[u8; 32],
        timestamp_ns: u64,
    ) {
        self.event_mac =
            self.compute_event_mac(receipt_stream_key, passport_id_hash, action_hash, timestamp_ns);
    }

    /// True iff `event_mac` matches the value `compute_event_mac` would
    /// produce for these inputs.
    pub fn verify_event_mac(
        &self,
        receipt_stream_key: &[u8; 32],
        passport_id_hash: &[u8; 32],
        action_hash: &[u8; 32],
        timestamp_ns: u64,
    ) -> bool {
        self.event_mac
            == self.compute_event_mac(
                receipt_stream_key,
                passport_id_hash,
                action_hash,
                timestamp_ns,
            )
    }

    /// Serialize to the 64-byte canonical form.
    pub fn to_bytes(&self) -> [u8; DECISION_SIZE] {
        let mut buf = [0u8; DECISION_SIZE];
        buf[0] = self.decision_type as u8;
        buf[1] = self.reason_code as u8;
        buf[2..8].copy_from_slice(&self.reserved);
        buf[8..16].copy_from_slice(&self.sequence_id.to_le_bytes());
        buf[16..32].copy_from_slice(&self.decision_id);
        buf[32..64].copy_from_slice(&self.event_mac);
        buf
    }

    /// Parse from the 64-byte canonical form. Validates that
    /// decision_type and reason_code are spec-defined; carries
    /// `event_mac` opaquely until chunk 2 wires the MAC check.
    pub fn from_bytes(bytes: &[u8; DECISION_SIZE]) -> Result<Self, DecisionError> {
        let decision_type = DecisionType::from_u8(bytes[0])?;
        let reason_code = ReasonCode::from_u8(bytes[1])?;
        let mut reserved = [0u8; 6];
        reserved.copy_from_slice(&bytes[2..8]);
        let sequence_id = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let mut decision_id = [0u8; 16];
        decision_id.copy_from_slice(&bytes[16..32]);
        let mut event_mac = [0u8; 32];
        event_mac.copy_from_slice(&bytes[32..64]);

        Ok(Decision {
            decision_type,
            reason_code,
            reserved,
            sequence_id,
            decision_id,
            event_mac,
        })
    }
}
