//! Section 5: Action Descriptor wire format.
//!
//! Packed canonical binary, total 204 bytes, little-endian for all
//! multi-byte integer fields. Per spec §5 the struct layout below is
//! documentary; the wire bytes are authoritative. `to_bytes` and
//! `from_bytes` serialize field-by-field in declaration order without
//! relying on compiler layout or implicit padding.
//!
//! Field offsets (chunk 1 reference):
//!   0..1     version
//!   1..4     reserved
//!   4..36    passport_id_hash (BLAKE3 of passport_id)
//!   36..68   tool_descriptor_hash (BLAKE3 of canonical tool descriptor)
//!   68..72   local_tool_id (u32 LE)
//!   72..74   operation_id (u16 LE)
//!   74..76   resource_type (u16 LE)
//!   76..77   risk_class
//!   77..78   resource_path_depth
//!   78..80   reserved2
//!   80..84   cost_units (u32 LE)
//!   84..92   sequence_id (u64 LE)
//!   92..108  nonce
//!   108..172 resource_path_hashes (8 x u64 LE)
//!   172..204 action_hash (BLAKE3 over bytes 0..172, computed in chunk 2)
//!
//! action_hash verification is deferred: chunk 1 only validates depth,
//! risk_class range, and version.

use thiserror::Error;

pub const ACTION_DESCRIPTOR_SIZE: usize = 204;

/// Section 5 Action Descriptor. Layout shown is documentary; serde / wire
/// goes through `to_bytes` / `from_bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDescriptor {
    pub version: u8,
    pub reserved: [u8; 3],
    pub passport_id_hash: [u8; 32],
    pub tool_descriptor_hash: [u8; 32],
    pub local_tool_id: u32,
    pub operation_id: u16,
    pub resource_type: u16,
    pub risk_class: u8,
    pub resource_path_depth: u8,
    pub reserved2: [u8; 2],
    pub cost_units: u32,
    pub sequence_id: u64,
    pub nonce: [u8; 16],
    pub resource_path_hashes: [u64; 8],
    pub action_hash: [u8; 32],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ActionError {
    #[error("invalid version: {0} (chunk 1 accepts only 1)")]
    InvalidVersion(u8),
    #[error("invalid risk_class: {0} (must be 0..=4)")]
    InvalidRiskClass(u8),
    #[error("invalid resource_path_depth: {0} (must be 0..=8)")]
    InvalidPathDepth(u8),
    #[error("action_hash mismatch")]
    ActionHashInvalid,
}

/// Byte offset where `action_hash` begins inside the wire descriptor.
/// `compute_action_hash` hashes only the bytes preceding this.
pub const ACTION_HASH_OFFSET: usize = 172;

fn read_u16_le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ])
}

fn read_u64_le(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

impl ActionDescriptor {
    /// Serialize to 204 bytes in canonical wire form.
    pub fn to_bytes(&self) -> [u8; ACTION_DESCRIPTOR_SIZE] {
        let mut buf = [0u8; ACTION_DESCRIPTOR_SIZE];
        let mut off = 0;

        buf[off] = self.version;
        off += 1;
        buf[off..off + 3].copy_from_slice(&self.reserved);
        off += 3;
        buf[off..off + 32].copy_from_slice(&self.passport_id_hash);
        off += 32;
        buf[off..off + 32].copy_from_slice(&self.tool_descriptor_hash);
        off += 32;
        buf[off..off + 4].copy_from_slice(&self.local_tool_id.to_le_bytes());
        off += 4;
        buf[off..off + 2].copy_from_slice(&self.operation_id.to_le_bytes());
        off += 2;
        buf[off..off + 2].copy_from_slice(&self.resource_type.to_le_bytes());
        off += 2;
        buf[off] = self.risk_class;
        off += 1;
        buf[off] = self.resource_path_depth;
        off += 1;
        buf[off..off + 2].copy_from_slice(&self.reserved2);
        off += 2;
        buf[off..off + 4].copy_from_slice(&self.cost_units.to_le_bytes());
        off += 4;
        buf[off..off + 8].copy_from_slice(&self.sequence_id.to_le_bytes());
        off += 8;
        buf[off..off + 16].copy_from_slice(&self.nonce);
        off += 16;
        for h in &self.resource_path_hashes {
            buf[off..off + 8].copy_from_slice(&h.to_le_bytes());
            off += 8;
        }
        buf[off..off + 32].copy_from_slice(&self.action_hash);
        off += 32;

        debug_assert_eq!(off, ACTION_DESCRIPTOR_SIZE);
        buf
    }

    /// Compute the BLAKE3 hash of the first 172 bytes of the descriptor
    /// (every field except `action_hash` itself). Spec §5.1.
    pub fn compute_action_hash(&self) -> [u8; 32] {
        let buf = self.to_bytes();
        *blake3::hash(&buf[..ACTION_HASH_OFFSET]).as_bytes()
    }

    /// Set `action_hash` to the computed value over the other fields.
    /// Used by the SDK when building an ActionDescriptor.
    pub fn finalize(&mut self) {
        self.action_hash = self.compute_action_hash();
    }

    /// Return true if the stored `action_hash` matches what
    /// `compute_action_hash` produces over the other fields. Spec §9
    /// step 0 will call this on the hot path.
    pub fn verify_action_hash(&self) -> bool {
        self.compute_action_hash() == self.action_hash
    }

    /// Parse from a 204-byte canonical wire form. Validates structural
    /// integrity only (version, risk_class range, depth range);
    /// `action_hash` is parsed but NOT verified here. The hot path
    /// controls the ordering of cheap checks per spec §9, so this stays
    /// validation-of-format only.
    pub fn from_bytes(bytes: &[u8; ACTION_DESCRIPTOR_SIZE]) -> Result<Self, ActionError> {
        let version = bytes[0];
        if version != 1 {
            return Err(ActionError::InvalidVersion(version));
        }

        let mut reserved = [0u8; 3];
        reserved.copy_from_slice(&bytes[1..4]);
        let mut passport_id_hash = [0u8; 32];
        passport_id_hash.copy_from_slice(&bytes[4..36]);
        let mut tool_descriptor_hash = [0u8; 32];
        tool_descriptor_hash.copy_from_slice(&bytes[36..68]);
        let local_tool_id = read_u32_le(bytes, 68);
        let operation_id = read_u16_le(bytes, 72);
        let resource_type = read_u16_le(bytes, 74);

        let risk_class = bytes[76];
        if risk_class > 4 {
            return Err(ActionError::InvalidRiskClass(risk_class));
        }
        let resource_path_depth = bytes[77];
        if resource_path_depth > 8 {
            return Err(ActionError::InvalidPathDepth(resource_path_depth));
        }

        let mut reserved2 = [0u8; 2];
        reserved2.copy_from_slice(&bytes[78..80]);
        let cost_units = read_u32_le(bytes, 80);
        let sequence_id = read_u64_le(bytes, 84);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[92..108]);

        let mut resource_path_hashes = [0u64; 8];
        for (i, slot) in resource_path_hashes.iter_mut().enumerate() {
            *slot = read_u64_le(bytes, 108 + i * 8);
        }
        let mut action_hash = [0u8; 32];
        action_hash.copy_from_slice(&bytes[172..204]);

        Ok(ActionDescriptor {
            version,
            reserved,
            passport_id_hash,
            tool_descriptor_hash,
            local_tool_id,
            operation_id,
            resource_type,
            risk_class,
            resource_path_depth,
            reserved2,
            cost_units,
            sequence_id,
            nonce,
            resource_path_hashes,
            action_hash,
        })
    }
}
