//! Section 5: Action Descriptor wire format. Packed canonical binary,
//! 204 bytes, field-by-field serialization, no implicit padding.
//!
//! TODO: implement zero-copy parsing, `action_hash` computation per
//! Section 5.1 (`BLAKE3(bytes[0..172])`), and nonce-LRU defense-in-depth
//! per Section 5.3 (optional in Prototype 1, required if relaxed-sequence
//! modes ship later).

pub const ACTION_DESCRIPTOR_BYTES: usize = 204;

/// Decoded Action Descriptor, Section 5 wire format.
#[repr(C)]
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
