//! Chunk-5 tests for [`ToolRegistry`] + Merkle root + fetcher mock.

use aps_verifier_core::{
    MockRegistryFetcher, RegistryError, ToolEntry, ToolRegistry,
};

fn hash_from_byte(b: u8) -> [u8; 32] {
    [b; 32]
}

// Manually compute the canonical Merkle root for known small inputs, to
// pin the construction (verifier+gateway must agree byte-for-byte).
fn leaf_hash(local_id: u32, descriptor_hash: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 4 + 32];
    input[0..4].copy_from_slice(&local_id.to_le_bytes());
    input[4..36].copy_from_slice(descriptor_hash);
    *blake3::hash(&input).as_bytes()
}

fn pair_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[0..32].copy_from_slice(left);
    input[32..64].copy_from_slice(right);
    *blake3::hash(&input).as_bytes()
}

#[test]
fn registry_empty_root_well_defined() {
    let reg = ToolRegistry::new();
    let expected = *blake3::hash(b"").as_bytes();
    assert_eq!(reg.current_root(), expected);
    assert_eq!(reg.size(), 0);
    assert_eq!(reg.max_local_id(), None);
}

#[test]
fn registry_add_then_lookup() {
    let mut reg = ToolRegistry::new();
    let h_a = hash_from_byte(0x11);
    let h_b = hash_from_byte(0x22);
    reg.add(h_a, 0).unwrap();
    reg.add(h_b, 1).unwrap();
    assert_eq!(reg.get_by_hash(&h_a), Some(0));
    assert_eq!(reg.get_by_hash(&h_b), Some(1));
    assert_eq!(reg.get_by_id(0), Some(&h_a));
    assert_eq!(reg.get_by_id(1), Some(&h_b));
    assert_eq!(reg.get_by_hash(&[0xFF; 32]), None);
    assert_eq!(reg.size(), 2);
    assert_eq!(reg.max_local_id(), Some(1));
}

#[test]
fn registry_root_deterministic() {
    let mut a = ToolRegistry::new();
    a.add(hash_from_byte(0x11), 0).unwrap();
    a.add(hash_from_byte(0x22), 1).unwrap();
    let mut b = ToolRegistry::new();
    b.add(hash_from_byte(0x11), 0).unwrap();
    b.add(hash_from_byte(0x22), 1).unwrap();
    assert_eq!(a.current_root(), b.current_root());
}

#[test]
fn registry_root_order_independent_via_local_id() {
    let mut asc = ToolRegistry::new();
    asc.add(hash_from_byte(0x11), 0).unwrap();
    asc.add(hash_from_byte(0x22), 1).unwrap();
    let mut desc = ToolRegistry::new();
    desc.add(hash_from_byte(0x22), 1).unwrap();
    desc.add(hash_from_byte(0x11), 0).unwrap();
    assert_eq!(asc.current_root(), desc.current_root());
}

#[test]
fn registry_root_changes_on_mutation() {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_byte(0x11), 0).unwrap();
    let after_one = reg.current_root();
    reg.add(hash_from_byte(0x22), 1).unwrap();
    let after_two = reg.current_root();
    assert_ne!(after_one, after_two);
}

#[test]
fn registry_duplicate_local_id_rejected() {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_byte(0x11), 0).unwrap();
    match reg.add(hash_from_byte(0x22), 0) {
        Err(RegistryError::DuplicateLocalId(0)) => {}
        other => panic!("expected DuplicateLocalId(0), got {other:?}"),
    }
}

#[test]
fn registry_duplicate_descriptor_hash_rejected() {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_byte(0x11), 0).unwrap();
    match reg.add(hash_from_byte(0x11), 1) {
        Err(RegistryError::DuplicateDescriptorHash) => {}
        other => panic!("expected DuplicateDescriptorHash, got {other:?}"),
    }
}

#[test]
fn registry_from_entries_sorts() {
    let entries = vec![
        ToolEntry { descriptor_hash: hash_from_byte(0x33), local_id: 2 },
        ToolEntry { descriptor_hash: hash_from_byte(0x11), local_id: 0 },
        ToolEntry { descriptor_hash: hash_from_byte(0x22), local_id: 1 },
    ];
    let reg = ToolRegistry::from_entries(entries).unwrap();
    assert_eq!(reg.size(), 3);
    assert_eq!(reg.get_by_id(0), Some(&hash_from_byte(0x11)));
    assert_eq!(reg.get_by_id(1), Some(&hash_from_byte(0x22)));
    assert_eq!(reg.get_by_id(2), Some(&hash_from_byte(0x33)));
    assert_eq!(reg.max_local_id(), Some(2));
}

#[test]
fn registry_sync_with_mock() {
    let entries = vec![
        ToolEntry { descriptor_hash: hash_from_byte(0xAA), local_id: 0 },
        ToolEntry { descriptor_hash: hash_from_byte(0xBB), local_id: 1 },
        ToolEntry { descriptor_hash: hash_from_byte(0xCC), local_id: 2 },
    ];
    let fetcher = MockRegistryFetcher::new(entries);
    let mut reg = ToolRegistry::new();
    let new_root = reg.sync(&fetcher).expect("sync ok");

    assert_eq!(reg.size(), 3);
    assert_eq!(reg.get_by_hash(&hash_from_byte(0xAA)), Some(0));
    assert_eq!(reg.get_by_hash(&hash_from_byte(0xBB)), Some(1));
    assert_eq!(reg.get_by_hash(&hash_from_byte(0xCC)), Some(2));
    assert_eq!(reg.current_root(), new_root);
    assert_ne!(new_root, *blake3::hash(b"").as_bytes());
}

#[test]
fn registry_sync_replaces_existing() {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_byte(0x11), 0).unwrap();
    reg.add(hash_from_byte(0x22), 1).unwrap();
    assert_eq!(reg.size(), 2);

    let fresh = vec![
        ToolEntry { descriptor_hash: hash_from_byte(0xAA), local_id: 0 },
        ToolEntry { descriptor_hash: hash_from_byte(0xBB), local_id: 1 },
        ToolEntry { descriptor_hash: hash_from_byte(0xCC), local_id: 2 },
    ];
    let fetcher = MockRegistryFetcher::new(fresh);
    reg.sync(&fetcher).unwrap();

    assert_eq!(reg.size(), 3);
    assert_eq!(reg.get_by_hash(&hash_from_byte(0x11)), None);
    assert_eq!(reg.get_by_hash(&hash_from_byte(0xAA)), Some(0));
}

// -----------------------------------------------------------------------
// Merkle layout pinning
// -----------------------------------------------------------------------

#[test]
fn merkle_root_known_value_single_entry() {
    let mut reg = ToolRegistry::new();
    let h = [0x01u8; 32];
    reg.add(h, 0).unwrap();
    let expected = leaf_hash(0, &h);
    assert_eq!(reg.current_root(), expected);
}

#[test]
fn merkle_root_two_entries() {
    let mut reg = ToolRegistry::new();
    let h_a = hash_from_byte(0x11);
    let h_b = hash_from_byte(0x22);
    reg.add(h_a, 0).unwrap();
    reg.add(h_b, 1).unwrap();

    let leaf_a = leaf_hash(0, &h_a);
    let leaf_b = leaf_hash(1, &h_b);
    let expected = pair_hash(&leaf_a, &leaf_b);
    assert_eq!(reg.current_root(), expected);
}

#[test]
fn merkle_root_odd_count_duplicates_last() {
    let mut reg = ToolRegistry::new();
    let h_a = hash_from_byte(0x11);
    let h_b = hash_from_byte(0x22);
    let h_c = hash_from_byte(0x33);
    reg.add(h_a, 0).unwrap();
    reg.add(h_b, 1).unwrap();
    reg.add(h_c, 2).unwrap();

    let leaf_a = leaf_hash(0, &h_a);
    let leaf_b = leaf_hash(1, &h_b);
    let leaf_c = leaf_hash(2, &h_c);

    // Level 1 has 3 leaves; duplicate c, giving pairs (a,b) and (c,c).
    let ab = pair_hash(&leaf_a, &leaf_b);
    let cc = pair_hash(&leaf_c, &leaf_c);
    let expected = pair_hash(&ab, &cc);
    assert_eq!(reg.current_root(), expected);
}
