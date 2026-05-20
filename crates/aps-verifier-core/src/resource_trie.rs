//! Section 8: resource-scope matcher.
//!
//! Reference shape is a trie walk over pre-hashed path components
//! (`u64` per component, depth 0..8). Spec permits alternative
//! structures (perfect hash, bloom + fallback) provided Section 8 hot
//! path properties hold; the chosen structure is selected by benchmark.
//!
//! TODO: trie construction at passport load, hot-path match against
//! `action.resource_path_hashes[0..resource_path_depth]`.

/// Trie node placeholder. Real layout lands with the matcher.
#[repr(C)]
pub struct TrieNode {
    _placeholder: [u8; 0],
}
