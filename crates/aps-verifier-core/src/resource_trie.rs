//! Section 8: resource-scope matcher.
//!
//! Reference shape is a trie walk over pre-hashed path components
//! (`u64` per component, depth 0..8). Spec permits alternative
//! structures (perfect hash, bloom + fallback) provided Section 8 hot
//! path properties hold; the chosen structure is selected by benchmark.
//!
//! Chunk 2 keeps `TrieNode` as a typed placeholder so
//! [`crate::compiled::CompiledAuthority`] can reserve the field. Chunk
//! 3 fills in construction and the `resource_trie_match` hot-path
//! function.

/// Resource-scope trie node. Fields are intentionally empty in chunk 2;
/// chunk 3 lands the construction and matching logic.
#[derive(Debug, Clone, Default)]
pub struct TrieNode {
    _placeholder: (),
}
