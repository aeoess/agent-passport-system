//! Section 8 and Section 11.1: resource-scope matcher for the compiled
//! authority hot path.
//!
//! Implementation: hashed-component radix trie. The
//! [`ActionDescriptor::resource_path_hashes`](crate::action::ActionDescriptor::resource_path_hashes)
//! field is 8 `u64` slots of pre-hashed path components; the SDK
//! computes these via [`hash_path_component`] (also defined here, so
//! the verifier and SDK share the exact same canonical hash). At
//! `aps_check` time the verifier walks the trie against the first
//! `action.resource_path_depth` slots.
//!
//! Scope syntax (Prototype 1):
//!
//! - `/` separates components.
//! - Leading and trailing `/` are trimmed.
//! - A trailing `*` matches any path at this depth or deeper.
//! - `*` alone (after trimming) matches everything.
//! - Mid-path wildcards are NOT supported in Prototype 1 (deferred to
//!   Phase 2).
//!
//! Examples:
//!
//! | Scope                  | Literal components            | Wildcard tail |
//! | ---------------------- | ----------------------------- | ------------- |
//! | `customer/*`           | `[h("customer")]`             | yes           |
//! | `invoice/vendor/acme/*`| `[h("invoice"),h("vendor"),h("acme")]` | yes  |
//! | `user/profile`         | `[h("user"),h("profile")]`    | no            |
//! | `*`                    | `[]`                          | yes           |
//!
//! Storage: each [`TrieNode`] holds children as a small sorted `Vec<(u64,
//! Box<TrieNode>)>`. Hot-path lookup is binary search on the sorted
//! children. For typical scope counts (<32 per passport) the cache
//! effects of the small Vec beat a `HashMap` at this size. Phase 2
//! optimization work will benchmark against alternative structures
//! (perfect hash, bloom + fallback); this is the Prototype 1 choice.

// -----------------------------------------------------------------------
// Path component hashing
// -----------------------------------------------------------------------

/// Canonical path-component hash. BLAKE3 of the UTF-8 bytes; take the
/// first 8 bytes and interpret as little-endian `u64`. The SDK MUST
/// produce the same value when populating
/// `ActionDescriptor.resource_path_hashes`.
pub fn hash_path_component(component: &str) -> u64 {
    let h = blake3::hash(component.as_bytes());
    let bytes = h.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

// -----------------------------------------------------------------------
// Scope parsing
// -----------------------------------------------------------------------

/// Parsed form of a single resource scope string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedScope {
    /// Pre-hashed literal components (everything except a trailing `*`).
    pub literal_components: Vec<u64>,
    /// True if the scope ends with a `/*` (or is the bare `*`).
    pub has_wildcard_tail: bool,
}

/// Parse a scope string into [`ParsedScope`]. Trims leading/trailing
/// slashes. Empty input parses as `{[], false}` (deny-only marker; no
/// path matches it, but `TrieNode::insert` tolerates it gracefully).
pub fn parse_scope(scope: &str) -> ParsedScope {
    let trimmed = scope.trim_matches('/');
    if trimmed.is_empty() {
        return ParsedScope {
            literal_components: Vec::new(),
            has_wildcard_tail: false,
        };
    }
    let parts: Vec<&str> = trimmed.split('/').filter(|p| !p.is_empty()).collect();
    let (literals, has_wildcard_tail) = match parts.split_last() {
        Some((last, head)) if *last == "*" => (head.to_vec(), true),
        _ => (parts, false),
    };
    ParsedScope {
        literal_components: literals.iter().map(|c| hash_path_component(c)).collect(),
        has_wildcard_tail,
    }
}

// -----------------------------------------------------------------------
// Trie
// -----------------------------------------------------------------------

/// Resource-scope trie node. Each node tracks its children plus two
/// accept flags: `is_terminal` (exact match) and `has_wildcard_tail`
/// (any deeper path also accepts).
#[derive(Debug, Clone, Default)]
pub struct TrieNode {
    /// Sorted by `u64` hash. Binary search at match time.
    children: Vec<(u64, Box<TrieNode>)>,
    /// This node terminates an exact-match scope.
    is_terminal: bool,
    /// This node also accepts any deeper path (trailing-`*` scope).
    has_wildcard_tail: bool,
}

impl TrieNode {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a trie from a slice of scope strings.
    pub fn build(scopes: &[String]) -> Self {
        let mut root = TrieNode::new();
        for s in scopes {
            root.insert(parse_scope(s));
        }
        root
    }

    /// Insert one parsed scope into the trie.
    pub fn insert(&mut self, scope: ParsedScope) {
        let mut node = self;
        for h in &scope.literal_components {
            let idx = match node.children.binary_search_by_key(h, |(k, _)| *k) {
                Ok(i) => i,
                Err(i) => {
                    node.children.insert(i, (*h, Box::new(TrieNode::new())));
                    i
                }
            };
            node = &mut node.children[idx].1;
        }
        if scope.has_wildcard_tail {
            node.has_wildcard_tail = true;
        } else {
            node.is_terminal = true;
        }
    }

    /// Match a path (slice of pre-hashed components) against the trie.
    /// Returns `true` if any scope in the trie covers the path.
    pub fn matches(&self, path: &[u64]) -> bool {
        let mut node = self;
        for (i, h) in path.iter().enumerate() {
            if node.has_wildcard_tail {
                // Trailing-`*` at this node covers anything from here on.
                // Includes the global `*` case (root with no literals and
                // wildcard_tail set).
                let _ = i;
                return true;
            }
            match node.children.binary_search_by_key(h, |(k, _)| *k) {
                Ok(idx) => node = &node.children[idx].1,
                Err(_) => return false,
            }
        }
        // Path fully consumed. Accept on exact-terminal or wildcard at
        // the current depth.
        node.is_terminal || node.has_wildcard_tail
    }
}
