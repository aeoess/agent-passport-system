//! Chunk-3 tests for the resource-scope trie matcher (spec §8 / §11.1).

mod common;

use aps_verifier_core::{
    hash_path_component, parse_scope, CompiledAuthority, RuntimePassport, ToolRegistry, TrieNode,
};

use common::{hash_from_hex, PassportBuilder};

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn hash_path(components: &[&str]) -> Vec<u64> {
    components.iter().map(|c| hash_path_component(c)).collect()
}

fn scopes(strings: &[&str]) -> Vec<String> {
    strings.iter().map(|s| (*s).to_string()).collect()
}

const TOOL_HEX_0: &str = "abcd000000000000000000000000000000000000000000000000000000000000";

// -----------------------------------------------------------------------
// hash_path_component
// -----------------------------------------------------------------------

#[test]
fn hash_path_component_deterministic() {
    assert_eq!(
        hash_path_component("customer"),
        hash_path_component("customer")
    );
    assert_eq!(hash_path_component(""), hash_path_component(""));

    // Different strings → different hashes (probabilistically; the three
    // hand-picked strings here all collide with negligible probability).
    let a = hash_path_component("customer");
    let b = hash_path_component("invoice");
    let c = hash_path_component("vendor");
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}

// -----------------------------------------------------------------------
// parse_scope
// -----------------------------------------------------------------------

#[test]
fn parse_scope_exact() {
    let p = parse_scope("user/profile");
    assert_eq!(
        p.literal_components,
        vec![
            hash_path_component("user"),
            hash_path_component("profile"),
        ]
    );
    assert!(!p.has_wildcard_tail);
}

#[test]
fn parse_scope_wildcard_tail() {
    let p = parse_scope("customer/*");
    assert_eq!(p.literal_components, vec![hash_path_component("customer")]);
    assert!(p.has_wildcard_tail);
}

#[test]
fn parse_scope_global() {
    let p = parse_scope("*");
    assert!(p.literal_components.is_empty());
    assert!(p.has_wildcard_tail);
}

#[test]
fn parse_scope_trims_slashes() {
    let p1 = parse_scope("/customer/*/");
    let p2 = parse_scope("customer/*");
    assert_eq!(p1, p2);
}

// -----------------------------------------------------------------------
// TrieNode::matches
// -----------------------------------------------------------------------

#[test]
fn trie_empty_denies_all() {
    let trie = TrieNode::build(&[]);
    assert!(!trie.matches(&[]));
    assert!(!trie.matches(&hash_path(&["anything"])));
    assert!(!trie.matches(&hash_path(&["one", "two", "three"])));
}

#[test]
fn trie_exact_match() {
    let trie = TrieNode::build(&scopes(&["user/profile"]));
    assert!(trie.matches(&hash_path(&["user", "profile"])));
    assert!(!trie.matches(&hash_path(&["user", "other"])));
    assert!(!trie.matches(&hash_path(&["user"]))); // path shorter
    assert!(!trie.matches(&hash_path(&["user", "profile", "extra"]))); // longer, no wildcard
}

#[test]
fn trie_wildcard_tail_match() {
    let trie = TrieNode::build(&scopes(&["customer/*"]));
    assert!(trie.matches(&hash_path(&["customer"])));
    assert!(trie.matches(&hash_path(&["customer", "123"])));
    assert!(trie.matches(&hash_path(&["customer", "123", "orders"])));
    assert!(!trie.matches(&hash_path(&["other"])));
    assert!(!trie.matches(&[]));
}

#[test]
fn trie_global_wildcard() {
    let trie = TrieNode::build(&scopes(&["*"]));
    assert!(trie.matches(&[]));
    assert!(trie.matches(&hash_path(&["anything"])));
    assert!(trie.matches(&hash_path(&["anything", "deep", "path"])));
}

#[test]
fn trie_multiple_scopes() {
    let trie = TrieNode::build(&scopes(&[
        "customer/*",
        "invoice/vendor/acme/*",
        "user/profile",
    ]));

    assert!(trie.matches(&hash_path(&["customer", "123"])));
    assert!(trie.matches(&hash_path(&["invoice", "vendor", "acme", "123"])));
    assert!(trie.matches(&hash_path(&["user", "profile"])));

    assert!(!trie.matches(&hash_path(&["user", "profile", "extra"])));
    assert!(!trie.matches(&hash_path(&["invoice", "vendor", "other", "123"])));
    assert!(!trie.matches(&hash_path(&["unrelated"])));
}

#[test]
fn trie_match_path_depth_8() {
    // ActionDescriptor.resource_path_hashes is [u64; 8]; build a scope
    // that exercises the full depth.
    let trie = TrieNode::build(&scopes(&["a/b/c/d/e/f/g/h"]));
    let path = hash_path(&["a", "b", "c", "d", "e", "f", "g", "h"]);
    assert_eq!(path.len(), 8);
    assert!(trie.matches(&path));

    // One off any component must fail.
    let mut wrong = path.clone();
    wrong[7] = hash_path_component("X");
    assert!(!trie.matches(&wrong));
}

// -----------------------------------------------------------------------
// CompiledAuthority round-trip
// -----------------------------------------------------------------------

fn passport_with_scopes_and_root(scope_strings: &[&str], root: [u8; 32]) -> RuntimePassport {
    let json = PassportBuilder::new()
        .with_root(root)
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(scope_strings.to_vec())
        .build_json();
    RuntimePassport::from_json(&json).expect("parse passport")
}

#[test]
fn compiled_authority_has_resource_trie() {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    let root = reg.current_root();

    let passport = passport_with_scopes_and_root(
        &["customer/*", "invoice/vendor/acme/*"],
        root,
    );

    let auth = CompiledAuthority::from_passport(&passport, reg).expect("compile");
    let trie = auth.resource_trie.expect("resource_trie populated");

    assert!(trie.matches(&hash_path(&["customer", "12345"])));
    assert!(trie.matches(&hash_path(&["invoice", "vendor", "acme", "x"])));
    assert!(!trie.matches(&hash_path(&["random", "path"])));
}
