//! Section 4.4 and Section 11.1: tool registry consistency.
//!
//! Wire form is descriptor-hash addressing (`allowed_tools` carries
//! 32-byte BLAKE3 hashes; the verifier resolves them to local integer
//! ids at passport load). The Runtime Passport's `tool_registry_root`
//! field is the Merkle root of the registry version against which the
//! passport was compiled. The verifier MUST hold the matching registry
//! or refuse the passport (chunk 5 wires this check into
//! [`crate::compiled::CompiledAuthority::from_passport`]).
//!
//! Canonical Merkle layout (verifier and gateway MUST agree):
//!
//! - Entries are sorted by `local_id`.
//! - Each leaf is `BLAKE3(local_id_le_bytes || descriptor_hash)` (4 + 32
//!   bytes input).
//! - Internal nodes are `BLAKE3(left || right)`.
//! - At any level with an odd number of nodes, the last node is
//!   duplicated (standard convention).
//! - The empty registry has root `BLAKE3(<empty>)`.
//!
//! The HTTPS-backed fetcher with signature verification lands in chunk
//! 6; chunk 5 ships the trait and a mock implementation.

use std::collections::HashMap;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolEntry {
    pub descriptor_hash: [u8; 32],
    pub local_id: u32,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("duplicate local_id: {0}")]
    DuplicateLocalId(u32),
    #[error("duplicate descriptor hash")]
    DuplicateDescriptorHash,
    #[error("local_id {0} not found")]
    NotFound(u32),
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("fetcher error: {0}")]
    Fetcher(String),
    #[error("registry build error: {0}")]
    Build(#[from] RegistryError),
}

// -----------------------------------------------------------------------
// Fetcher trait + mock
// -----------------------------------------------------------------------

/// Fetch a current snapshot of the registry from the gateway.
pub trait RegistryFetcher {
    fn fetch_registry(&self) -> Result<Vec<ToolEntry>, String>;
}

/// Test-only fetcher: returns a pre-canned snapshot.
#[derive(Debug, Clone)]
pub struct MockRegistryFetcher {
    entries: Vec<ToolEntry>,
}

impl MockRegistryFetcher {
    pub fn new(entries: Vec<ToolEntry>) -> Self {
        MockRegistryFetcher { entries }
    }
}

impl RegistryFetcher for MockRegistryFetcher {
    fn fetch_registry(&self) -> Result<Vec<ToolEntry>, String> {
        Ok(self.entries.clone())
    }
}

// -----------------------------------------------------------------------
// ToolRegistry
// -----------------------------------------------------------------------

/// Descriptor-hash → local-integer-id table with cached Merkle root.
#[derive(Debug, Clone)]
pub struct ToolRegistry {
    /// Sorted by `local_id`. Stored sorted so the Merkle leaf order is
    /// deterministic given the entry set.
    entries: Vec<ToolEntry>,
    /// Descriptor hash → local_id lookup index.
    by_hash: HashMap<[u8; 32], u32>,
    /// Cached Merkle root; recomputed on every mutation.
    root: [u8; 32],
}

impl Default for ToolRegistry {
    fn default() -> Self {
        let root = compute_merkle_root(&[]);
        ToolRegistry {
            entries: Vec::new(),
            by_hash: HashMap::new(),
            root,
        }
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries(mut entries: Vec<ToolEntry>) -> Result<Self, RegistryError> {
        entries.sort_by_key(|e| e.local_id);
        // Duplicate detection in O(n) over the sorted vec.
        let mut by_hash: HashMap<[u8; 32], u32> = HashMap::with_capacity(entries.len());
        for w in entries.windows(2) {
            if w[0].local_id == w[1].local_id {
                return Err(RegistryError::DuplicateLocalId(w[0].local_id));
            }
        }
        for e in &entries {
            if by_hash.insert(e.descriptor_hash, e.local_id).is_some() {
                return Err(RegistryError::DuplicateDescriptorHash);
            }
        }
        let root = compute_merkle_root(&entries);
        Ok(ToolRegistry {
            entries,
            by_hash,
            root,
        })
    }

    pub fn add(
        &mut self,
        descriptor_hash: [u8; 32],
        local_id: u32,
    ) -> Result<(), RegistryError> {
        if self.entries.iter().any(|e| e.local_id == local_id) {
            return Err(RegistryError::DuplicateLocalId(local_id));
        }
        if self.by_hash.contains_key(&descriptor_hash) {
            return Err(RegistryError::DuplicateDescriptorHash);
        }
        let entry = ToolEntry {
            descriptor_hash,
            local_id,
        };
        let pos = self
            .entries
            .binary_search_by_key(&local_id, |e| e.local_id)
            .unwrap_or_else(|i| i);
        self.entries.insert(pos, entry);
        self.by_hash.insert(descriptor_hash, local_id);
        self.root = compute_merkle_root(&self.entries);
        Ok(())
    }

    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<u32> {
        self.by_hash.get(hash).copied()
    }

    pub fn get_by_id(&self, id: u32) -> Option<&[u8; 32]> {
        self.entries
            .binary_search_by_key(&id, |e| e.local_id)
            .ok()
            .map(|i| &self.entries[i].descriptor_hash)
    }

    pub fn current_root(&self) -> [u8; 32] {
        self.root
    }

    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Maximum `local_id` registered, or `None` if empty. Used by the
    /// compiler to size the allowed-tool bitmap.
    pub fn max_local_id(&self) -> Option<u32> {
        self.entries.last().map(|e| e.local_id)
    }

    /// Replace registry contents with a fresh snapshot from the fetcher.
    /// Returns the new root.
    pub fn sync<F: RegistryFetcher>(&mut self, fetcher: &F) -> Result<[u8; 32], SyncError> {
        let entries = fetcher.fetch_registry().map_err(SyncError::Fetcher)?;
        let fresh = ToolRegistry::from_entries(entries)?;
        *self = fresh;
        Ok(self.root)
    }
}

// -----------------------------------------------------------------------
// Merkle root
// -----------------------------------------------------------------------

fn leaf_hash(entry: &ToolEntry) -> [u8; 32] {
    let mut input = [0u8; 4 + 32];
    input[0..4].copy_from_slice(&entry.local_id.to_le_bytes());
    input[4..36].copy_from_slice(&entry.descriptor_hash);
    *blake3::hash(&input).as_bytes()
}

fn pair_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[0..32].copy_from_slice(left);
    input[32..64].copy_from_slice(right);
    *blake3::hash(&input).as_bytes()
}

/// Compute the canonical Merkle root over `entries`. Callers MUST
/// ensure `entries` is sorted by `local_id` (which `ToolRegistry`
/// maintains internally).
pub(crate) fn compute_merkle_root(entries: &[ToolEntry]) -> [u8; 32] {
    if entries.is_empty() {
        return *blake3::hash(b"").as_bytes();
    }
    let mut level: Vec<[u8; 32]> = entries.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            // Duplicate-last-node convention at an odd level.
            let last = *level.last().unwrap();
            level.push(last);
        }
        level = level
            .chunks(2)
            .map(|pair| pair_hash(&pair[0], &pair[1]))
            .collect();
    }
    level[0]
}
