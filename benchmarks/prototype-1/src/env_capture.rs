//! Environment metadata capture for Mode B results.
//!
//! Spec reference: `specs/PROTOTYPE-1-RUNTIME-PASSPORT.md` Section 13.4
//! ("Required storage configuration logging for Mode B results").
//!
//! Without this metadata, Mode B numbers are not comparable across
//! environments, so every Mode B benchmark run MUST emit a populated
//! `EnvironmentSnapshot`.

/// Captures the Section 13.4 fields that must accompany every Mode B
/// number. All fields are required — `Option` is only used where the
/// underlying OS may genuinely not expose the value (e.g. power loss
/// protection on consumer hardware).
#[derive(Debug, Clone)]
pub struct EnvironmentSnapshot {
    /// Disk type and exact model string.
    pub disk_type_and_model: String,
    /// Filesystem and mount options (e.g. `ext4 data=ordered,noatime`).
    pub filesystem_and_mount_options: String,
    /// Fsync / group commit batch size.
    pub fsync_group_commit_batch_size: u32,
    /// Fsync / group commit window in microseconds.
    pub fsync_group_commit_window_us: u32,
    /// IOPS limit if cloud-provisioned (e.g. AWS gp3 default 3000).
    pub iops_limit: Option<u32>,
    /// Write cache enabled at the device level.
    pub write_cache_enabled: bool,
    /// Power loss protection if known (cloud / enterprise SSDs).
    pub power_loss_protection: Option<bool>,
    /// Sample size used for the published number.
    pub sample_size: u64,
    /// Statistical methodology (e.g. "criterion warm-up 3s, measure 10s,
    /// p50/p95/p99/p99.9 reported, 95% CI via bootstrap").
    pub methodology: String,
}

/// Capture the host environment by probing the OS. Implementations are
/// platform-specific (Linux: `/sys/block`, `/proc/mounts`, `lsblk`;
/// macOS: `diskutil`, `sysctl`).
pub fn capture() -> EnvironmentSnapshot {
    todo!(
        "Stream C env capture: probe disk model, filesystem and mount options, \
         IOPS limit, write cache, power loss protection. See spec Section 13.4."
    );
}

/// Validate that a snapshot has every field required for a publishable
/// Mode B number. Run before recording any L3b1 / L3b2 result.
pub fn validate_for_mode_b(_snapshot: &EnvironmentSnapshot) -> Result<(), String> {
    todo!(
        "Stream C: enforce Section 13.4 completeness. Reject if any required \
         field is missing or empty before persisting a Mode B result."
    );
}
