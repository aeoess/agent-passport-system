//! Host environment capture.
//!
//! Spec §13.3 (Apple Silicon developer reference). This narrow Stream
//! C scope covers the pure-verifier benchmarks L0 and L1 only; the
//! storage-config logging requirements of §13.4 are Mode-B-specific
//! and land alongside the L3b1 / L3b2 benchmarks.

use std::process::Command;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EnvironmentSnapshot {
    pub label: String,
    pub spec_section: String,
    pub canonical: bool,
    pub host: Host,
}

#[derive(Debug, Clone, Serialize)]
pub struct Host {
    pub cpu_brand: String,
    pub cpu_arch: String,
    pub os_name: String,
    pub os_version: String,
    pub hostname: String,
    pub memory_bytes: u64,
}

/// Capture the current host environment. macOS-only in this narrow
/// scope; Linux and bare-metal capture land alongside the canonical
/// benchmark target.
pub fn capture_mac_apple_silicon() -> EnvironmentSnapshot {
    EnvironmentSnapshot {
        label: "mac-apple-silicon".into(),
        spec_section: "13.3".into(),
        canonical: false,
        host: Host {
            cpu_brand: sysctl_string("machdep.cpu.brand_string"),
            cpu_arch: shell_string("uname", &["-m"]),
            os_name: shell_string("sw_vers", &["-productName"]),
            os_version: shell_string("sw_vers", &["-productVersion"]),
            hostname: shell_string("hostname", &[]),
            memory_bytes: sysctl_string("hw.memsize").parse().unwrap_or(0),
        },
    }
}

fn sysctl_string(name: &str) -> String {
    shell_string("sysctl", &["-n", name])
}

fn shell_string(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into())
}
