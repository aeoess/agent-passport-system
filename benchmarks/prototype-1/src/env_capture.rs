//! Host environment capture.
//!
//! Spec §13.1 (bare-metal Linux x86_64, canonical), §13.2 (AWS
//! c7i.2xlarge cloud reference), §13.3 (Apple Silicon developer
//! reference). Dispatches by target_os; on Linux, further dispatches
//! by DMI sys_vendor to distinguish AWS EC2 from bare metal.

#[cfg(target_os = "linux")]
use std::fs;
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

/// Unified entry point. Picks the right capture function based on
/// target_os and (on linux) the DMI sys_vendor.
pub fn capture() -> EnvironmentSnapshot {
    #[cfg(target_os = "macos")]
    {
        capture_mac_apple_silicon()
    }
    #[cfg(target_os = "linux")]
    {
        let sys_vendor = read_trim("/sys/class/dmi/id/sys_vendor");
        if sys_vendor == "Amazon EC2" {
            capture_aws_c7i()
        } else {
            capture_linux_baremetal()
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        compile_error!("env_capture: target_os not supported (need macos or linux)");
    }
}

/// macOS path (Apple M-series). §13.3 developer reference.
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

/// Bare-metal Linux x86_64 (§13.1 canonical). Acceptance gate:
/// `/sys/hypervisor/type` must be absent or empty. If a hypervisor is
/// detected, the function panics, because the §13.1 measurement is
/// only meaningful on bare metal.
#[cfg(target_os = "linux")]
pub fn capture_linux_baremetal() -> EnvironmentSnapshot {
    let hyper = read_trim("/sys/hypervisor/type");
    if !hyper.is_empty() && hyper != "none" {
        panic!(
            "env_capture: §13.1 requires bare metal; hypervisor detected: {hyper}"
        );
    }
    EnvironmentSnapshot {
        label: "bare-metal-linux".into(),
        spec_section: "13.1".into(),
        canonical: true,
        host: linux_host(),
    }
}

/// AWS EC2 c7i.2xlarge (§13.2 cloud reference). Acceptance gate:
/// IMDSv2 must report `instance-type == "c7i.2xlarge"`. Any other
/// instance type panics with the actual type named.
#[cfg(target_os = "linux")]
pub fn capture_aws_c7i() -> EnvironmentSnapshot {
    let instance_type = imdsv2_instance_type();
    if instance_type != "c7i.2xlarge" {
        panic!(
            "env_capture: §13.2 requires c7i.2xlarge; IMDSv2 reports: {instance_type}"
        );
    }
    EnvironmentSnapshot {
        label: "aws-c7i-gp3".into(),
        spec_section: "13.2".into(),
        canonical: false,
        host: linux_host(),
    }
}

#[cfg(target_os = "linux")]
fn linux_host() -> Host {
    Host {
        cpu_brand: cpuinfo_field("model name"),
        cpu_arch: shell_string("uname", &["-m"]),
        os_name: os_release_field("PRETTY_NAME"),
        os_version: shell_string("uname", &["-r"]),
        hostname: shell_string("hostname", &[]),
        memory_bytes: meminfo_total_bytes(),
    }
}

#[cfg(target_os = "linux")]
fn cpuinfo_field(name: &str) -> String {
    let body = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    for line in body.lines() {
        let mut parts = line.splitn(2, ':');
        let key = parts.next().unwrap_or("").trim();
        let val = parts.next().unwrap_or("").trim();
        if key == name {
            return val.to_string();
        }
    }
    "unknown".into()
}

#[cfg(target_os = "linux")]
fn meminfo_total_bytes() -> u64 {
    let body = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb_str = rest.trim().split_whitespace().next().unwrap_or("0");
            let kb: u64 = kb_str.parse().unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn os_release_field(name: &str) -> String {
    let body = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let prefix = format!("{name}=");
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return rest.trim_matches('"').to_string();
        }
    }
    "unknown".into()
}

/// Read a file's contents, trim whitespace, return empty string on
/// failure. Used for sysfs probes where missing files mean "not
/// present" rather than "error."
#[cfg(target_os = "linux")]
fn read_trim(path: &str) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// IMDSv2 instance-type lookup. Returns empty string if IMDSv2 is
/// unreachable (e.g. not on EC2). Caller decides whether that's an
/// acceptance failure.
#[cfg(target_os = "linux")]
fn imdsv2_instance_type() -> String {
    let token = Command::new("curl")
        .args([
            "-fsS",
            "-X",
            "PUT",
            "-H",
            "X-aws-ec2-metadata-token-ttl-seconds: 60",
            "http://169.254.169.254/latest/api/token",
        ])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    if token.is_empty() {
        return String::new();
    }
    Command::new("curl")
        .args([
            "-fsS",
            "-H",
            &format!("X-aws-ec2-metadata-token: {token}"),
            "http://169.254.169.254/latest/meta-data/instance-type",
        ])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
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
