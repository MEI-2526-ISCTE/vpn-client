#[cfg(target_os = "linux")]
use std::process::Command;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct DnsSnapshot {
    pub resolv_conf: Option<String>,
}

/**
 * @brief Capture current DNS resolver configuration (Linux).
 * @return Snapshot of `/etc/resolv.conf` content.
 */
#[cfg(target_os = "linux")]
pub fn snapshot_dns() -> DnsSnapshot {
    let content = std::fs::read_to_string("/etc/resolv.conf").ok();
    DnsSnapshot { resolv_conf: content }
}

/**
 * @brief Apply full-tunnel DNS settings using systemd-resolved (Linux).
 * @param ifname Interface alias.
 */
#[cfg(target_os = "linux")]
pub fn apply_full_tunnel_dns(ifname: &str) {
    // Prefer systemd-resolved
    let _ = Command::new("resolvectl").args(["dns", ifname, "1.1.1.1", "8.8.8.8"]).output();
    let _ = Command::new("resolvectl").args(["domain", ifname, "~."]).output();
}

/**
 * @brief Restore DNS configuration from snapshot (Linux).
 * @param snapshot Previously captured DNS settings.
 */
#[cfg(target_os = "linux")]
pub fn restore_dns(snapshot: &DnsSnapshot) {
    if let Some(ref content) = snapshot.resolv_conf {
        let _ = std::fs::write("/etc/resolv.conf", content);
    }
}

/** @brief Capture DNS configuration (Windows stub). */
#[cfg(target_os = "windows")]
pub fn snapshot_dns() -> DnsSnapshot { DnsSnapshot { resolv_conf: None } }

/**
 * @brief Apply DNS servers on the interface (Windows best-effort).
 * @param ifname Interface alias.
 */
#[cfg(target_os = "windows")]
pub fn apply_full_tunnel_dns(ifname: &str) {
    // Set DNS servers on the interface; best-effort
    let _ = std::process::Command::new("powershell").args([
        "-Command",
        &format!("Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @('1.1.1.1','8.8.8.8')", ifname),
    ]).output();
}

/**
 * @brief Restore DNS settings to default (Windows).
 * @param ifname Interface alias.
 */
#[cfg(target_os = "windows")]
pub fn restore_dns(ifname: &str) {
    let _ = std::process::Command::new("powershell").args([
        "-Command",
        &format!("Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses", ifname),
    ]).output();
}
