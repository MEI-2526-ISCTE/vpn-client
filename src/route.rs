#[cfg(target_os = "linux")]
use std::process::Command;

/**
 * @brief Snapshot default route gateway and device (Linux only).
 * @return Optional pair `(gateway, device)`.
 */
#[cfg(target_os = "linux")]
pub fn snapshot_default() -> Option<(String, String)> {
    let out = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 5 { Some((parts[2].to_string(), parts[4].to_string())) } else { None }
}

/**
 * @brief Install a host route to the VPN endpoint to avoid recursive routing (Linux only).
 * @param server_ip Endpoint IP.
 * @param gw Gateway.
 * @param dev Device.
 */
#[cfg(target_os = "linux")]
pub fn host_route_to_endpoint(server_ip: &str, gw: &str, dev: &str) {
    let _ = Command::new("ip").args(["route", "add", &format!("{}/32", server_ip), "via", gw, "dev", dev]).output();
}

/**
 * @brief Restore default route if modified (Linux only).
 * @param _gw_dev Previous `(gateway, device)` snapshot.
 */
#[cfg(target_os = "linux")]
pub fn restore_default(_gw_dev: &Option<(String, String)>) {
    // default route remains managed by WireGuard allowed IPs; no change needed
}

/** @brief Snapshot default route (stub on non-Linux). */
#[cfg(not(target_os = "linux"))]
pub fn snapshot_default() -> Option<(String, String)> { None }

/** @brief Install host route to endpoint (stub on non-Linux). */
#[cfg(not(target_os = "linux"))]
pub fn host_route_to_endpoint(_server_ip: &str, _gw: &str, _dev: &str) {}

/** @brief Restore default route (stub on non-Linux). */
#[cfg(not(target_os = "linux"))]
pub fn restore_default(_gw_dev: &Option<(String, String)>) {}
