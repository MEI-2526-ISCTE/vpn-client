#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
pub fn snapshot_default() -> Option<(String, String)> {
    let out = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 5 { Some((parts[2].to_string(), parts[4].to_string())) } else { None }
}

#[cfg(target_os = "linux")]
pub fn host_route_to_endpoint(server_ip: &str, gw: &str, dev: &str) {
    let _ = Command::new("ip").args(["route", "add", &format!("{}/32", server_ip), "via", gw, "dev", dev]).output();
}

#[cfg(target_os = "linux")]
pub fn restore_default(_gw_dev: &Option<(String, String)>) {
    // default route remains managed by WireGuard allowed IPs; no change needed
}

#[cfg(not(target_os = "linux"))]
pub fn snapshot_default() -> Option<(String, String)> { None }

#[cfg(not(target_os = "linux"))]
pub fn host_route_to_endpoint(_server_ip: &str, _gw: &str, _dev: &str) {}

#[cfg(not(target_os = "linux"))]
pub fn restore_default(_gw_dev: &Option<(String, String)>) {}
