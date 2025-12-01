#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
pub fn ensure_full_tunnel(ifname: &str, server_ip: &str) {
    let out = Command::new("ip").args(["route", "show", "default"]).output();
    if let Ok(o) = out {
        if let Ok(s) = String::from_utf8(o.stdout) {
            let parts: Vec<&str> = s.split_whitespace().collect();
            if parts.len() >= 5 {
                let gw = parts[2];
                let dev = parts[4];
                let _ = Command::new("ip").args(["route", "add", &format!("{}/32", server_ip), "via", gw, "dev", dev]).output();
                let _ = Command::new("ip").args(["route", "replace", "default", "dev", ifname]).output();
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn ensure_full_tunnel(_ifname: &str, _server_ip: &str) {}
