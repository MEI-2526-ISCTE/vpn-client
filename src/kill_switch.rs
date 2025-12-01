use std::process::Command;

pub fn apply_kill_switch(interface: &str) {
    if cfg!(target_os = "linux") {
        let _ = Command::new("iptables").args(["-P", "OUTPUT", "DROP"]).output();
        let _ = Command::new("iptables").args(["-A", "OUTPUT", "-o", interface, "-j", "ACCEPT"]).output();
    } else if cfg!(target_os = "windows") {
        let _ = Command::new("netsh").args(["advfirewall", "set", "allprofiles", "state", "on"]).output();
    }
}

pub fn revert_kill_switch(interface: &str) {
    if cfg!(target_os = "linux") {
        let _ = Command::new("iptables").args(["-P", "OUTPUT", "ACCEPT"]).output();
        let _ = Command::new("iptables").args(["-D", "OUTPUT", "-o", interface, "-j", "ACCEPT"]).output();
    } else if cfg!(target_os = "windows") {
        // No-op to avoid toggling global firewall state
    }
}
