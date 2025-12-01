use vpn_client::build_interface_config;
use vpn_client::config::{load_client_config, ensure_client_keys};

#[test]
fn ct_f03_split_tunnel_allowed_ips_is_vpn_range() {
    let mut cfg = load_client_config(None).unwrap();
    let mut cfg = ensure_client_keys(cfg, None).unwrap();
    cfg.split_tunnel = true;
    let config = build_interface_config(&cfg, &cfg.interface_name).unwrap();
    let p = &config.peers[0];
    assert!(p.allowed_ips.iter().any(|ip| ip.to_string() == "10.8.0.0/24"));
}

