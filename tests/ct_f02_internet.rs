use vpn_client::build_interface_config;
use vpn_client::config::{load_client_config, ensure_client_keys};

#[test]
fn ct_f02_full_tunnel_allowed_ips_includes_default_route() {
    let mut cfg = load_client_config(None).unwrap();
    let mut cfg = ensure_client_keys(cfg, None).unwrap();
    cfg.split_tunnel = false;
    let config = build_interface_config(&cfg, &cfg.interface_name).unwrap();
    let p = &config.peers[0];
    assert!(p.allowed_ips.iter().any(|ip| ip.to_string() == "0.0.0.0/0"));
}

