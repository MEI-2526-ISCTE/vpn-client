use vpn_client::build_interface_config;
use vpn_client::config::{ClientConfig, load_client_config, ensure_client_keys};

#[test]
fn ct_f01_simple_client_connection_config_builds() {
    let mut cfg = load_client_config(None).unwrap();
    let cfg = ensure_client_keys(cfg, None).unwrap();
    let ifname = cfg.interface_name.clone();
    let config = build_interface_config(&cfg, &ifname).unwrap();
    assert_eq!(config.name, ifname);
    assert_eq!(config.peers.len(), 1);
    let p = &config.peers[0];
    assert!(p.endpoint.is_some());
    assert!(p.persistent_keepalive_interval.is_some());
}

