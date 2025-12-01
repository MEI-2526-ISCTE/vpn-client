use vpn_client::build_interface_config;
use vpn_client::config::{load_client_config, ensure_client_keys};
use base64::Engine as _;

#[test]
fn ct_f01_simple_client_connection_config_builds() {
    let mut cfg = ensure_client_keys(load_client_config(None).unwrap(), None).unwrap();
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    cfg.server_public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
    cfg.server_endpoint = "127.0.0.1:51820".into();
    let ifname = cfg.interface_name.clone();
    let config = build_interface_config(&cfg, &ifname).unwrap();
    assert_eq!(config.name, ifname);
    assert_eq!(config.peers.len(), 1);
    let p = &config.peers[0];
    assert!(p.endpoint.is_some());
    assert!(p.persistent_keepalive_interval.is_some());
}
