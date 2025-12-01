use vpn_client::build_interface_config;
use vpn_client::config::{load_client_config, ensure_client_keys};
use base64::Engine as _;

#[test]
fn ct_f02_full_tunnel_allowed_ips_includes_default_route() {
    let mut cfg = ensure_client_keys(load_client_config(None).unwrap(), None).unwrap();
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    cfg.server_public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
    cfg.server_endpoint = "127.0.0.1:51820".into();
    cfg.split_tunnel = false;
    let config = build_interface_config(&cfg, &cfg.interface_name).unwrap();
    let p = &config.peers[0];
    assert!(p.allowed_ips.iter().any(|ip| ip.to_string() == "0.0.0.0/0"));
}
