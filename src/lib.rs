pub mod config;
use defguard_wireguard_rs::{host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration};
use base64::Engine as _;
use std::str::FromStr;

/**
 * @brief Build the WireGuard interface configuration for the client.
 * @param cfg Loaded client configuration (addresses, endpoint, keys, split/full tunnel).
 * @param ifname Interface name to create/use.
 * @return InterfaceConfiguration populated with one server peer and client settings.
 */
pub fn build_interface_config(cfg: &crate::config::ClientConfig, ifname: &str) -> Result<InterfaceConfiguration, Box<dyn std::error::Error>> {
    let server_pubkey_bytes = base64::engine::general_purpose::STANDARD.decode(&cfg.server_public_key_b64)?;
    if server_pubkey_bytes.len() != 32 { return Err("Server public key must decode to exactly 32 bytes".into()); }
    let server_pubkey = Key::new(server_pubkey_bytes.try_into().unwrap());
    let mut peer = Peer::new(server_pubkey);
    peer.endpoint = Some(cfg.server_endpoint.parse()?);
    peer.persistent_keepalive_interval = Some(cfg.keepalive_secs);
    if cfg.split_tunnel {
        peer.allowed_ips.push(IpAddrMask::from_str("10.8.0.0/24")?);
    } else {
        peer.allowed_ips.push(IpAddrMask::from_str("0.0.0.0/0")?);
    }
    let config = InterfaceConfiguration {
        name: ifname.to_string(),
        prvkey: cfg.client_private_key_b64.clone().ok_or("Missing client private key")?,
        addresses: vec![cfg.address_cidr.parse()?],
        port: 0,
        peers: vec![peer],
        mtu: None,
    };
    Ok(config)
}
