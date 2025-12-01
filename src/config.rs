use serde::{Deserialize, Serialize};
use base64::Engine as _;
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub interface_name: String,
    pub address_cidr: String,
    pub server_endpoint: String,
    pub server_public_key_b64: String,
    pub keepalive_secs: u16,
    pub split_tunnel: bool,
    pub kill_switch: bool,
    pub client_private_key_b64: Option<String>,
    pub enroll_url: Option<String>,
    pub welcome_url: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            interface_name: "wg-client".into(),
            address_cidr: "10.8.0.2/32".into(),
            server_endpoint: "127.0.0.1:51820".into(),
            server_public_key_b64: String::new(),
            keepalive_secs: 25,
            split_tunnel: false,
            kill_switch: false,
            client_private_key_b64: None,
            enroll_url: Some("http://127.0.0.1:8080/enroll".into()),
            welcome_url: Some("http://127.0.0.1:8080/".into()),
        }
    }
}

/**
 * @brief Load client configuration from `client.toml`, creating defaults when missing.
 */
pub fn load_client_config(path: Option<PathBuf>) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let p = path.unwrap_or_else(|| PathBuf::from("client.toml"));
    if !p.exists() {
        let def = ClientConfig::default();
        let s = toml::to_string_pretty(&def)?;
        fs::write(&p, s)?;
        return Ok(def);
    }
    let s = fs::read_to_string(p)?;
    let cfg: ClientConfig = toml::from_str(&s)?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn creates_default_when_missing() {
        let p = PathBuf::from("client.toml");
        let _ = std::fs::remove_file(&p);
        let cfg = load_client_config(Some(p.clone())).unwrap();
        assert_eq!(cfg.interface_name, "wg-client");
        assert!(p.exists());
    }
}

/**
 * @brief Ensure client private key exists; if not, generate and persist into `client.toml`.
 */
pub fn ensure_client_keys(mut cfg: ClientConfig, path: Option<PathBuf>) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    if cfg.client_private_key_b64.is_some() {
        return Ok(cfg);
    }
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let priv_b64 = base64::engine::general_purpose::STANDARD.encode(secret.to_bytes());
    cfg.client_private_key_b64 = Some(priv_b64);
    let p = path.unwrap_or_else(|| PathBuf::from("client.toml"));
    let s = toml::to_string_pretty(&cfg)?;
    fs::write(p, s)?;
    println!("Client public key: {}", base64::engine::general_purpose::STANDARD.encode(public.as_bytes()));
    Ok(cfg)
}
