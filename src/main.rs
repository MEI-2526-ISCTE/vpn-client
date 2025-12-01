use std::{
    net::SocketAddr,
    str::FromStr,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    thread,
    time::Duration,
};

use base64::{engine::general_purpose, Engine as _};
mod config;
use config::{load_client_config, ensure_client_keys};
use clap::{Parser, Subcommand};
mod kill_switch;
use defguard_wireguard_rs::{
    host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration, WGApi, WireguardInterfaceApi,
};

#[derive(Parser)]
#[command(name = "vpn-client")]
#[command(version, about = "WireGuard VPN client")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[arg(long)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    Init,
    Connect { #[arg(long)] ifname: Option<String> },
    Disconnect,
    Status,
    Import { path: String },
    PrintPubkey,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();
    let cfg_path = cli.config.as_ref().map(|p| std::path::PathBuf::from(p));
    match cli.cmd {
        Cmd::Init => {
            let cfg = load_client_config(cfg_path.clone())?;
            let _ = ensure_client_keys(cfg, cfg_path.clone())?;
        }
        Cmd::Connect { ifname } => {
            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();
            ctrlc::set_handler(move || {
                r.store(false, Ordering::SeqCst);
                println!("\nShutting down...");
            })?;
            let cfg = load_client_config(cfg_path.clone())?;
            let cfg = ensure_client_keys(cfg, cfg_path.clone())?;
            let ifname = ifname.unwrap_or_else(|| cfg.interface_name.clone());
            let client_private_key_b64 = cfg.client_private_key_b64.clone().unwrap();
            let server_public_key_b64 = cfg.server_public_key_b64.clone();
            let server_pubkey_bytes = general_purpose::STANDARD.decode(server_public_key_b64)?;
            if server_pubkey_bytes.len() != 32 { return Err("Server public key must decode to exactly 32 bytes".into()); }
            let server_pubkey = Key::new(server_pubkey_bytes.try_into().unwrap());
            let mut peer = Peer::new(server_pubkey);
            peer.endpoint = Some(cfg.server_endpoint.parse::<SocketAddr>()?);
            peer.persistent_keepalive_interval = Some(cfg.keepalive_secs);
            if cfg.split_tunnel { peer.allowed_ips.push(IpAddrMask::from_str("10.8.0.0/24")?); } else { peer.allowed_ips.push(IpAddrMask::from_str("0.0.0.0/0")?); }
            let config = InterfaceConfiguration { name: ifname.clone(), prvkey: client_private_key_b64.to_string(), addresses: vec![cfg.address_cidr.parse()?], port: 0, peers: vec![peer], mtu: None };
            println!("Creating interface {ifname} and connecting...");
            let wgapi = WGApi::<defguard_wireguard_rs::Kernel>::new(ifname.clone())?;
            wgapi.create_interface()?;
            #[cfg(target_os = "windows")]
            {
                wgapi.configure_interface(&config, &[], &[])?;
            }
            #[cfg(not(target_os = "windows"))]
            {
                wgapi.configure_interface(&config)?;
            }
            if cfg.kill_switch { kill_switch::apply_kill_switch(&ifname); }
            println!("Client is running — handshaking with server...");
            println!("Press Ctrl+C to stop\n");
            while running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(5));
                if let Ok(data) = wgapi.read_interface_data() {
                    for (_, p) in &data.peers {
                        if p.last_handshake.is_some() { println!("CONNECTED | {} KB sent | {} KB recv", p.tx_bytes / 1024, p.rx_bytes / 1024); } else { println!("Still waiting for handshake..."); }
                    }
                }
            }
            drop(wgapi);
            println!("Client stopped.");
        }
        Cmd::Disconnect => {
            let cfg = load_client_config(cfg_path.clone())?;
            let ifname = cfg.interface_name.clone();
            let wgapi = WGApi::<defguard_wireguard_rs::Kernel>::new(ifname.clone())?;
            let _ = std::process::Command::new("ip").args(["link", "set", &ifname, "down"]).output();
            wgapi.remove_interface()?;
        }
        Cmd::Status => {
            let cfg = load_client_config(cfg_path.clone())?;
            let ifname = cfg.interface_name.clone();
            let wgapi = WGApi::<defguard_wireguard_rs::Kernel>::new(ifname.clone())?;
            if let Ok(data) = wgapi.read_interface_data() {
                for (_, p) in &data.peers {
                    let hs = p.last_handshake.is_some();
                    println!("{} {} KB {} KB", hs, p.tx_bytes / 1024, p.rx_bytes / 1024);
                }
            }
        }
        Cmd::Import { path } => {
            let s = std::fs::read_to_string(path)?;
            let mut cfg = load_client_config(cfg_path.clone())?;
            let imported: toml::Value = toml::from_str(&s)?;
            if let Some(ep) = imported.get("server_endpoint").and_then(|v| v.as_str()) { cfg.server_endpoint = ep.into(); }
            if let Some(pk) = imported.get("server_public_key_b64").and_then(|v| v.as_str()) { cfg.server_public_key_b64 = pk.into(); }
            let out = toml::to_string_pretty(&cfg)?;
            let p = cfg_path.unwrap_or_else(|| std::path::PathBuf::from("client.toml"));
            std::fs::write(p, out)?;
        }
        Cmd::PrintPubkey => {
            let cfg = load_client_config(cfg_path.clone())?;
            let sk_b64 = cfg.client_private_key_b64.clone().ok_or("Missing client private key")?;
            let sk_bytes = general_purpose::STANDARD.decode(sk_b64)?;
            let arr: [u8;32] = sk_bytes.try_into().map_err(|_| "Invalid key length")?;
            let secret = x25519_dalek::StaticSecret::from(arr);
            let public = x25519_dalek::PublicKey::from(&secret);
            println!("{}", general_purpose::STANDARD.encode(public.as_bytes()));
        }
    }
    Ok(())
}
