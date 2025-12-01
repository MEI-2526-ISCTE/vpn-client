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
mod filelog;
mod route;
mod dns;
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
            if let Some(url) = &cfg.enroll_url {
                // POST client public key to server enrollment endpoint
                let sk_bytes = general_purpose::STANDARD.decode(&client_private_key_b64)?;
                let arr: [u8;32] = sk_bytes.try_into().map_err(|_| "Invalid key length")?;
                let secret = x25519_dalek::StaticSecret::from(arr);
                let public = x25519_dalek::PublicKey::from(&secret);
                let pub_b64 = general_purpose::STANDARD.encode(public.as_bytes());
                if url.starts_with("http://") {
                    // naive HTTP client
                    let (host_port, path) = {
                        let s = url.trim_start_matches("http://");
                        let pos = s.find('/').unwrap_or(s.len());
                        let hp = &s[..pos];
                        let p = &s[pos..];
                        (hp.to_string(), if p.is_empty() { "/".to_string() } else { p.to_string() })
                    };
                    let mut parts = host_port.split(':');
                    let host = parts.next().unwrap_or("127.0.0.1");
                    let port: u16 = parts.next().unwrap_or("8080").parse().unwrap_or(8080);
                    let mut stream = std::net::TcpStream::connect((host, port))?;
                    let body = pub_b64.clone();
                    let req = format!(
                        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        path, host, body.len(), body
                    );
                    use std::io::Write;
                    stream.write_all(req.as_bytes())?;
                    use std::io::Read;
                    let mut resp = String::new();
                    stream.read_to_string(&mut resp)?;
                    if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
                        return Err("Enrollment failed".into());
                    }
                }
            }
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
            let original = if !cfg.split_tunnel { route::snapshot_default() } else { None };
            let dns_snap = if !cfg.split_tunnel && !cfg!(target_os = "windows") { Some(dns::snapshot_dns()) } else { None };
            if !cfg.split_tunnel {
                if let Some((gw, dev)) = original.as_ref() {
                    let ep_ip = cfg.server_endpoint.split(':').next().unwrap_or("127.0.0.1");
                    route::host_route_to_endpoint(ep_ip, gw, dev);
                }
                dns::apply_full_tunnel_dns(&ifname);
            }
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(20);
            loop {
                if let Ok(data) = wgapi.read_interface_data() {
                    let mut ok = false;
                    for (_, p) in &data.peers {
                        if p.last_handshake.is_some() { ok = true; break; }
                    }
                    if ok { break; }
                }
                if start.elapsed() >= timeout {
                    filelog::write_line("vpn-client.log", &format!("Handshake timeout for {ifname}"));
                    let _ = std::process::Command::new("ip").args(["link", "set", &ifname, "down"]).output();
                    wgapi.remove_interface()?;
                    return Err("Handshake timeout — server unreachable".into());
                }
                thread::sleep(Duration::from_secs(1));
            }
            // Connectivity probe over raw IP (no DNS)
            let probe = std::net::TcpStream::connect_timeout(
                &"1.1.1.1:443".parse::<std::net::SocketAddr>().unwrap(),
                std::time::Duration::from_secs(3),
            );
            if probe.is_err() {
                filelog::write_line("vpn-client.log", "Connectivity probe failed after handshake — tearing down");
                let _ = std::process::Command::new("ip").args(["link", "set", &ifname, "down"]).output();
                wgapi.remove_interface()?;
                if cfg.kill_switch { kill_switch::revert_kill_switch(&ifname); }
                #[cfg(target_os = "windows")]
                {
                    dns::restore_dns(&ifname);
                }
                #[cfg(not(target_os = "windows"))]
                {
                    if let Some(ref snap) = dns_snap { dns::restore_dns(snap); }
                }
                return Err("Connectivity failed — restored network".into());
            }
            println!("Client is running — handshaking with server...");
            filelog::write_line("vpn-client.log", &format!("Client connected on {ifname}"));
            {
                let host = cfg.server_endpoint.split(':').next().unwrap_or("127.0.0.1");
                let target = cfg.welcome_url.clone().unwrap_or_else(|| format!("http://{}:8080/", host));
                if cfg!(target_os = "windows") {
                    let _ = std::process::Command::new("powershell").args(["-Command", &format!("Start-Process '{}'", target)]).output();
                } else if cfg!(target_os = "macos") {
                    let _ = std::process::Command::new("open").arg(&target).output();
                } else {
                    let _ = std::process::Command::new("xdg-open").arg(&target).output();
                }
            }
            println!("Press Ctrl+C to stop\n");
            while running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(5));
                if let Ok(data) = wgapi.read_interface_data() {
                    for (_, p) in &data.peers {
                        if p.last_handshake.is_some() { let msg = format!("CONNECTED | {} KB sent | {} KB recv", p.tx_bytes / 1024, p.rx_bytes / 1024); println!("{}", msg); filelog::write_line("vpn-client.log", &msg); } else { println!("Still waiting for handshake..."); }
                    }
                }
            }
            drop(wgapi);
            let _ = std::process::Command::new("ip").args(["link", "set", &ifname, "down"]).output();
            let wgapi = WGApi::<defguard_wireguard_rs::Kernel>::new(ifname.clone())?;
            let _ = wgapi.remove_interface();
            if cfg.kill_switch { kill_switch::revert_kill_switch(&ifname); }
            if !cfg.split_tunnel { route::restore_default(&original); }
            #[cfg(target_os = "windows")]
            {
                dns::restore_dns(&ifname);
            }
            #[cfg(not(target_os = "windows"))]
            {
                if let Some(ref snap) = dns_snap { dns::restore_dns(snap); }
            }
            println!("Client stopped.");
            filelog::write_line("vpn-client.log", &format!("Client stopped on {ifname}"));
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
