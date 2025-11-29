use std::{
    net::SocketAddr,
    str::FromStr,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    thread,
    time::Duration,
};

use base64::{engine::general_purpose, Engine as _};
use defguard_wireguard_rs::{
    host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration, WGApi, WireguardInterfaceApi,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("\nShutting down...");
    })?;

    let ifname = "wg-client".to_string();  // Changed to avoid conflict with server

    // === CLIENT KEYS (valid fixed pair matching server's peer) ===
    let client_private_key_b64 = "LlaygSDSany5T+/ft9TcaLlk83gGKrFc1gcG8VWAxtM=";
    println!("Connecting with client public key:");
    println!("SBGX26d2F9aECQ7zMD4nUu90T3gPZvNzTara/iS2CW4=\n");

    // === SERVER PUBLIC KEY (matches server's fixed private key) ===
    let server_public_key_b64 = "dk5wF6ddw4IolWSxtwhIrghD753KdQRmg0m+DwkFgDo=";

    let server_pubkey_bytes = general_purpose::STANDARD.decode(server_public_key_b64)?;
    if server_pubkey_bytes.len() != 32 {
        return Err("Server public key must decode to exactly 32 bytes".into());
    }
    let server_pubkey = Key::new(server_pubkey_bytes.try_into().unwrap());

    // === PEER (the server) ===
    let mut peer = Peer::new(server_pubkey);
    peer.endpoint = Some("127.0.0.1:51820".parse::<SocketAddr>()?);  // Loopback for local testing
    peer.persistent_keepalive_interval = Some(25);
    peer.allowed_ips.push(IpAddrMask::from_str("0.0.0.0/0")?);

    // === CLIENT CONFIG ===
    let config = InterfaceConfiguration {
        name: ifname.clone(),
        prvkey: client_private_key_b64.to_string(),
        addresses: vec!["10.8.0.2/32".parse()?],  // Changed to match server's range
        port: 0,
        peers: vec![peer],
        mtu: None,
    };

    println!("Creating interface {ifname} and connecting...");
    let wgapi = WGApi::<defguard_wireguard_rs::Kernel>::new(ifname.clone())?;
    wgapi.create_interface()?;
    wgapi.configure_interface(&config)?;

    println!("Client is running — handshaking with server...");
    println!("Press Ctrl+C to stop\n");

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(5));

        if let Ok(data) = wgapi.read_interface_data() {
            for (_, p) in &data.peers {
                if p.last_handshake.is_some() {
                    println!(
                        "CONNECTED | {} KB sent | {} KB recv",
                        p.tx_bytes / 1024,
                        p.rx_bytes / 1024
                    );
                } else {
                    println!("Still waiting for handshake...");
                }
            }
        }
    }

    drop(wgapi);
    println!("Client stopped.");
    Ok(())
}