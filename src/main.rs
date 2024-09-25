use btc_hs::message::*;
use btc_hs::*;
use clap::Parser;
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
};

#[derive(Parser)]
#[command(version, about = "Btc Handshake Implementation", long_about = None)]
struct Cli {
    /// The Bitcoin DNS seed, used for peer discovery.
    #[arg(long, short, default_value_t = DEFAULT_DNS_SEED.to_string())]
    dns_seed: String,

    /// Optionally provide a port other than mainnet's default.
    #[arg(long, short, value_parser = clap::value_parser!(u16).range(1..), default_value_t = MAIN_NET_PORT)]
    port: u16,

    /// Outputs the version of the currently supported bitcoin p2p network protocol.
    #[arg(long, short)]
    btc_proto: bool,
}

fn main() {
    let cli = Cli::parse();
    if cli.btc_proto {
        println!(
            "This implementation supports the p2p network protocol {}.",
            BTC_PROTO_VERSION
        );
        return;
    }
    tracing_subscriber::fmt::init();

    let dns = cli.dns_seed + ":" + &cli.port.to_string();

    tracing::info!("Attempting to resolve DNS: {:?}", dns);

    let addresses = dns
        .to_socket_addrs()
        .expect(&format!("Unable to resolve the provided dns: {dns}."));

    tracing::debug!("addresses {:?}", addresses);

    match TcpStream::connect(&addresses.as_slice()[..]) {
        Ok(mut stream) => {
            tracing::info!("Connected to: {:?}", stream.peer_addr().unwrap());
            handshake(&mut stream).unwrap();
            tracing::info!("Handshake with {:?} completed.", stream.peer_addr().unwrap());
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        }
        Err(e) => {
            tracing::error!("Could not connect to any of the resolved addresses. {}", e);
        }
    }
}

/// Attempts dandshaking a peer.
pub fn handshake(stream: &mut TcpStream) -> Result<(), String> {
    let rx = stream.local_addr().unwrap();
    let tx = stream.peer_addr().unwrap();

    let rx_ip = match rx.ip() {
        std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        std::net::IpAddr::V6(ip) => ip,
    }
    .octets();

    let tx_ip = match tx.ip() {
        std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        std::net::IpAddr::V6(ip) => ip,
    }
    .octets();

    let version = VersionMessage::new_with_defaults(
        tx_ip,
        // u16::to_be(rx.port()),
        rx.port(),
        rx_ip,
        // u16::to_be(tx.port()),
        tx.port(),
    );

    let bytes = generate_message(&version);
    stream.write_all(&bytes).unwrap();

    let mut header_bytes: [u8; Header::HEADER_WIDTH] = [0; Header::HEADER_WIDTH];
    stream.read_exact(&mut header_bytes).unwrap();

    let mut verack_bytes: [u8; 103] = [0u8; 103];
    stream.read_exact(&mut verack_bytes).unwrap();

    let verack = VerackMessage;
    let ver_bytes = generate_message(&verack);
    stream.write_all(&ver_bytes).unwrap();

    header_bytes = [0u8; Header::HEADER_WIDTH];
    stream.read_exact(&mut header_bytes).unwrap();

    Ok(())
}
