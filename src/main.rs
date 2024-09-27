use btc_hs::*;
use clap::Parser;
use handshake::Handshake;
use std::net::{TcpStream, ToSocketAddrs};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if cli.btc_proto {
        println!(
            "This implementation supports the p2p network protocol {}.",
            BTC_PROTO_VERSION
        );
        return Ok(());
    }

    tracing_subscriber::fmt::init();

    let dns = cli.dns_seed + ":" + &cli.port.to_string();

    tracing::info!("Attempting to resolve DNS: {:?}", dns);

    let addresses = dns
        .to_socket_addrs()
        .expect(&format!("Unable to resolve the provided dns: {dns}."));

    tracing::debug!("addresses {:?}", addresses);

    match TcpStream::connect(&addresses.as_slice()[..]) {
        Ok(stream) => {
            let peer = stream.peer_addr()?;
            tracing::info!("Connected to: {:?}", peer);

            let mut handshake = Handshake::new(&stream);
            let handshake_result = handshake.process();
            match handshake_result {
                Ok(_) => {
                    tracing::info!("Handshake with {:?} completed.", peer);
                }
                Err(ref e) => {
                    tracing::error!("Handshake with {:?} failed. {}", peer, e);
                }
            }
            stream.shutdown(std::net::Shutdown::Both)?;
            handshake_result?
        }
        Err(e) => {
            tracing::error!("Could not connect to any of the resolved addresses. {}", e);
            return Err(e.into());
        }
    }
    Ok(())
}
