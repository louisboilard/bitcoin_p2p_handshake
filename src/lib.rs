// NOTE: Based on https://developer.bitcoin.org/devguide/p2p_network.html

//! Implementation of the bitcoin p2p network handshake for BTC_PROTO_VERSION.

pub mod handshake;
mod message;

/// Testnet default port
pub const TEST_NET_PORT: u16 = 18333;
/// Mainnet default port
pub const MAIN_NET_PORT: u16 = 8333;
/// Default dns seed for testing, from bitcoin core client
pub const DEFAULT_DNS_SEED: &str = "seed.bitcoin.sipa.be";
/// Version of the p2p protocol supported by this implementation
pub const BTC_PROTO_VERSION: i32 = 70015;
