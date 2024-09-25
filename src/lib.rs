// NOTE: Based on https://developer.bitcoin.org/devguide/p2p_network.html

//! Implementation of the bitcoin p2p network handshake for BTC_PROTO_VERSION.

/// Testnet default port
pub const TEST_NET_PORT: u16 = 18333;
/// Mainnet default port
pub const MAIN_NET_PORT: u16 = 8333;
/// Default dns seed for testing, from bitcoin core client
pub const DEFAULT_DNS_SEED: &str = "seed.bitcoin.sipa.be";
/// Version of the p2p protocol supported by this implementation
pub const BTC_PROTO_VERSION: i32 = 70015;

pub mod message;

mod handshake {
    /// States the handshake goes through (post connection).
    #[derive(Debug)]
    enum State {
        Init,
        SendVersion,
        RecvVersion,
        ValidateVersion,
        SendAck,
        RecvAck,
        ValidateAck,
        Complete,
    }

    impl State {
        fn new() -> Self {
            Self::Init
        }

        /// States transitions.
        fn next(s: Self) -> Self {
            match s {
                Self::Init => Self::SendVersion,
                Self::SendVersion => Self::RecvVersion,
                Self::RecvVersion => Self::ValidateVersion,
                Self::ValidateVersion => Self::SendAck,
                Self::SendAck => Self::RecvAck,
                Self::RecvAck => Self::ValidateAck,
                Self::ValidateAck => Self::Complete,
                Self::Complete => Self::Complete,
            }
        }
    }
}
