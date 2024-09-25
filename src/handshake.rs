use std::{error::Error, fmt, io::Read, io::Write, net::TcpStream};

use crate::message::{serialize_message, Header, MessageError, VersionMessage};

/// States the handshake goes through (post connection).
#[derive(Debug, Clone, Copy)]
pub enum State {
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

    fn completed(&self) -> bool {
        match self {
            Self::Complete => return true,
            _ => return false,
        }
    }

    fn next(&mut self) {
        match self {
            Self::Init => *self = Self::SendVersion,
            Self::SendVersion => *self = Self::RecvVersion,
            Self::RecvVersion => *self = Self::ValidateVersion,
            Self::ValidateVersion => *self = Self::SendAck,
            Self::SendAck => *self = Self::RecvAck,
            Self::RecvAck => *self = Self::ValidateAck,
            Self::ValidateAck => *self = Self::Complete,
            Self::Complete => *self = Self::Complete,
        };
    }
}

impl fmt::Display for State {
    // relies on the fact that State implements Debug
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Init => write!(f, "Initial state"),
            Self::SendVersion => write!(f, "Sending Version Message"),
            Self::RecvVersion => write!(f, "Receiving Version Message"),
            Self::ValidateVersion => write!(f, "Validating Version Message"),
            Self::SendAck => write!(f, "Sending Ack Message"),
            Self::RecvAck => write!(f, "Receiving Ack Message"),
            Self::ValidateAck => write!(f, "Validating Ack Message"),
            Self::Complete => write!(f, "Handshake completed"),
        }
    }
}

#[derive(Debug)]
/// Top level error, injecting state level context.
pub enum HandshakeError {
    /// An error that happened at the message layer.
    MessageError(State, MessageError),
    /// IO related errors.
    IOError(State, std::io::Error),
}

/// Top level error, injecting state level context.
impl fmt::Display for HandshakeError {
    // NOTE: Relies on the fact that HandshakeError implements Debug
    // and that State implements display.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MessageError(state, err) => write!(f, "Message Error: {} {}", state, err),
            Self::IOError(state, err) => write!(f, "IO Error: {} {}", state, err),
        }
    }
}
impl Error for HandshakeError {}

/// Handshake
#[derive(Debug)]
pub struct Handshake {
    /// The current state
    state: State,
    /// A tcp stream between a local and remote socket
    /// on which the handshake will happen.
    stream: TcpStream,
}

impl Handshake {
    /// Constructs and initializes the handshake that will be attempted on
    /// the given TcpStream.
    pub fn new(stream: TcpStream) -> Self {
        let state = State::new();
        Self { state, stream }
    }

    /// Attempts to run an handshake to completion.
    pub fn handshake(&mut self) -> Result<(), HandshakeError> {
        while let Some(state_result) = self.next() {
            match state_result {
                Ok(state) => {
                    tracing::info!("Reached state: {}", state);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    fn step(&mut self) -> Result<(), HandshakeError> {
        match self.state {
            State::Init => {
                self.send_version()?;
                self.state = State::SendVersion
            }
            State::SendVersion => {
                self.read_version()?;
                self.state = State::RecvVersion
            }
            State::RecvVersion => self.state = State::ValidateVersion,
            State::ValidateVersion => self.state = State::SendAck,
            State::SendAck => self.state = State::RecvAck,
            State::RecvAck => self.state = State::ValidateAck,
            State::ValidateAck => self.state = State::Complete,
            State::Complete => self.state = State::Complete,
        }
        Ok(())
    }

    /// Builds and send the "version" message
    fn send_version(&mut self) -> Result<(), HandshakeError> {
        let rx = self
            .stream
            .local_addr()
            .map_err(|err| HandshakeError::IOError(self.state, err))?;

        let tx = self
            .stream
            .peer_addr()
            .map_err(|err| HandshakeError::IOError(self.state, err))?;

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

        let bytes = serialize_message(&version)
            .map_err(|err| HandshakeError::MessageError(self.state, err))?;

        self.stream
            .write_all(&bytes)
            .map_err(|err| HandshakeError::IOError(self.state, err))?;
        Ok(())
    }

    fn read_version(&mut self) -> Result<(), HandshakeError> {
        let mut header_bytes: [u8; Header::HEADER_WIDTH] = [0; Header::HEADER_WIDTH];
        self.stream
            .read_exact(&mut header_bytes)
            .map_err(|err| HandshakeError::IOError(self.state, err))?;

        let header = Header::from_bytes(&header_bytes)
            .map_err(|err| HandshakeError::MessageError(self.state, err))?;

        let message_width = header.get_payload_size() as usize;

        let mut verack_bytes: Vec<u8> = Vec::with_capacity(message_width);
        self.stream
            .read_exact(&mut verack_bytes[..message_width])
            .map_err(|err| HandshakeError::IOError(self.state, err))?;
        Ok(())
    }
}

// This iterator returns None when the handshake is complete and the current
// State or error when stepping.
impl Iterator for Handshake {
    type Item = Result<State, HandshakeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.state.completed() {
            return None;
        }

        // Step
        // todo: handle the errors here, whenever there's an error here we need to bubble it up.
        self.step();
        None
    }
}
