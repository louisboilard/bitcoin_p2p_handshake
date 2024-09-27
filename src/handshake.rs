use std::{error::Error, fmt, io::Read, io::Write, net::TcpStream};

use crate::message::{serialize_message, Header, MessageError, VerackMessage, VersionMessage};

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
}

impl fmt::Display for State {
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
/// Top level error, with handshake state context.
pub enum HandshakeError {
    /// An error that happened at the message layer.
    MessageError(State, MessageError),
    /// IO related errors.
    IOError(State, std::io::Error),
}

impl fmt::Display for HandshakeError {
    // NOTE: Relies on the fact that HandshakeError implements Debug
    // and that State implements display.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MessageError(state, err) => {
                write!(f, "Message Error: State: {}. err: {}.", state, err)
            }
            Self::IOError(state, err) => write!(f, "IO Error: State: {}. err: {}.", state, err),
        }
    }
}
impl Error for HandshakeError {}

/// Handshake
#[derive(Debug)]
pub struct Handshake<'a> {
    /// The current state of the handshake process.
    state: State,
    /// A tcp stream between a local and remote socket
    /// on which the handshake will happen.
    stream: &'a TcpStream,
}

impl<'a> Handshake<'a> {
    /// Constructs and initializes the handshake that will be attempted on
    /// the given TcpStream.
    pub fn new(stream: &'a TcpStream) -> Self {
        let state = State::new();
        Self { state, stream }
    }

    /// Attempts to run an handshake to completion.
    pub fn process(&mut self) -> Result<(), HandshakeError> {
        while let Some(state_result) = self.next() {
            match state_result {
                Ok(_) => {
                    tracing::info!("Reached state: {}", self.state);
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
            State::ValidateVersion => {
                self.send_verack()?;
                self.state = State::SendAck
            }
            State::SendAck => {
                self.read_verack()?;
                self.state = State::RecvAck
            }
            State::RecvAck => self.state = State::ValidateAck,
            State::ValidateAck => self.state = State::Complete,
            State::Complete => self.state = State::Complete,
        }
        Ok(())
    }

    fn read_verack(&mut self) -> Result<(), HandshakeError> {
        let mut header_bytes = [0u8; Header::HEADER_WIDTH];

        self.stream
            .read_exact(&mut header_bytes)
            .map_err(|err| HandshakeError::IOError(self.state, err))?;

        Ok(())
    }

    /// Builds and send the "verack" message
    fn send_verack(&mut self) -> Result<(), HandshakeError> {
        let verack = VerackMessage;

        let verack_bytes = serialize_message(&verack)
            .map_err(|err| HandshakeError::MessageError(self.state, err))?;

        self.stream
            .write_all(&verack_bytes)
            .map_err(|err| HandshakeError::IOError(self.state, err))?;
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

        let mut verack_bytes: Vec<u8> = vec![0; message_width];
        self.stream
            .read_exact(&mut verack_bytes[..message_width])
            .map_err(|err| HandshakeError::IOError(self.state, err))?;
        Ok(())
    }
}

// Returns `None` when the handshake is completed.
impl Iterator for Handshake<'_> {
    type Item = Result<(), HandshakeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.state.completed() {
            return None;
        }

        // Step in
        Some(self.step())
    }
}
