use crate::BTC_PROTO_VERSION;
use byteorder::{BigEndian, ByteOrder, LittleEndian, WriteBytesExt};
use core::str;
use sha2::{Digest, Sha256};
use std::{error::Error, fmt, io::Write, time::SystemTime};

/// Defines the messages transmitted to a peer during the handshake.
pub trait Message {
    /// The message's name. i.e "verack"
    fn name(&self) -> &'static str;

    /// The message's payload, for messages that have one.
    fn payload(&self) -> Result<Option<Vec<u8>>, MessageError>;
}

#[derive(Debug)]
pub enum MessageError {
    InvalidCommandName(String),
    PayloadOverSizeLimit(String),
    Serialization(std::io::Error),
    Deserialization,
    HeaderFailedParsing(String),
}

impl fmt::Display for MessageError {
    // relies on the fact that MessageError implements Debug
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidCommandName(err) => write!(f, "Invalid command name: {}", err),
            Self::PayloadOverSizeLimit(err) => write!(f, "Payload is too big: {}", err),
            Self::Serialization(err) => write!(f, "Serialization error: {}", err),
            Self::Deserialization => write!(f, "Deserialization error"),
            Self::HeaderFailedParsing(err) => write!(f, "Could not parse header: {}", err),
        }
    }
}

impl Error for MessageError {}

/// A message's header. Present in all messages.
#[derive(Debug, PartialEq)]
pub struct Header {
    /// Identifies the originating network.
    magic: [u8; 4],
    /// ASCII strings that identifies the message's type. Padded with 0s.
    command_name: [u8; 12],
    /// Width of the payload, max of 32MiB.
    payload_size: u32,
    /// First 4 bytes of SHA256(SHA256(payload)).
    checksum: [u8; 4],
}

impl Header {
    /// Total size of the header
    pub const HEADER_WIDTH: usize = 24;
    const MAX_PAYLOAD_WIDTH: usize = 1024 * 1024 * 32;
    const CHECKSUM_WIDTH: usize = 4;
    const MAGIC_WIDTH: usize = 4;
    const COMMAND_NAME_WIDTH: usize = 12;

    // (SHA256(SHA256(""))), avoid computing it when payloads are empty.
    const EMPTY_CHECKSUM: [u8; Self::CHECKSUM_WIDTH] = [0x5d, 0xf6, 0xe0, 0xe2];

    // const MAGIC_TESTNET: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];
    const MAGIC_MAINNET: [u8; Self::MAGIC_WIDTH] = [0xf9, 0xbe, 0xb4, 0xd9];

    pub fn get_payload_size(&self) -> u32 {
        self.payload_size
    }

    /// Generates the Header associated to a Command.
    // NOTE: The header is agnostic to the command/message itself.
    fn new(command: &str, payload: Option<&Vec<u8>>) -> Result<Self, MessageError> {
        let command_name = Self::command_name_from_str(command)?;

        let mut checksum = Self::EMPTY_CHECKSUM;
        let mut payload_size: u32 = 0;

        if let Some(payload) = payload {
            if payload.len() > Self::MAX_PAYLOAD_WIDTH {
                return Err(MessageError::PayloadOverSizeLimit(format!(
                    "Payload of size {} is bigger than max: {}.",
                    payload.len(),
                    Self::MAX_PAYLOAD_WIDTH
                )));
            }
            payload_size = payload.len() as u32;
            checksum = Self::checksum_from_payload(&payload);
        }

        let header = Self {
            magic: Self::MAGIC_MAINNET,
            command_name,
            payload_size,
            checksum,
        };

        Ok(header)
    }

    /// Generates bytes from a header
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        let mut serialized_header = Vec::with_capacity(std::mem::size_of::<Header>()); //

        serialized_header
            .write_all(&self.magic)
            .map_err(|err| MessageError::Serialization(err))?;

        serialized_header
            .write_all(&self.command_name)
            .map_err(|err| MessageError::Serialization(err))?;

        serialized_header
            .write_u32::<LittleEndian>(self.payload_size)
            .map_err(|err| MessageError::Serialization(err))?;

        serialized_header
            .write_all(&self.checksum)
            .map_err(|err| MessageError::Serialization(err))?;

        Ok(serialized_header)
    }

    /// Generates a Header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > Header::HEADER_WIDTH {
            let err = format!(
                "Can't generate header from byte slice of len {} which is smaller than the min {}.",
                bytes.len(),
                Header::HEADER_WIDTH
            );
            return Err(MessageError::HeaderFailedParsing(err));
        }

        let mut current_byte: usize = 0;

        let magic: [u8; Self::MAGIC_WIDTH] = bytes[current_byte..Self::MAGIC_WIDTH]
            .try_into()
            .map_err(|_| MessageError::Deserialization)?;

        current_byte += Self::MAGIC_WIDTH;

        let command_name: [u8; Self::COMMAND_NAME_WIDTH] = bytes
            [current_byte..current_byte + Self::COMMAND_NAME_WIDTH]
            .try_into()
            .map_err(|_| MessageError::Deserialization)?;

        current_byte += Self::COMMAND_NAME_WIDTH;

        let payload_size: u32 =
            LittleEndian::read_u32(&bytes[current_byte..current_byte + std::mem::size_of::<u32>()]);
        current_byte += std::mem::size_of::<u32>();

        let checksum: [u8; Self::CHECKSUM_WIDTH] = bytes
            [current_byte..current_byte + Header::CHECKSUM_WIDTH]
            .try_into()
            .map_err(|_| MessageError::Deserialization)?;
        current_byte += Self::CHECKSUM_WIDTH;

        if current_byte != Self::HEADER_WIDTH {
            return Err(MessageError::HeaderFailedParsing(
                "Unexpected number of bytes in header.".to_owned(),
            ));
        }

        tracing::debug!(
            "command received: {:?}",
            String::from_utf8_lossy(&command_name)
        );

        Ok(Self {
            magic,
            command_name,
            payload_size,
            checksum,
        })
    }

    /// Generates a [u8; 12] from an ascii string, padding with 0s when needed.
    fn command_name_from_str(name: &str) -> Result<[u8; 12], MessageError> {
        const NAME_LEN: usize = 12;

        if !name.is_ascii() {
            return Err(MessageError::InvalidCommandName(format!(
                "command: '{name}' should only contain ASCII characters.",
            )));
        }

        if name.len() > NAME_LEN {
            return Err(MessageError::InvalidCommandName(format!(
                "name: '{name}' has length {} which is more than the allowed max {}.",
                name.len(),
                NAME_LEN
            )));
        }

        let mut formatted_name: [u8; NAME_LEN] = [0; NAME_LEN];
        let bytes = name.as_bytes();

        for i in 0..name.len() {
            formatted_name[i] = bytes[i];
        }

        Ok(formatted_name)
    }

    /// Generates the checksum SHA256(SHA256(payload)).
    fn checksum_from_payload(payload: &Vec<u8>) -> [u8; Self::CHECKSUM_WIDTH] {
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let mut hash = hasher.finalize();

        // shadow and rehash, as per the protocol.
        hasher = Sha256::new();
        hasher.update(hash);
        hash = hasher.finalize();

        let mut checksum: [u8; Self::CHECKSUM_WIDTH] = [0; Self::CHECKSUM_WIDTH];
        checksum.clone_from_slice(&hash[..Self::CHECKSUM_WIDTH]);

        checksum
    }
}

/// A serialized message that can be sent over the wire.
pub fn serialize_message<T: Message>(message: &T) -> Result<Vec<u8>, MessageError> {
    let payload = message.payload()?;
    let header = Header::new(message.name(), payload.as_ref())?;

    let mut serialized_message = header.to_bytes()?;

    // message has a payload/body: append it after the header.
    if let Some(p) = payload {
        serialized_message.extend(p);
    }
    Ok(serialized_message)
}

/// The first and primary messages in the handshake.
#[derive(Debug)]
pub struct VersionMessage {
    /// The highest protocol version understood by the transmitting node
    version: i32,
    /// The services supported by the transmitting node encoded as a bitfield
    service: u64,
    /// The current Unix epoch time according to the transmitting node’s clock
    timestamp: i64,
    /// The services supported by the receiving node as perceived by the transmitting node
    addr_recv_services: u64,
    /// The IPv6 address of the receiving node as perceived by the transmitting node
    addr_recv_ip: [u8; 16], // Note: big endian
    /// The port number of the receiving node as perceived by the transmitting node
    addr_recv_port: u16, // Note: big endian,
    /// The services supported by the transmitting node
    addr_trans_services: u64,
    /// The port number of the transmitting node as perceived by the transmitting node
    addr_trans_ip: [u8; 16], // Note: big endian,
    /// The port number of the transmitting node
    addr_trans_port: u16, // Note: big endian,
    /// A random nonce which can help a node detect a connection to itself.
    /// If the nonce is 0, the nonce field is ignored
    nonce: u64,
    /// Number of bytes in following user_agent field.
    /// If 0x00, no user agent field is sent.
    user_agent_bytes: u8,
    /// The user agent itself.
    user_agent_str: Option<String>,
    /// The height of the transmitting node’s best block chain
    start_height: i32,
    /// Transaction relay flag
    relay: bool,
}

impl VersionMessage {
    pub fn new(
        version: i32,
        service: u64,
        timestamp: i64,
        addr_recv_services: u64,
        addr_recv_ip: [u8; 16],
        addr_recv_port: u16,
        addr_trans_services: u64,
        addr_trans_ip: [u8; 16],
        addr_trans_port: u16,
        nonce: u64,
        user_agent_bytes: u8,
        user_agent_str: Option<String>,
        start_height: i32,
        relay: bool,
    ) -> Self {
        Self {
            version,
            service,
            timestamp,
            addr_recv_services,
            addr_recv_ip,
            addr_recv_port,
            addr_trans_services,
            addr_trans_ip,
            addr_trans_port,
            nonce,
            user_agent_bytes,
            user_agent_str,
            start_height,
            relay,
        }
    }

    // NOTE: Might be useful to introduce a builder here for flexibility.
    /// Ctor that uses the most probable values.
    /// Takes in the statically unknown fields as params: local and target addr.
    pub fn new_with_defaults(
        addr_recv_ip: [u8; 16],
        addr_recv_port: u16,
        addr_trans_ip: [u8; 16],
        addr_trans_port: u16,
    ) -> Self {
        let timestamp: i64 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Could not get unix timestamp")
            .as_secs() as i64;

        Self {
            version: BTC_PROTO_VERSION,
            service: Service::NODE_NETWORK,
            timestamp,
            addr_recv_services: Service::NODE_NETWORK,
            addr_recv_ip,
            addr_recv_port,
            addr_trans_services: Service::NODE_NETWORK,
            addr_trans_ip,
            addr_trans_port,
            nonce: rand::random(),
            user_agent_bytes: 0,
            user_agent_str: None,
            start_height: 0,
            relay: false,
        }
    }
}

impl Message for VersionMessage {
    fn name(&self) -> &'static str {
        "version"
    }

    fn payload(&self) -> Result<Option<Vec<u8>>, MessageError> {
        let mut payload: Vec<u8> = Vec::with_capacity(std::mem::size_of::<VersionMessage>()); // ; // todo, capacity.

        payload
            .write_i32::<LittleEndian>(self.version)
            .map_err(|err| MessageError::Serialization(err))?;

        payload
            .write_u64::<LittleEndian>(self.service)
            .map_err(|err| MessageError::Serialization(err))?;

        payload
            .write_i64::<LittleEndian>(self.timestamp)
            .map_err(|err| MessageError::Serialization(err))?;

        // rx end
        payload
            .write_u64::<LittleEndian>(self.addr_recv_services)
            .map_err(|err| MessageError::Serialization(err))?;
        payload
            .write_u128::<BigEndian>(u128::from_ne_bytes(self.addr_recv_ip))
            .map_err(|err| MessageError::Serialization(err))?;
        payload
            .write_u16::<BigEndian>(self.addr_recv_port)
            .map_err(|err| MessageError::Serialization(err))?;

        // tx end
        payload
            .write_u64::<LittleEndian>(self.addr_trans_services)
            .map_err(|err| MessageError::Serialization(err))?;

        payload
            .write_u128::<BigEndian>(u128::from_ne_bytes(self.addr_trans_ip))
            .map_err(|err| MessageError::Serialization(err))?;

        payload
            .write_u16::<BigEndian>(self.addr_trans_port)
            .map_err(|err| MessageError::Serialization(err))?;

        payload
            .write_u64::<LittleEndian>(self.nonce)
            .map_err(|err| MessageError::Serialization(err))?;

        if let Some(user) = &self.user_agent_str {
            payload
                .write_u8(self.user_agent_bytes)
                .map_err(|err| MessageError::Serialization(err))?;

            payload
                .write_all(user.as_bytes())
                .map_err(|err| MessageError::Serialization(err))?;
        } else {
            // indicate that there are no user agent
            payload.push(0);
        }
        payload
            .write_i32::<LittleEndian>(self.start_height)
            .map_err(|err| MessageError::Serialization(err))?;
        payload
            .write_u8(self.relay.into())
            .map_err(|err| MessageError::Serialization(err))?;

        Ok(Some(payload))
    }
}

struct Service;
#[allow(dead_code)]
impl Service {
    const UNNAMED: u64 = 0x00;
    const NODE_NETWORK: u64 = 0x01;
    const NODE_GETUTXO: u64 = 0x02;
    const NODE_BLOOM: u64 = 0x04;
    const NODE_WITNESS: u64 = 0x08;
    const NODE_XTHIN: u64 = 0x10;
    const NODE_NETWORK_LIMITED: u64 = 0x0400;
}

/// Version Acknowledgement. Payload-less command.
pub struct VerackMessage;
impl Message for VerackMessage {
    // fn name() -> [u8; 12] {
    fn name(&self) -> &'static str {
        "verack"
    }

    fn payload(&self) -> Result<Option<Vec<u8>>, MessageError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use super::*;

    fn version_msg_mock() -> VersionMessage {
        let addr = "90.25.213.4:8333".parse::<SocketAddrV4>().unwrap();
        let addr_bytes = addr.ip().to_ipv6_mapped().octets();

        VersionMessage::new_with_defaults(addr_bytes, addr.port(), addr_bytes, addr.port())
    }

    #[test]
    fn header_generation() {
        let version_msg = version_msg_mock();
        let header =
            Header::new(version_msg.name(), version_msg.payload().unwrap().as_ref()).unwrap();
        let cmd_name = [b'v', b'e', b'r', b's', b'i', b'o', b'n', 0, 0, 0, 0, 0];
        assert_eq!(header.command_name, cmd_name);
        assert_eq!(
            header.payload_size as usize,
            version_msg.payload().unwrap().unwrap().len()
        );
    }

    #[test]
    fn header_serialization() {
        // via property: encode->decode->encode.
        let version_msg = version_msg_mock();
        let header =
            Header::new(version_msg.name(), version_msg.payload().unwrap().as_ref()).unwrap();

        let encoded = header.to_bytes().unwrap();
        let deserialized_header = Header::from_bytes(&encoded).unwrap();

        assert_eq!(header, deserialized_header);

        let second_encoding = deserialized_header.to_bytes().unwrap();
        assert_eq!(second_encoding, encoded);
    }
}
