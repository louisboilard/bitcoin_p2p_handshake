use crate::BTC_PROTO_VERSION;
use byteorder::{BigEndian, ByteOrder, LittleEndian, WriteBytesExt};
use core::str;
use sha2::{Digest, Sha256};
use std::{io::Write, time::SystemTime};

/// Defines the messages transmitted to a peer during the handshake.
pub trait Message {
    /// The message's name. i.e "verack"
    fn name(&self) -> &'static str;

    /// The message's payload, for messages that have one.
    fn payload(&self) -> Option<Vec<u8>>;
}

/// A message's header. Present in all messages.
#[derive(Debug)]
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

    /// Generates the Header associated to a Command.
    // NOTE: The header is agnostic to the command/message itself.
    fn new(command: &str, payload: Option<&Vec<u8>>) -> Result<Self, String> {
        let command_name = Self::command_name_from_str(command)?;

        let mut checksum = Self::EMPTY_CHECKSUM;
        let mut payload_size: u32 = 0;

        if let Some(payload) = payload {
            if payload.len() > Self::MAX_PAYLOAD_WIDTH {
                return Err(format!(
                    "Payload of size {} is bigger than max: {}.",
                    payload.len(),
                    Self::MAX_PAYLOAD_WIDTH
                ));
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut serialized_header = Vec::with_capacity(std::mem::size_of::<Header>()); //
        serialized_header.write_all(&self.magic).unwrap();
        serialized_header.write_all(&self.command_name).unwrap();
        serialized_header
            .write_u32::<LittleEndian>(self.payload_size)
            .unwrap();
        serialized_header.write_all(&self.checksum).unwrap();
        serialized_header
    }

    /// Generates a Header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() > Header::HEADER_WIDTH {
            panic!("too small!");
        }

        let mut current_byte: usize = 0;

        let magic: [u8; Self::MAGIC_WIDTH] =
            bytes[current_byte..Self::MAGIC_WIDTH].try_into().unwrap();
        current_byte += Self::MAGIC_WIDTH;

        let command_name: [u8; Self::COMMAND_NAME_WIDTH] = bytes
            [current_byte..current_byte + Self::COMMAND_NAME_WIDTH]
            .try_into()
            .unwrap();
        current_byte += Self::COMMAND_NAME_WIDTH;

        let payload_size: u32 = LittleEndian::read_u32(
            &bytes[current_byte..current_byte + std::mem::size_of::<u32>()],
        );
        current_byte += std::mem::size_of::<u32>();

        let checksum: [u8; Self::CHECKSUM_WIDTH] = bytes
            [current_byte..current_byte + Header::CHECKSUM_WIDTH]
            .try_into()
            .unwrap();

        current_byte += Self::CHECKSUM_WIDTH;
        assert!(current_byte == Self::HEADER_WIDTH);

        println!(
            "command received:::: {:?}",
            String::from_utf8_lossy(&command_name)
        );

        Self {
            magic,
            command_name,
            payload_size,
            checksum,
        }
    }

    /// Generates a [u8; 12] from an ascii string, padding with 0s when needed.
    fn command_name_from_str(name: &str) -> Result<[u8; 12], String> {
        const NAME_LEN: usize = 12;

        if !name.is_ascii() {
            return Err(format!(
                "Name: {name} should only contain ASCII characters.",
            ));
        }

        if name.len() > NAME_LEN {
            return Err(format!(
                "Name: {name} has length {} which is more than the allowed max {}.",
                name.len(),
                NAME_LEN
            ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_test() {}
}

/// A serialized message that can be sent over the wire.
pub fn generate_message<T: Message>(message: &T) -> Vec<u8> {
    let payload = message.payload();
    let header = Header::new(message.name(), payload.as_ref()).unwrap();

    // todo: port to test.
    // let testing = header.to_bytes();
    // println!("header generated::: \n{:02x?}", testing);
    // let testing2 = Header::from_bytes(&testing);
    // let testing3 = testing2.to_bytes();
    // if testing != testing3 {
    //     eprintln!("not equal!!!!!!!!!!!")
    // }

    let mut header_bytes = header.to_bytes();

    // message has a payload/body: append it after the header.
    if let Some(p) = payload {
        // println!("payload:: {:02x?}", p);
        header_bytes.extend(p);
        // println!("");
    }
    header_bytes
}

#[derive(Debug)]
pub struct VersionMessage {
    version: i32,
    service: u64,
    timestamp: i64,
    addr_recv_services: u64,
    addr_recv_ip: [u8; 16], // Note: big endian
    addr_recv_port: u16,    // Note: big endian,
    addr_trans_services: u64,
    addr_trans_ip: [u8; 16], // Note: big endian,
    addr_trans_port: u16,    // Note: big endian,
    nonce: u64,
    user_agent_bytes: u8,
    user_agent_str: Option<String>,
    start_height: i32,
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
        // [b'v', b'e', b'r', b's', b'i', b'o', b'n', b'0', b'0', b'0', b'0', b'0']
        "version"
    }

    fn payload(&self) -> Option<Vec<u8>> {
        let mut payload: Vec<u8> = Vec::with_capacity(std::mem::size_of::<VersionMessage>()); // ; // todo, capacity.

        payload.write_i32::<LittleEndian>(self.version).unwrap();
        payload.write_u64::<LittleEndian>(self.service).unwrap();
        payload.write_i64::<LittleEndian>(self.timestamp).unwrap();

        // rx end
        payload
            .write_u64::<LittleEndian>(self.addr_recv_services)
            .unwrap();
        payload
            .write_u128::<BigEndian>(u128::from_ne_bytes(self.addr_recv_ip))
            .unwrap();
        payload.write_u16::<BigEndian>(self.addr_recv_port).unwrap();

        // tx end
        payload
            .write_u64::<LittleEndian>(self.addr_trans_services)
            .unwrap();
        payload
            .write_u128::<BigEndian>(u128::from_ne_bytes(self.addr_trans_ip))
            .unwrap();
        payload
            .write_u16::<BigEndian>(self.addr_trans_port)
            .unwrap();

        payload.write_u64::<LittleEndian>(self.nonce).unwrap();

        if let Some(user) = &self.user_agent_str {
            payload.write_u8(self.user_agent_bytes).unwrap();
            payload.write_all(user.as_bytes()).unwrap();
        } else {
            // indicate that there are no user agent
            payload.push(0);
        }
        payload
            .write_i32::<LittleEndian>(self.start_height)
            .unwrap();
        payload.write_u8(self.relay.into()).unwrap();

        Some(payload)
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

    fn payload(&self) -> Option<Vec<u8>> {
        None
    }
}
