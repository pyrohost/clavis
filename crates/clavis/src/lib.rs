//! # Clavis Library
//!
//! The Clavis library provides a secure and efficient abstraction, `EncryptedStream`, over asynchronous streams. It enables encrypted and authenticated communication using the XChaCha20Poly1305 algorithm, ensuring both data integrity and confidentiality.
//!
//! ## Usage Example
//!
//! Below is an example demonstrating how to set up a secure communication channel over a TCP connection using Clavis:
//!
//! ```rust,no_run
//! use clavis::{EncryptedStream, Role, define_packets};
//! use tokio::net::TcpStream;
//!
//! // Define a custom message structure
//! #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
//! struct Message {
//!     content: String,
//! }
//!
//! // Use the define_packets! macro to create a custom packet enum
//! define_packets! {
//!     enum MyPacket {
//!         VoidMessage,
//!         Message(String),
//!         StructMessage(Message),
//!         StructuredMessage { content: String },
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Establish a TCP connection
//!     let stream = TcpStream::connect("127.0.0.1:8080").await?;
//!
//!     // Define a pre-shared key (PSK)
//!     let psk = b"my_secret_psk";
//!
//!     // Create an EncryptedStream and split it into reader and writer
//!     let (mut reader, mut writer) = EncryptedStream::new(stream, Role::Client, Some(psk))
//!         .await?
//!         .split();
//!
//!     // Send an encrypted message
//!     writer.write_packet(&MyPacket::Message("Hello, server!".to_string())).await?;
//!
//!     // Receive and decrypt a response
//!     let response: MyPacket = reader.read_packet().await?;
//!     println!("Received response: {:?}", response);
//!
//!     Ok(())
//! }
//! ```
//!
//! This example illustrates how to create an encrypted communication channel, send a message, and handle a response securely.
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use x25519_dalek::{EphemeralSecret, PublicKey};

use hmac::{Hmac, Mac};
use tracing::{debug, error, info, instrument, trace, warn};

type HmacSha256 = Hmac<Sha256>;

pub use bincode;
pub use serde;
pub use tracing;

/// Maximum allowed data length for packets (12 MiB).
pub const MAX_DATA_LENGTH: u32 = 1024 * 1024 * 12;

/// Protocol version.
const PROTOCOL_VERSION: u8 = 1;

/// Packet types used in the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketType {
    KeyExchange = 0,
    Data = 1,
}

impl TryFrom<u8> for PacketType {
    type Error = PacketError;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(PacketType::KeyExchange),
            1 => Ok(PacketType::Data),
            _ => Err(PacketError::InvalidPacketType(value)),
        }
    }
}

/// Custom error type for packet and encryption operations.
#[derive(thiserror::Error, Debug)]
pub enum PacketError {
    #[error("IO error")]
    Io(#[from] std::io::Error),
    #[error("Invalid packet type")]
    InvalidPacketType(u8),
    #[error("Data length exceeds maximum allowed size")]
    DataTooLarge,
    #[error("Serialization error")]
    Serialization,
    #[error("Deserialization error")]
    Deserialization,
    #[error("Encryption error")]
    Encryption,
    #[error("Decryption error")]
    Decryption,
    #[error("Key derivation error")]
    KeyDerivation,
    #[error("Protocol error")]
    Protocol,
    #[error("Replay attack detected")]
    ReplayAttack,
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Sequence number overflow")]
    SequenceOverflow,
}

pub type Result<T> = std::result::Result<T, PacketError>;

/// Role of the peer in the encrypted communication (Client or Server).
#[derive(Debug, Clone, Copy)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyExchangePacket {
    version: u8,
    ephemeral_public_key: [u8; 32],
    sequence_number: u64,
}

impl KeyExchangePacket {
    fn new(ephemeral_public_key: [u8; 32], sequence_number: u64) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ephemeral_public_key,
            sequence_number,
        }
    }
}

/// Trait that defines serialization and deserialization for packets.
pub trait PacketTrait: Send + Sync + Sized + Debug {
    /// Serializes the packet into a byte vector.
    fn serialize(&self) -> Result<Vec<u8>>;
    /// Deserializes the packet from a byte slice.
    fn deserialize(data: &[u8]) -> Result<Self>;
}

impl PacketTrait for KeyExchangePacket {
    fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|_| PacketError::Serialization)
    }

    fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|_| PacketError::Deserialization)
    }
}

/// Encrypted stream for secure communication over an underlying asynchronous stream.
///
/// This struct provides methods to read and write encrypted packets over a stream.
/// It handles key exchange, encryption/decryption, and sequence number management.
///
/// # Type Parameters
///
/// - `S`: The underlying stream type, which must implement `AsyncRead + AsyncWrite + Unpin + Send`.
pub struct EncryptedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    stream: S,
    cipher_enc: XChaCha20Poly1305,
    cipher_dec: XChaCha20Poly1305,
    send_sequence: u64,
    recv_sequence: u64,
}

impl<S> EncryptedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Creates a new `EncryptedStream` by performing an authenticated key exchange.
    ///
    /// # Arguments
    ///
    /// - `stream`: The underlying asynchronous stream.
    /// - `role`: The role of this peer (`Role::Client` or `Role::Server`).
    /// - `psk`: The optional pre-shared key for authentication. Strongly recommended.
    #[instrument(level = "info", skip(stream, psk), fields(role = ?role))]
    pub async fn new(mut stream: S, role: Role, psk: Option<&[u8]>) -> Result<Self> {
        info!("Initializing EncryptedStream");
        if psk.is_none() {
            warn!("PSK is None; key exchange is unauthenticated. MITM attacks are possible!");
        }

        let local_ephemeral_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let local_ephemeral_public = PublicKey::from(&local_ephemeral_secret);
        debug!("Local ephemeral public key generated");

        // Initialize sequence numbers
        let send_sequence = 0u64;
        let recv_sequence;

        let (shared_secret, remote_ephemeral_public) = match role {
            Role::Client => {
                info!("Role: Client - initiating key exchange");
                let key_exchange_packet =
                    KeyExchangePacket::new(*local_ephemeral_public.as_bytes(), send_sequence);
                write_packet_unencrypted(&mut stream, &key_exchange_packet, psk).await?;

                let remote_packet: KeyExchangePacket =
                    read_packet_unencrypted(&mut stream, psk).await?;
                if remote_packet.version != PROTOCOL_VERSION {
                    return Err(PacketError::Protocol);
                }

                let remote_ephemeral_public = PublicKey::from(remote_packet.ephemeral_public_key);
                let shared_secret = local_ephemeral_secret.diffie_hellman(&remote_ephemeral_public);

                recv_sequence = remote_packet.sequence_number;

                (shared_secret, remote_ephemeral_public)
            }
            Role::Server => {
                info!("Role: Server - responding to key exchange");
                let remote_packet: KeyExchangePacket =
                    read_packet_unencrypted(&mut stream, psk).await?;
                if remote_packet.version != PROTOCOL_VERSION {
                    return Err(PacketError::Protocol);
                }

                let remote_ephemeral_public = PublicKey::from(remote_packet.ephemeral_public_key);
                let shared_secret = local_ephemeral_secret.diffie_hellman(&remote_ephemeral_public);

                recv_sequence = remote_packet.sequence_number;

                let key_exchange_packet =
                    KeyExchangePacket::new(*local_ephemeral_public.as_bytes(), send_sequence);
                write_packet_unencrypted(&mut stream, &key_exchange_packet, psk).await?;

                (shared_secret, remote_ephemeral_public)
            }
        };

        debug!("Shared secret computed via Diffie-Hellman");

        // Compute the salt using both ephemeral public keys
        let salt = compute_salt(
            local_ephemeral_public.as_bytes(),
            remote_ephemeral_public.as_bytes(),
            psk,
        )?;

        let (cipher_enc, cipher_dec) = derive_ciphers(shared_secret.as_bytes(), role, &salt)?;

        info!("Key derivation and cipher initialization completed successfully");

        Ok(Self {
            stream,
            cipher_enc,
            cipher_dec,
            send_sequence,
            recv_sequence,
        })
    }

    /// Splits the `EncryptedStream` into an `EncryptedReader` and an `EncryptedWriter`.
    #[instrument(level = "info", skip(self))]
    pub fn split(self) -> (EncryptedReader<ReadHalf<S>>, EncryptedWriter<WriteHalf<S>>) {
        info!("Splitting EncryptedStream into reader and writer");
        let (read_half, write_half) = io::split(self.stream);

        let reader = EncryptedReader {
            stream: read_half,
            cipher_dec: self.cipher_dec,
            recv_sequence: self.recv_sequence,
        };

        let writer = EncryptedWriter {
            stream: write_half,
            cipher_enc: self.cipher_enc,
            send_sequence: self.send_sequence,
        };

        (reader, writer)
    }

    /// Reads a packet from the encrypted stream.
    pub async fn read_packet<P: PacketTrait>(&mut self) -> Result<P> {
        let (data, sequence_number) = read_message(&mut self.stream, &self.cipher_dec).await?;
        if sequence_number <= self.recv_sequence {
            return Err(PacketError::ReplayAttack);
        }
        self.recv_sequence = sequence_number;
        P::deserialize(&data)
    }

    /// Writes a packet to the encrypted stream.
    pub async fn write_packet(&mut self, packet: &impl PacketTrait) -> Result<()> {
        if self.send_sequence == u64::MAX {
            return Err(PacketError::SequenceOverflow);
        }
        self.send_sequence = self.send_sequence.wrapping_add(1);
        let data = packet.serialize()?;
        write_message(
            &mut self.stream,
            &self.cipher_enc,
            &data,
            self.send_sequence,
        )
        .await
    }
}

/// Encrypted reader for reading packets from the encrypted stream.
///
/// # Type Parameters
///
/// - `R`: The underlying reader type, which must implement `AsyncRead + Unpin + Send`.
pub struct EncryptedReader<R>
where
    R: AsyncRead + Unpin + Send,
{
    stream: R,
    cipher_dec: XChaCha20Poly1305,
    recv_sequence: u64,
}

impl<R> EncryptedReader<R>
where
    R: AsyncRead + Unpin + Send,
{
    /// Reads a packet from the encrypted reader.
    pub async fn read_packet<P: PacketTrait>(&mut self) -> Result<P> {
        let (data, sequence_number) = read_message(&mut self.stream, &self.cipher_dec).await?;
        if sequence_number <= self.recv_sequence {
            return Err(PacketError::ReplayAttack);
        }
        self.recv_sequence = sequence_number;
        P::deserialize(&data)
    }
}

/// Encrypted writer for writing packets to the encrypted stream.
///
/// # Type Parameters
///
/// - `W`: The underlying writer type, which must implement `AsyncWrite + Unpin + Send`.
pub struct EncryptedWriter<W>
where
    W: AsyncWrite + Unpin + Send,
{
    stream: W,
    cipher_enc: XChaCha20Poly1305,
    send_sequence: u64,
}

impl<W> EncryptedWriter<W>
where
    W: AsyncWrite + Unpin + Send,
{
    /// Writes a packet to the encrypted writer.
    pub async fn write_packet(&mut self, packet: &impl PacketTrait) -> Result<()> {
        if self.send_sequence == u64::MAX {
            return Err(PacketError::SequenceOverflow);
        }
        self.send_sequence = self.send_sequence.wrapping_add(1);
        let data = packet.serialize()?;
        write_message(
            &mut self.stream,
            &self.cipher_enc,
            &data,
            self.send_sequence,
        )
        .await
    }
}

/// Reads an encrypted message from the stream.
async fn read_message<R: AsyncRead + Unpin>(
    stream: &mut R,
    cipher: &XChaCha20Poly1305,
) -> Result<(Vec<u8>, u64)> {
    // Read length and nonce together to minimize system calls
    let mut header = [0u8; 4 + 24];
    stream.read_exact(&mut header).await?;

    let length = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;

    if length > MAX_DATA_LENGTH as usize {
        return Err(PacketError::DataTooLarge);
    }

    let nonce = XNonce::from_slice(&header[4..]);

    let mut ciphertext = vec![0u8; length];
    stream.read_exact(&mut ciphertext).await?;

    let plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).map_err(|_| {
        error!("Decryption failed");
        PacketError::Decryption
    })?;

    if plaintext.len() < 8 {
        return Err(PacketError::Protocol);
    }

    let sequence_number = u64::from_le_bytes(plaintext[..8].try_into().unwrap());

    let message = plaintext[8..].to_vec();

    Ok((message, sequence_number))
}

/// Writes an encrypted message to the stream.
async fn write_message<W: AsyncWrite + Unpin>(
    stream: &mut W,
    cipher: &XChaCha20Poly1305,
    message: &[u8],
    sequence_number: u64,
) -> Result<()> {
    if message.len() > MAX_DATA_LENGTH as usize - 8 {
        return Err(PacketError::DataTooLarge);
    }

    // Prepare sequence_message
    let mut sequence_message = Vec::with_capacity(8 + message.len());
    sequence_message.extend_from_slice(&sequence_number.to_le_bytes());
    sequence_message.extend_from_slice(message);

    // Prepare nonce
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..8].copy_from_slice(&sequence_number.to_le_bytes());
    OsRng.fill_bytes(&mut nonce_bytes[8..]);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, sequence_message.as_slice())
        .map_err(|_| {
            error!("Encryption failed");
            PacketError::Encryption
        })?;

    let length = ciphertext.len() as u32;
    if length > MAX_DATA_LENGTH {
        return Err(PacketError::DataTooLarge);
    }

    // Prepare the entire message buffer to minimize system calls
    let mut buffer = Vec::with_capacity(4 + 24 + ciphertext.len());
    buffer.extend_from_slice(&length.to_le_bytes());
    buffer.extend_from_slice(&nonce_bytes);
    buffer.extend_from_slice(&ciphertext);

    // Write the buffer in one call
    stream.write_all(&buffer).await?;
    stream.flush().await?;

    Ok(())
}

/// Reads an unencrypted packet from the stream during key exchange.
async fn read_packet_unencrypted<S, P: PacketTrait>(stream: &mut S, psk: Option<&[u8]>) -> Result<P>
where
    S: AsyncRead + Unpin + Send,
{
    trace!("Reading unencrypted packet");

    // Read packet_type and data_length together
    let mut header = [0u8; 1 + 4];
    stream.read_exact(&mut header).await?;
    let packet_type_byte = header[0];
    let _packet_type = PacketType::try_from(packet_type_byte)?;

    let data_length = u32::from_le_bytes(header[1..].try_into().unwrap());

    trace!(
        "Unencrypted packet type: {:?}, data length: {}",
        _packet_type,
        data_length
    );

    if data_length > MAX_DATA_LENGTH {
        return Err(PacketError::DataTooLarge);
    }

    let mut data = vec![0u8; data_length as usize];
    stream.read_exact(&mut data).await?;

    let mut hmac_bytes = [0u8; 32];
    stream.read_exact(&mut hmac_bytes).await?;

    if let Some(psk) = psk {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(psk).map_err(|_| PacketError::KeyDerivation)?;
        mac.update(&header);
        mac.update(&data);
        mac.verify_slice(&hmac_bytes)
            .map_err(|_| PacketError::AuthenticationFailed)?;
    }

    trace!("Read unencrypted packet data");

    P::deserialize(&data)
}

/// Writes an unencrypted packet to the stream during key exchange.
async fn write_packet_unencrypted<S, P: PacketTrait>(
    stream: &mut S,
    packet: &P,
    psk: Option<&[u8]>,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send,
{
    trace!("Writing unencrypted packet");

    let data = packet.serialize()?;
    let data_length = data.len() as u32;
    if data_length > MAX_DATA_LENGTH {
        return Err(PacketError::DataTooLarge);
    }

    let packet_type_byte = PacketType::KeyExchange as u8;
    let length_bytes = data_length.to_le_bytes();

    // Prepare HMAC data
    let mut hmac_data = Vec::with_capacity(1 + 4 + data.len());
    hmac_data.push(packet_type_byte);
    hmac_data.extend_from_slice(&length_bytes);
    hmac_data.extend_from_slice(&data);

    let hmac = if let Some(psk) = psk {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(psk).map_err(|_| PacketError::KeyDerivation)?;
        mac.update(&hmac_data);
        mac.finalize().into_bytes()
    } else {
        [0u8; 32].into()
    };

    // Prepare the entire buffer to minimize system calls
    let mut buffer = Vec::with_capacity(hmac_data.len() + 32);
    buffer.extend_from_slice(&hmac_data);
    buffer.extend_from_slice(&hmac);

    stream.write_all(&buffer).await?;
    stream.flush().await?;

    trace!("Wrote unencrypted packet to stream");
    Ok(())
}

/// Computes the salt using both local and remote ephemeral public keys and the PSK.
fn compute_salt(
    local_pub_key: &[u8],
    remote_pub_key: &[u8],
    psk: Option<&[u8]>,
) -> Result<[u8; 32]> {
    let mut keys = [0u8; 64];
    if local_pub_key <= remote_pub_key {
        keys[..32].copy_from_slice(local_pub_key);
        keys[32..].copy_from_slice(remote_pub_key);
    } else {
        keys[..32].copy_from_slice(remote_pub_key);
        keys[32..].copy_from_slice(local_pub_key);
    }
    let hash = Sha256::digest(&keys);

    let salt = if let Some(psk) = psk {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(psk).map_err(|_| PacketError::KeyDerivation)?;
        mac.update(&hash);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&code_bytes);
        salt
    } else {
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&hash);
        salt
    };

    Ok(salt)
}

/// Derives encryption keys from the shared secret using HKDF.
fn derive_ciphers(
    shared_secret: &[u8],
    role: Role,
    salt: &[u8],
) -> Result<(XChaCha20Poly1305, XChaCha20Poly1305)> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);

    let mut key_material = [0u8; 64]; // 32 bytes for each key
    hk.expand(b"key expansion", &mut key_material)
        .map_err(|_| PacketError::KeyDerivation)?;

    let (key1_bytes, key2_bytes) = key_material.split_at(32);

    let cipher1 = XChaCha20Poly1305::new(key1_bytes.into());
    let cipher2 = XChaCha20Poly1305::new(key2_bytes.into());

    // Assign ciphers based on role
    let (cipher_enc, cipher_dec) = match role {
        Role::Client => (cipher1, cipher2),
        Role::Server => (cipher2, cipher1),
    };

    Ok((cipher_enc, cipher_dec))
}

#[macro_export]
macro_rules! define_packets {
    (
        $(
            $(#[$enum_meta:meta])*
            $enum_vis:vis enum $enum_name:ident {
                $(
                    $(#[$variant_meta:meta])*
                    $variant_vis:vis $variant:ident
                    $(($inner:ty))?
                    $({ $( $field_vis:vis $field:ident : $ftype:ty ),+ $(,)? })?
                ),* $(,)?
            }
        )*
    ) => {
        $(
            #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                $(
                    $(#[$variant_meta])*
                    $variant_vis $variant
                    $(($inner))?
                    $({ $( $field_vis $field : $ftype ),+ })?,
                )*
            }

            impl $crate::PacketTrait for $enum_name {
                fn serialize(&self) -> $crate::Result<Vec<u8>> {
                    $crate::bincode::serialize(self).map_err(|_| {
                        $crate::PacketError::Serialization
                    })
                }
                fn deserialize(data: &[u8]) -> $crate::Result<Self> {
                    $crate::bincode::deserialize(data).map_err(|_| {
                        $crate::PacketError::Deserialization
                    })
                }
            }

            impl std::fmt::Display for $enum_name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "{:?}", self)
                }
            }
        )*
    };
}