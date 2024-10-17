use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt::Debug;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use x25519_dalek::{PublicKey, StaticSecret};

use tracing::{debug, error, info, instrument, trace, warn};

pub use bincode;
pub use serde;
pub use tracing;

pub const MAX_DATA_LENGTH: u32 = 1024 * 1024 * 12;
const KEY_EXCHANGE_PACKET_TYPE: u8 = 0;

#[derive(thiserror::Error, Debug)]
pub enum PacketError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid packet type: {0}")]
    InvalidPacketType(u8),
    #[error("Data length exceeds maximum allowed size")]
    DataTooLarge,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
}

pub type Result<T> = std::result::Result<T, PacketError>;

#[derive(Debug, Clone, Copy)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Serialize, Deserialize)]
enum InternalPacket {
    KeyExchange(Vec<u8>),
}

pub trait Packet: Send + Sync + Sized + Debug {
    fn serialize(&self) -> Result<Vec<u8>>;
    fn deserialize(data: &[u8]) -> Result<Self>;
}

pub struct EncryptedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    stream: S,
    cipher_read: XChaCha20Poly1305,
    cipher_write: XChaCha20Poly1305,
}

type KeyValidator = Option<Box<dyn Fn(&PublicKey) -> Result<()> + Send>>;

impl<S> EncryptedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    #[instrument(level = "info", skip(stream, key_validator, static_secret), fields(role = ?role))]
    pub async fn new(
        mut stream: S,
        role: Role,
        static_secret: Option<StaticSecret>,
        key_validator: KeyValidator,
    ) -> Result<Self> {
        info!("Initializing EncryptedStream");
        let local_private_key = static_secret.unwrap_or_else(|| {
            debug!("Generating new static secret");
            StaticSecret::random_from_rng(OsRng)
        });
        let local_public_key = PublicKey::from(&local_private_key);
        debug!("Local public key generated");

        let remote_public_key_bytes = match role {
            Role::Client => {
                info!("Role: Client - initiating key exchange");
                let public_key_bytes = local_public_key.as_bytes().to_vec();
                let key_exchange_packet = InternalPacket::KeyExchange(public_key_bytes);
                write_packet_unencrypted(&mut stream, &key_exchange_packet).await?;

                let packet = read_packet_unencrypted(&mut stream).await?;
                match packet {
                    InternalPacket::KeyExchange(bytes) => bytes,
                }
            }
            Role::Server => {
                info!("Role: Server - responding to key exchange");
                let packet = read_packet_unencrypted(&mut stream).await?;
                let InternalPacket::KeyExchange(remote_public_key_bytes) = packet;

                let public_key_bytes = local_public_key.as_bytes().to_vec();
                let key_exchange_packet = InternalPacket::KeyExchange(public_key_bytes);
                write_packet_unencrypted(&mut stream, &key_exchange_packet).await?;

                remote_public_key_bytes
            }
        };

        trace!("Remote public key bytes: {:?}", remote_public_key_bytes);

        if remote_public_key_bytes.len() != 32 {
            error!(
                "Invalid public key length: expected 32, got {}",
                remote_public_key_bytes.len()
            );
            return Err(PacketError::Deserialization(
                "Invalid public key length".into(),
            ));
        }

        let remote_public_key_array: [u8; 32] =
            remote_public_key_bytes.as_slice().try_into().map_err(|_| {
                error!("Failed to convert remote public key bytes to array");
                PacketError::Deserialization("Invalid public key".into())
            })?;
        let remote_public_key = PublicKey::from(remote_public_key_array);
        debug!("Remote public key deserialized successfully");

        if let Some(ref validator) = key_validator {
            info!("Validating remote public key");
            validator(&remote_public_key)?;
            debug!("Remote public key validated successfully");
        } else {
            debug!("No key validator provided");
        }

        let shared_secret = local_private_key.diffie_hellman(&remote_public_key);
        let shared_secret_bytes = shared_secret.as_bytes();
        debug!("Shared secret computed via Diffie-Hellman");

        let (cipher_read, cipher_write) = derive_keys(shared_secret_bytes, role)?;

        info!("Key derivation and cipher initialization completed successfully");

        Ok(Self {
            stream,
            cipher_read,
            cipher_write,
        })
    }

    #[instrument(level = "info", skip(self))]
    pub fn split(self) -> (EncryptedReader<ReadHalf<S>>, EncryptedWriter<WriteHalf<S>>) {
        info!("Splitting EncryptedStream into reader and writer");
        let (read_half, write_half) = io::split(self.stream);

        let reader = EncryptedReader {
            stream: read_half,
            cipher: self.cipher_read,
        };

        let writer = EncryptedWriter {
            stream: write_half,
            cipher: self.cipher_write,
        };

        (reader, writer)
    }

    pub async fn read_packet<P: Packet>(&mut self) -> Result<P> {
        let data = read_message(&mut self.stream, &self.cipher_read).await?;
        P::deserialize(&data)
    }

    pub async fn write_packet(&mut self, packet: &impl Packet) -> Result<()> {
        let data = packet.serialize()?;
        write_message(&mut self.stream, &self.cipher_write, &data).await
    }
}

pub struct EncryptedReader<R>
where
    R: AsyncRead + Unpin + Send,
{
    stream: R,
    cipher: XChaCha20Poly1305,
}

impl<R> EncryptedReader<R>
where
    R: AsyncRead + Unpin + Send,
{
    pub async fn read_packet<P: Packet>(&mut self) -> Result<P> {
        let data = read_message(&mut self.stream, &self.cipher).await?;
        P::deserialize(&data)
    }
}

pub struct EncryptedWriter<W>
where
    W: AsyncWrite + Unpin + Send,
{
    stream: W,
    cipher: XChaCha20Poly1305,
}

impl<W> EncryptedWriter<W>
where
    W: AsyncWrite + Unpin + Send,
{
    pub async fn write_packet(&mut self, packet: &impl Packet) -> Result<()> {
        let data = packet.serialize()?;
        write_message(&mut self.stream, &self.cipher, &data).await
    }
}

async fn read_message<R: AsyncRead + Unpin>(
    stream: &mut R,
    cipher: &XChaCha20Poly1305,
) -> Result<Vec<u8>> {
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes).await?;
    let length = u32::from_le_bytes(length_bytes) as usize;

    if length > MAX_DATA_LENGTH as usize {
        return Err(PacketError::DataTooLarge);
    }

    let mut nonce_bytes = [0u8; 24];
    stream.read_exact(&mut nonce_bytes).await?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let mut buffer = vec![0u8; length];
    stream.read_exact(&mut buffer).await?;

    let plaintext = cipher.decrypt(nonce, buffer.as_ref()).map_err(|e| {
        error!("Decryption failed: {}", e);
        PacketError::DecryptionFailed(e.to_string())
    })?;

    Ok(plaintext)
}

async fn write_message<W: AsyncWrite + Unpin>(
    stream: &mut W,
    cipher: &XChaCha20Poly1305,
    message: &[u8],
) -> Result<()> {
    if message.len() > MAX_DATA_LENGTH as usize {
        return Err(PacketError::DataTooLarge);
    }

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, message).map_err(|e| {
        error!("Encryption failed: {}", e);
        PacketError::Serialization(format!("Encryption failed: {}", e))
    })?;

    let length = ciphertext.len() as u32;
    if length > MAX_DATA_LENGTH {
        return Err(PacketError::DataTooLarge);
    }

    stream.write_all(&length.to_le_bytes()).await?;
    stream.write_all(&nonce).await?;
    stream.write_all(&ciphertext).await?;
    stream.flush().await?;

    Ok(())
}

#[instrument(level = "debug", skip(stream))]
async fn read_packet_unencrypted<S>(stream: &mut S) -> Result<InternalPacket>
where
    S: AsyncRead + Unpin + Send,
{
    trace!("Reading unencrypted packet");

    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let packet_type_byte = header[0];
    let data_length = u32::from_le_bytes(
        header[1..5]
            .try_into()
            .expect("header[1..5] should be 4 bytes"),
    );
    trace!(
        "Unencrypted packet type byte: {}, data length: {}",
        packet_type_byte,
        data_length
    );

    if packet_type_byte != KEY_EXCHANGE_PACKET_TYPE {
        warn!(
            "Expected key exchange packet type {}, got {}",
            KEY_EXCHANGE_PACKET_TYPE, packet_type_byte
        );
        return Err(PacketError::InvalidPacketType(packet_type_byte));
    }

    if data_length > MAX_DATA_LENGTH {
        warn!(
            "Unencrypted packet data length {} exceeds maximum allowed size {}",
            data_length, MAX_DATA_LENGTH
        );
        return Err(PacketError::DataTooLarge);
    }

    let mut data = vec![0u8; data_length as usize];
    stream.read_exact(&mut data).await?;
    trace!("Read unencrypted packet data: {} bytes", data.len());

    Ok(InternalPacket::KeyExchange(data))
}

#[instrument(level = "debug", skip(stream, packet))]
async fn write_packet_unencrypted<S>(stream: &mut S, packet: &InternalPacket) -> Result<()>
where
    S: AsyncWrite + Unpin + Send,
{
    trace!("Writing unencrypted packet: {:?}", packet);
    let InternalPacket::KeyExchange(data) = packet;

    let data_length = data.len() as u32;
    if data_length > MAX_DATA_LENGTH {
        warn!(
            "Unencrypted packet data length {} exceeds maximum allowed size {}",
            data_length, MAX_DATA_LENGTH
        );
        return Err(PacketError::DataTooLarge);
    }

    let mut buffer = Vec::with_capacity(5 + data.len());
    buffer.push(KEY_EXCHANGE_PACKET_TYPE);
    buffer.extend_from_slice(&data_length.to_le_bytes());
    buffer.extend_from_slice(data);

    stream.write_all(&buffer).await?;
    stream.flush().await?;
    trace!("Wrote unencrypted packet to stream");
    Ok(())
}

fn derive_keys(shared_secret: &[u8], role: Role) -> Result<(XChaCha20Poly1305, XChaCha20Poly1305)> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut client_key = [0u8; 32];
    let mut server_key = [0u8; 32];

    hk.expand(b"client stream key", &mut client_key)
        .map_err(|e| {
            error!("HKDF expand failed for client stream key: {}", e);
            PacketError::KeyDerivationFailed(format!("HKDF expand failed: {}", e))
        })?;
    hk.expand(b"server stream key", &mut server_key)
        .map_err(|e| {
            error!("HKDF expand failed for server stream key: {}", e);
            PacketError::KeyDerivationFailed(format!("HKDF expand failed: {}", e))
        })?;

    let (write_key, read_key) = match role {
        Role::Client => {
            debug!("Client role selected keys");
            (client_key, server_key)
        }
        Role::Server => {
            debug!("Server role selected keys");
            (server_key, client_key)
        }
    };

    Ok((
        XChaCha20Poly1305::new(&read_key.into()),
        XChaCha20Poly1305::new(&write_key.into()),
    ))
}

#[macro_export]
macro_rules! define_packets {
    (
        $(
            $packet_type:ident $(( $data_struct:ty ))?
        ),* $(,)?
    ) => {
        #[derive(Debug, Clone, PartialEq, Eq, $crate::serde::Serialize, $crate::serde::Deserialize)]
        pub enum Packet {
            $(
                $packet_type $(($data_struct))?,
            )*
        }
        impl $crate::Packet for Packet {
            fn serialize(&self) -> $crate::Result<Vec<u8>> {
                $crate::bincode::serialize(self)
                    .map_err(|e| $crate::PacketError::Serialization(e.to_string()))
            }
            fn deserialize(data: &[u8]) -> $crate::Result<Self> {
                $crate::bincode::deserialize(data)
                    .map_err(|e| $crate::PacketError::Deserialization(e.to_string()))
            }
        }
    };
}
