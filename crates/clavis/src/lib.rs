use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt::Debug;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use x25519_dalek::{PublicKey, StaticSecret};

use tracing::{debug, error, info, instrument, trace, warn};

pub use bincode;
pub use serde;
pub use tracing;

pub const MAX_DATA_LENGTH: u32 = 1024 * 1024 * 12;
const KEY_EXCHANGE_PACKET_TYPE: u8 = 0;

#[derive(Error, Debug)]
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
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
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
    fn packet_type(&self) -> u8;
    fn serialize(&self) -> Result<Vec<u8>>;
    fn deserialize(packet_type: u8, data: &[u8]) -> Result<Self>;
}

pub struct EncryptedPacketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    stream: S,
    cipher_read: Arc<Aes256GcmSiv>,
    cipher_write: Arc<Aes256GcmSiv>,
}

type KeyValidator = Option<Box<dyn Fn(&PublicKey) -> Result<()> + Send>>;

impl<S> EncryptedPacketStream<S>
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
        info!("Initializing EncryptedPacketStream");
        let local_private_key = match static_secret {
            Some(secret) => {
                debug!("Using provided static secret");
                secret
            }
            None => {
                debug!("Generating new static secret");
                StaticSecret::random_from_rng(OsRng)
            }
        };
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

        let hk = Hkdf::<Sha256>::new(None, shared_secret_bytes);
        let mut client_write_key = [0u8; 32];
        let mut server_write_key = [0u8; 32];

        hk.expand(b"client write key", &mut client_write_key)
            .map_err(|_| {
                error!("HKDF expand failed for client write key");
                PacketError::KeyDerivationFailed
            })?;
        hk.expand(b"server write key", &mut server_write_key)
            .map_err(|_| {
                error!("HKDF expand failed for server write key");
                PacketError::KeyDerivationFailed
            })?;

        let (write_key, read_key) = match role {
            Role::Client => {
                debug!("Client role selected keys");
                (client_write_key, server_write_key)
            }
            Role::Server => {
                debug!("Server role selected keys");
                (server_write_key, client_write_key)
            }
        };

        let cipher_read = Arc::new(
            Aes256GcmSiv::new_from_slice(&read_key)
                .map_err(|_| PacketError::KeyDerivationFailed)?,
        );
        let cipher_write = Arc::new(
            Aes256GcmSiv::new_from_slice(&write_key)
                .map_err(|_| PacketError::KeyDerivationFailed)?,
        );

        info!("Key derivation and cipher initialization completed successfully");

        Ok(Self {
            stream,
            cipher_read,
            cipher_write,
        })
    }

    #[instrument(level = "info", skip(self))]
    pub fn split(
        self,
    ) -> (
        EncryptedPacketReader<ReadHalf<S>>,
        EncryptedPacketWriter<WriteHalf<S>>,
    ) {
        info!("Splitting EncryptedPacketStream into reader and writer");
        let EncryptedPacketStream {
            stream,
            cipher_read,
            cipher_write,
        } = self;
        let (read_half, write_half) = io::split(stream);

        let reader = EncryptedPacketReader {
            stream: read_half,
            cipher_read,
        };

        let writer = EncryptedPacketWriter {
            stream: write_half,
            cipher_write,
        };

        (reader, writer)
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn read_packet<P>(&mut self) -> Result<P>
    where
        P: Packet,
    {
        trace!("Preparing to read a packet");

        let mut header = [0u8; 5];
        self.stream.read_exact(&mut header).await?;
        let packet_type_byte = header[0];
        let data_length = u32::from_le_bytes(header[1..5].try_into().unwrap());
        trace!(
            "Read packet type: {}, data length: {}",
            packet_type_byte,
            data_length
        );

        if packet_type_byte == KEY_EXCHANGE_PACKET_TYPE {
            warn!("Received unexpected key exchange packet type during encrypted communication");
            return Err(PacketError::InvalidPacketType(packet_type_byte));
        }

        if data_length > MAX_DATA_LENGTH {
            warn!(
                "Data length {} exceeds maximum allowed size {}",
                data_length, MAX_DATA_LENGTH
            );
            return Err(PacketError::DataTooLarge);
        }

        if data_length < 12 {
            error!("Encrypted data is too short: {}", data_length);
            return Err(PacketError::Deserialization("Data too short".into()));
        }

        let mut nonce_bytes = [0u8; 12];
        self.stream.read_exact(&mut nonce_bytes).await?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        trace!("Nonce extracted for decryption");

        let ciphertext_length = data_length as usize - 12;
        let mut ciphertext = vec![0u8; ciphertext_length];
        self.stream.read_exact(&mut ciphertext).await?;
        trace!("Read encrypted data: {} bytes", ciphertext.len());

        let associated_data = &[packet_type_byte];
        trace!("Associated data for decryption: {:?}", associated_data);

        let plaintext = self
            .cipher_read
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|e| {
                error!("Decryption failed: {}", e);
                PacketError::DecryptionFailed
            })?;
        trace!("Decryption successful");

        let packet = P::deserialize(packet_type_byte, &plaintext)?;
        Ok(packet)
    }

    #[instrument(level = "debug", skip(self, packet))]
    pub async fn write_packet<P>(&mut self, packet: &P) -> Result<()>
    where
        P: Packet,
    {
        trace!("Preparing to write a packet: {:?}", packet);

        let data = packet.serialize()?;
        trace!("Serialized packet data");

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        trace!("Generated nonce for encryption");

        let packet_type_byte = packet.packet_type();
        trace!("Packet type byte: {}", packet_type_byte);

        if packet_type_byte == KEY_EXCHANGE_PACKET_TYPE {
            warn!("Attempted to write a key exchange packet during encrypted communication");
            return Err(PacketError::InvalidPacketType(packet_type_byte));
        }

        let associated_data = &[packet_type_byte];
        trace!("Associated data for encryption: {:?}", associated_data);

        let ciphertext = self
            .cipher_write
            .encrypt(
                nonce,
                Payload {
                    msg: data.as_ref(),
                    aad: associated_data,
                },
            )
            .map_err(|e| {
                error!("Encryption failed: {}", e);
                PacketError::Serialization("Encryption failed".into())
            })?;
        trace!("Encryption successful");

        let data_length = (nonce_bytes.len() + ciphertext.len()) as u32;
        if data_length > MAX_DATA_LENGTH {
            warn!(
                "Encrypted data length {} exceeds maximum allowed size {}",
                data_length, MAX_DATA_LENGTH
            );
            return Err(PacketError::DataTooLarge);
        }

        let mut header = [0u8; 5];
        header[0] = packet_type_byte;
        header[1..5].copy_from_slice(&data_length.to_le_bytes());
        self.stream.write_all(&header).await?;
        trace!("Wrote packet header");

        self.stream.write_all(&nonce_bytes).await?;
        self.stream.write_all(&ciphertext).await?;
        trace!("Wrote nonce and ciphertext to stream");
        self.stream.flush().await?;
        trace!("Flushed the stream");
        Ok(())
    }
}

pub struct EncryptedPacketReader<R>
where
    R: AsyncRead + Unpin + Send,
{
    stream: R,
    cipher_read: Arc<Aes256GcmSiv>,
}

impl<R> EncryptedPacketReader<R>
where
    R: AsyncRead + Unpin + Send,
{
    #[instrument(level = "debug", skip(self))]
    pub async fn read_packet<P>(&mut self) -> Result<P>
    where
        P: Packet,
    {
        trace!("Reader preparing to read a packet");

        let mut header = [0u8; 5];
        self.stream.read_exact(&mut header).await?;
        let packet_type_byte = header[0];
        let data_length = u32::from_le_bytes(header[1..5].try_into().unwrap());
        trace!(
            "Reader read packet type: {}, data length: {}",
            packet_type_byte,
            data_length
        );

        if packet_type_byte == KEY_EXCHANGE_PACKET_TYPE {
            warn!("Reader received unexpected key exchange packet type");
            return Err(PacketError::InvalidPacketType(packet_type_byte));
        }

        if data_length > MAX_DATA_LENGTH {
            warn!(
                "Reader data length {} exceeds maximum allowed size {}",
                data_length, MAX_DATA_LENGTH
            );
            return Err(PacketError::DataTooLarge);
        }

        if data_length < 12 {
            error!("Encrypted data is too short: {}", data_length);
            return Err(PacketError::Deserialization("Data too short".into()));
        }

        let mut nonce_bytes = [0u8; 12];
        self.stream.read_exact(&mut nonce_bytes).await?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        trace!("Reader extracted nonce");

        let ciphertext_length = data_length as usize - 12;
        let mut ciphertext = vec![0u8; ciphertext_length];
        self.stream.read_exact(&mut ciphertext).await?;
        trace!("Reader read encrypted data: {} bytes", ciphertext.len());

        let associated_data = &[packet_type_byte];
        trace!(
            "Reader associated data for decryption: {:?}",
            associated_data
        );

        let plaintext = self
            .cipher_read
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|e| {
                error!("Reader decryption failed: {}", e);
                PacketError::DecryptionFailed
            })?;
        trace!("Reader decryption successful");

        let packet = P::deserialize(packet_type_byte, &plaintext)?;
        Ok(packet)
    }
}

pub struct EncryptedPacketWriter<W>
where
    W: AsyncWrite + Unpin + Send,
{
    stream: W,
    cipher_write: Arc<Aes256GcmSiv>,
}

impl<W> EncryptedPacketWriter<W>
where
    W: AsyncWrite + Unpin + Send,
{
    #[instrument(level = "debug", skip(self, packet))]
    pub async fn write_packet<P>(&mut self, packet: &P) -> Result<()>
    where
        P: Packet,
    {
        trace!("Writer preparing to write a packet: {:?}", packet);

        let data = packet.serialize()?;
        trace!("Writer serialized packet data");

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        trace!("Writer generated nonce for encryption");

        let packet_type_byte = packet.packet_type();
        trace!("Writer packet type byte: {}", packet_type_byte);

        if packet_type_byte == KEY_EXCHANGE_PACKET_TYPE {
            warn!("Writer attempted to write a key exchange packet during encrypted communication");
            return Err(PacketError::InvalidPacketType(packet_type_byte));
        }

        let associated_data = &[packet_type_byte];
        trace!(
            "Writer associated data for encryption: {:?}",
            associated_data
        );

        let ciphertext = self
            .cipher_write
            .encrypt(
                nonce,
                Payload {
                    msg: data.as_ref(),
                    aad: associated_data,
                },
            )
            .map_err(|e| {
                error!("Writer encryption failed: {}", e);
                PacketError::Serialization("Encryption failed".into())
            })?;
        trace!("Writer encryption successful");

        let data_length = (nonce_bytes.len() + ciphertext.len()) as u32;
        if data_length > MAX_DATA_LENGTH {
            warn!(
                "Writer encrypted data length {} exceeds maximum allowed size {}",
                data_length, MAX_DATA_LENGTH
            );
            return Err(PacketError::DataTooLarge);
        }

        let mut header = [0u8; 5];
        header[0] = packet_type_byte;
        header[1..5].copy_from_slice(&data_length.to_le_bytes());
        self.stream.write_all(&header).await?;
        trace!("Writer wrote packet header");

        self.stream.write_all(&nonce_bytes).await?;
        self.stream.write_all(&ciphertext).await?;
        trace!("Writer wrote nonce and ciphertext to stream");
        self.stream.flush().await?;
        trace!("Writer flushed the stream");
        Ok(())
    }
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
    let data_length = u32::from_le_bytes(header[1..5].try_into().unwrap());
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

    let data = match packet {
        InternalPacket::KeyExchange(data) => data,
    };

    let data_length = data.len() as u32;
    if data_length > MAX_DATA_LENGTH {
        warn!(
            "Unencrypted packet data length {} exceeds maximum allowed size {}",
            data_length, MAX_DATA_LENGTH
        );
        return Err(PacketError::DataTooLarge);
    }

    let mut header = [0u8; 5];
    header[0] = KEY_EXCHANGE_PACKET_TYPE;
    header[1..5].copy_from_slice(&data_length.to_le_bytes());
    stream.write_all(&header).await?;
    trace!("Wrote unencrypted packet header");

    stream.write_all(&data).await?;
    trace!("Wrote unencrypted packet data to stream");
    stream.flush().await?;
    trace!("Flushed the unencrypted stream");
    Ok(())
}

#[macro_export]
macro_rules! define_user_packets {
    (
        $(
            $packet_type:ident = $discriminant:expr => $data_struct:ty
        ),* $(,)?
    ) => {
        #[derive(Debug, Serialize, Deserialize)]
        pub enum UserPacket {
            $(
                $packet_type($data_struct),
            )*
        }

        impl $crate::Packet for UserPacket {
            fn packet_type(&self) -> u8 {
                match self {
                    $(
                        UserPacket::$packet_type(_) => $discriminant,
                    )*
                }
            }

            fn serialize(&self) -> $crate::Result<Vec<u8>> {
                match self {
                    $(
                        UserPacket::$packet_type(data) => $crate::bincode::serialize(data)
                            .map_err(|e| $crate::PacketError::Serialization(e.to_string())),
                    )*
                }
            }

            fn deserialize(packet_type: u8, data: &[u8]) -> $crate::Result<Self> {
                match packet_type {
                    $(
                        $discriminant => {
                            let data = $crate::bincode::deserialize(data)
                                .map_err(|e| $crate::PacketError::Deserialization(e.to_string()))?;
                            Ok(UserPacket::$packet_type(data))
                        },
                    )*
                    _ => {
                        $crate::tracing::warn!("Attempted to deserialize unknown packet type: {}", packet_type);
                        Err($crate::PacketError::InvalidPacketType(packet_type))
                    },
                }
            }
        }
    };
}
