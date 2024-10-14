use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt::Debug;
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

#[derive(Debug)]
pub struct EncryptedPacketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    stream: S,
    read_key: [u8; 32],
    write_key: [u8; 32],
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

        info!("Key derivation completed successfully");

        Ok(Self {
            stream,
            read_key,
            write_key,
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
            read_key,
            write_key,
        } = self;
        let (read_half, write_half) = io::split(stream);

        let reader = EncryptedPacketReader {
            stream: read_half,
            read_key,
        };

        let writer = EncryptedPacketWriter {
            stream: write_half,
            write_key,
        };

        (reader, writer)
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn read_packet<P>(&mut self) -> Result<P>
    where
        P: Packet,
    {
        trace!("Preparing to read a packet");
        let cipher = Aes256GcmSiv::new_from_slice(&self.read_key).map_err(|e| {
            error!("Failed to create cipher: {}", e);
            PacketError::Serialization("Failed to create cipher".into())
        })?;

        let packet_type_byte = read_u8(&mut self.stream).await?;
        trace!("Read packet type: {}", packet_type_byte);

        if packet_type_byte == KEY_EXCHANGE_PACKET_TYPE {
            warn!("Received unexpected key exchange packet type during encrypted communication");
            return Err(PacketError::InvalidPacketType(packet_type_byte));
        }

        let data_length = read_u32(&mut self.stream).await?;
        trace!("Data length: {}", data_length);

        if data_length > MAX_DATA_LENGTH {
            warn!(
                "Data length {} exceeds maximum allowed size {}",
                data_length, MAX_DATA_LENGTH
            );
            return Err(PacketError::DataTooLarge);
        }

        let mut data = vec![0u8; data_length as usize];
        self.stream.read_exact(&mut data).await?;
        trace!("Read encrypted data: {} bytes", data.len());

        if data.len() < 12 {
            error!("Encrypted data is too short: {}", data.len());
            return Err(PacketError::Deserialization("Data too short".into()));
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        trace!("Nonce extracted for decryption");

        let associated_data = &[packet_type_byte];
        trace!("Associated data for decryption: {:?}", associated_data);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
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
        let cipher = Aes256GcmSiv::new_from_slice(&self.write_key).map_err(|e| {
            error!("Failed to create cipher: {}", e);
            PacketError::Serialization("Failed to create cipher".into())
        })?;

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

        let ciphertext = cipher
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

        let encrypted_data = [nonce_bytes.as_ref(), ciphertext.as_ref()].concat();
        trace!("Encrypted data length: {}", encrypted_data.len());

        write_u8(&mut self.stream, packet_type_byte).await?;
        trace!("Wrote packet type byte");

        let data_length = encrypted_data.len() as u32;
        trace!("Encrypted data length as u32: {}", data_length);
        if data_length > MAX_DATA_LENGTH {
            warn!(
                "Encrypted data length {} exceeds maximum allowed size {}",
                data_length, MAX_DATA_LENGTH
            );
            return Err(PacketError::DataTooLarge);
        }
        write_u32(&mut self.stream, data_length).await?;
        trace!("Wrote data length");

        self.stream.write_all(&encrypted_data).await?;
        trace!("Wrote encrypted data to stream");
        self.stream.flush().await?;
        trace!("Flushed the stream");
        Ok(())
    }
}

#[derive(Debug)]
pub struct EncryptedPacketReader<R>
where
    R: AsyncRead + Unpin + Send,
{
    stream: R,
    read_key: [u8; 32],
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
        let cipher = Aes256GcmSiv::new_from_slice(&self.read_key).map_err(|e| {
            error!("Failed to create cipher in reader: {}", e);
            PacketError::Serialization("Failed to create cipher".into())
        })?;

        let packet_type_byte = read_u8(&mut self.stream).await?;
        trace!("Reader read packet type: {}", packet_type_byte);

        if packet_type_byte == KEY_EXCHANGE_PACKET_TYPE {
            warn!("Reader received unexpected key exchange packet type");
            return Err(PacketError::InvalidPacketType(packet_type_byte));
        }

        let data_length = read_u32(&mut self.stream).await?;
        trace!("Reader data length: {}", data_length);

        if data_length > MAX_DATA_LENGTH {
            warn!(
                "Reader data length {} exceeds maximum allowed size {}",
                data_length, MAX_DATA_LENGTH
            );
            return Err(PacketError::DataTooLarge);
        }

        let mut data = vec![0u8; data_length as usize];
        self.stream.read_exact(&mut data).await?;
        trace!("Reader read encrypted data: {} bytes", data.len());

        if data.len() < 12 {
            error!("Reader: Encrypted data is too short: {}", data.len());
            return Err(PacketError::Deserialization("Data too short".into()));
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        trace!("Reader extracted nonce");

        let associated_data = &[packet_type_byte];
        trace!(
            "Reader associated data for decryption: {:?}",
            associated_data
        );

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
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

#[derive(Debug)]
pub struct EncryptedPacketWriter<W>
where
    W: AsyncWrite + Unpin + Send,
{
    stream: W,
    write_key: [u8; 32],
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
        let cipher = Aes256GcmSiv::new_from_slice(&self.write_key).map_err(|e| {
            error!("Failed to create cipher in writer: {}", e);
            PacketError::Serialization("Failed to create cipher".into())
        })?;

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

        let ciphertext = cipher
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

        let encrypted_data = [nonce_bytes.as_ref(), ciphertext.as_ref()].concat();
        trace!("Writer encrypted data length: {}", encrypted_data.len());

        write_u8(&mut self.stream, packet_type_byte).await?;
        trace!("Writer wrote packet type byte");

        let data_length = encrypted_data.len() as u32;
        trace!("Writer encrypted data length as u32: {}", data_length);
        if data_length > MAX_DATA_LENGTH {
            warn!(
                "Writer encrypted data length {} exceeds maximum allowed size {}",
                data_length, MAX_DATA_LENGTH
            );
            return Err(PacketError::DataTooLarge);
        }
        write_u32(&mut self.stream, data_length).await?;
        trace!("Writer wrote data length");

        self.stream.write_all(&encrypted_data).await?;
        trace!("Writer wrote encrypted data to stream");
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
    let packet_type_byte = read_u8(stream).await?;
    trace!("Unencrypted packet type byte: {}", packet_type_byte);
    if packet_type_byte != KEY_EXCHANGE_PACKET_TYPE {
        warn!(
            "Expected key exchange packet type {}, got {}",
            KEY_EXCHANGE_PACKET_TYPE, packet_type_byte
        );
        return Err(PacketError::InvalidPacketType(packet_type_byte));
    }

    let data_length = read_u32(stream).await?;
    trace!("Unencrypted packet data length: {}", data_length);
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
    write_u8(stream, KEY_EXCHANGE_PACKET_TYPE).await?;
    trace!("Wrote key exchange packet type byte");

    let data = match packet {
        InternalPacket::KeyExchange(data) => data.clone(),
    };
    trace!("Unencrypted packet data length: {}", data.len());

    let data_length = data.len() as u32;
    if data_length > MAX_DATA_LENGTH {
        warn!(
            "Unencrypted packet data length {} exceeds maximum allowed size {}",
            data_length, MAX_DATA_LENGTH
        );
        return Err(PacketError::DataTooLarge);
    }
    write_u32(stream, data_length).await?;
    trace!("Wrote unencrypted packet data length");

    stream.write_all(&data).await?;
    trace!("Wrote unencrypted packet data to stream");
    stream.flush().await?;
    trace!("Flushed the unencrypted stream");
    Ok(())
}

#[instrument(level = "debug", skip(reader))]
async fn read_u8<R>(reader: &mut R) -> Result<u8>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf).await?;
    trace!("Read u8: {}", buf[0]);
    Ok(buf[0])
}

#[instrument(level = "debug", skip(reader))]
async fn read_u32<R>(reader: &mut R) -> Result<u32>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf).await?;
    let value = u32::from_le_bytes(buf);
    trace!("Read u32: {}", value);
    Ok(value)
}

#[instrument(level = "debug", skip(writer))]
async fn write_u8<W>(writer: &mut W, value: u8) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&[value]).await?;
    trace!("Wrote u8: {}", value);
    Ok(())
}

#[instrument(level = "debug", skip(writer))]
async fn write_u32<W>(writer: &mut W, value: u32) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&value.to_le_bytes()).await?;
    trace!("Wrote u32: {}", value);
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
