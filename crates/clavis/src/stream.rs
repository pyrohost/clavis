use chacha20poly1305::{aead::Aead, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::{debug, error, info, instrument, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    crypto::{compute_salt, derive_ciphers},
    error::{PacketError, Result},
    packet::{InternalPacket, PacketTrait},
    utils::{read_packet_unencrypted, write_packet_unencrypted},
    MAX_DATA_LENGTH,
};

#[derive(Debug, Clone, Copy)]
pub enum Role {
    Client,
    Server,
}

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
    #[instrument(level = "info", skip(stream, psk), fields(role = ?role))]
    pub async fn new(mut stream: S, role: Role, psk: Option<&[u8]>) -> Result<Self> {
        info!("Initializing EncryptedStream");
        if psk.is_none() {
            warn!("PSK is None; key exchange is unauthenticated. MITM attacks are possible!");
        }

        let local_ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let local_ephemeral_public = PublicKey::from(&local_ephemeral_secret);
        debug!("Local ephemeral public key generated");

        let (shared_secret, remote_ephemeral_public, send_sequence, recv_sequence) = match role {
            Role::Client => {
                info!("Role: Client - initiating key exchange");

                // Generate initial sequence number
                let mut initial_sequence_bytes = [0u8; 8];
                OsRng.fill_bytes(&mut initial_sequence_bytes);
                let initial_sequence = u64::from_le_bytes(initial_sequence_bytes);

                // Send our key exchange packet
                let key_exchange = InternalPacket::KeyExchange {
                    public_key: *local_ephemeral_public.as_bytes(),
                    initial_sequence,
                };
                write_packet_unencrypted(&mut stream, &key_exchange, psk).await?;

                // Receive server's key exchange
                let server_key_exchange: InternalPacket =
                    read_packet_unencrypted(&mut stream, psk).await?;

                let (server_public_key, server_sequence) = match server_key_exchange {
                    InternalPacket::KeyExchange {
                        public_key,
                        initial_sequence,
                    } => (public_key, initial_sequence),
                };

                let remote_public = PublicKey::from(server_public_key);
                let shared = local_ephemeral_secret.diffie_hellman(&remote_public);

                (shared, remote_public, initial_sequence, server_sequence)
            }
            Role::Server => {
                info!("Role: Server - responding to key exchange");

                // Receive client's key exchange first
                let client_key_exchange: InternalPacket =
                    read_packet_unencrypted(&mut stream, psk).await?;

                let (client_public_key, client_sequence) = match client_key_exchange {
                    InternalPacket::KeyExchange {
                        public_key,
                        initial_sequence,
                    } => (public_key, initial_sequence),
                };

                // Generate our initial sequence number
                let mut initial_sequence_bytes = [0u8; 8];
                OsRng.fill_bytes(&mut initial_sequence_bytes);
                let initial_sequence = u64::from_le_bytes(initial_sequence_bytes);

                // Send our key exchange response
                let key_exchange = InternalPacket::KeyExchange {
                    public_key: *local_ephemeral_public.as_bytes(),
                    initial_sequence,
                };
                write_packet_unencrypted(&mut stream, &key_exchange, psk).await?;

                let remote_public = PublicKey::from(client_public_key);
                let shared = local_ephemeral_secret.diffie_hellman(&remote_public);

                (shared, remote_public, initial_sequence, client_sequence)
            }
        };

        debug!("Shared secret computed via Diffie-Hellman");

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

    pub async fn read_packet<P: PacketTrait>(&mut self) -> Result<P> {
        let (data, sequence_number) = read_message(&mut self.stream, &self.cipher_dec).await?;
        if sequence_number <= self.recv_sequence {
            return Err(PacketError::ReplayAttack);
        }
        self.recv_sequence = sequence_number;
        P::deserialize(&data)
    }

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
    pub async fn read_packet<P: PacketTrait>(&mut self) -> Result<P> {
        let (data, sequence_number) = read_message(&mut self.stream, &self.cipher_dec).await?;
        if sequence_number <= self.recv_sequence {
            return Err(PacketError::ReplayAttack);
        }
        self.recv_sequence = sequence_number;
        P::deserialize(&data)
    }
}

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

async fn read_message<R: AsyncRead + Unpin>(
    stream: &mut R,
    cipher: &XChaCha20Poly1305,
) -> Result<(Vec<u8>, u64)> {
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

async fn write_message<W: AsyncWrite + Unpin>(
    stream: &mut W,
    cipher: &XChaCha20Poly1305,
    message: &[u8],
    sequence_number: u64,
) -> Result<()> {
    if message.len() > MAX_DATA_LENGTH as usize - 8 {
        return Err(PacketError::DataTooLarge);
    }

    let mut sequence_message = Vec::with_capacity(8 + message.len());
    sequence_message.extend_from_slice(&sequence_number.to_le_bytes());
    sequence_message.extend_from_slice(message);

    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..8].copy_from_slice(&sequence_number.to_le_bytes());
    OsRng.fill_bytes(&mut nonce_bytes[8..]);
    let nonce = XNonce::from_slice(&nonce_bytes);

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

    let mut buffer = Vec::with_capacity(4 + 24 + ciphertext.len());
    buffer.extend_from_slice(&length.to_le_bytes());
    buffer.extend_from_slice(&nonce_bytes);
    buffer.extend_from_slice(&ciphertext);

    stream.write_all(&buffer).await?;
    stream.flush().await?;

    Ok(())
}
