use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    error::{ClavisError, ClavisResult, CryptoOperation, MessageError, SecurityError, StreamError},
    stream::EncryptedStreamOptions,
};

struct Sizes {
    nonce: usize,
    key: usize,
    length: usize,
    mac: usize,
}

const SIZES: Sizes = Sizes {
    nonce: 24,
    key: 32,
    length: 4,
    mac: 32,
};

struct CryptoContext {
    cipher: XChaCha20Poly1305,
    buffer: Vec<u8>,
    max_message_size: usize,
}

impl CryptoContext {
    fn new(key: &[u8], max_message_size: usize) -> ClavisResult<Self> {
        if key.len() != SIZES.key {
            return Err(ClavisError::Security(SecurityError::InvalidKeyMaterial(
                format!("Key must be exactly {} bytes, got {}", SIZES.key, key.len()),
            )));
        }

        Ok(Self {
            cipher: XChaCha20Poly1305::new(key.into()),
            buffer: Vec::with_capacity(4096),
            max_message_size,
        })
    }

    #[inline]
    fn validate_message_size(&self, size: usize) -> ClavisResult<()> {
        if size > self.max_message_size {
            return Err(ClavisError::Message(MessageError::MessageTooLarge {
                size,
                max_size: self.max_message_size,
            }));
        }
        Ok(())
    }

    #[inline]
    fn calculate_total_len(ciphertext_len: usize) -> usize {
        SIZES.length + SIZES.nonce + ciphertext_len
    }

    async fn read_message<R: AsyncRead + Unpin>(&self, stream: &mut R) -> ClavisResult<Vec<u8>> {
        let length = stream
            .read_u32_le()
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))? as usize;

        self.validate_message_size(length)?;

        let mut buffer = vec![0u8; SIZES.nonce + length];
        stream
            .read_exact(&mut buffer)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    ClavisError::Stream(StreamError::UnexpectedClose)
                }
                _ => ClavisError::Stream(StreamError::Io(e)),
            })?;

        let (nonce, ciphertext) = buffer.split_at(SIZES.nonce);

        self.cipher.decrypt(nonce.into(), ciphertext).map_err(|e| {
            ClavisError::crypto_failure(
                CryptoOperation::Decryption,
                format!("Failed to decrypt message: {}", e),
            )
        })
    }

    async fn write_message<W: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut W,
        message: &[u8],
    ) -> ClavisResult<()> {
        self.validate_message_size(message.len())?;

        let nonce = generate_random_bytes::<{ SIZES.nonce }>();
        let ciphertext = self
            .cipher
            .encrypt(nonce.as_slice().into(), message)
            .map_err(|e| {
                ClavisError::crypto_failure(
                    CryptoOperation::Encryption,
                    format!("Failed to encrypt message: {}", e),
                )
            })?;

        self.buffer.clear();
        self.buffer
            .reserve(Self::calculate_total_len(ciphertext.len()));
        self.buffer
            .extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        self.buffer.extend_from_slice(&nonce);
        self.buffer.extend_from_slice(&ciphertext);

        stream
            .write_all(&self.buffer)
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
        stream
            .flush()
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
        Ok(())
    }
}

struct HandshakeContext {
    transcript: Vec<u8>,
    hmac: Option<Hmac<Sha256>>,
}

impl HandshakeContext {
    fn new(psk: Option<&[u8]>) -> ClavisResult<Self> {
        Ok(Self {
            transcript: Vec::with_capacity(SIZES.key * 4),
            hmac: psk
                .map(|key| {
                    KeyInit::new_from_slice(key).map_err(|e| {
                        ClavisError::crypto_failure(
                            CryptoOperation::Authentication,
                            format!("Failed to create HMAC: {}", e),
                        )
                    })
                })
                .transpose()?,
        })
    }

    #[inline]
    fn append(&mut self, data: &[u8]) {
        self.transcript.extend_from_slice(data);
        if let Some(hmac) = &mut self.hmac {
            Mac::update(hmac, data);
        }
    }

    fn finalize(self) -> ([u8; SIZES.key], Option<[u8; SIZES.mac]>) {
        let transcript_hash = Sha256::digest(&self.transcript).into();
        let mac = self.hmac.map(|mac| Mac::finalize(mac).into_bytes().into());
        (transcript_hash, mac)
    }
}

#[inline]
fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    let mut rng = ChaCha20Rng::from_entropy();
    rng.fill_bytes(&mut bytes);
    bytes
}

pub struct CryptoReader(CryptoContext);
pub struct CryptoWriter(CryptoContext);

// Implement methods for the public interface
impl CryptoReader {
    #[inline]
    pub async fn read<R: AsyncRead + Unpin>(&self, stream: &mut R) -> ClavisResult<Vec<u8>> {
        self.0.read_message(stream).await
    }
}

impl CryptoWriter {
    #[inline]
    pub async fn write<W: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut W,
        message: &[u8],
    ) -> ClavisResult<()> {
        self.0.write_message(stream, message).await
    }
}

pub struct CryptoCore {
    reader: CryptoContext,
    writer: CryptoContext,
}

impl CryptoCore {
    pub async fn establish<S>(stream: &mut S, options: EncryptedStreamOptions) -> ClavisResult<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if let Some(psk) = options.psk.as_ref() {
            if psk.len() < 16 {
                return Err(ClavisError::Security(SecurityError::InvalidKeyMaterial(
                    "Pre-shared key must be at least 16 bytes long".into(),
                )));
            }
        }

        let (secret, transcript_hash, mac, is_initiator) =
            Self::handshake(stream, options.psk.as_deref()).await?;

        if let Some(local_mac) = mac {
            let mut peer_mac = [0u8; SIZES.mac];

            match is_initiator {
                true => {
                    stream
                        .write_all(&local_mac)
                        .await
                        .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
                    stream
                        .read_exact(&mut peer_mac)
                        .await
                        .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
                }
                false => {
                    stream
                        .read_exact(&mut peer_mac)
                        .await
                        .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
                    stream
                        .write_all(&local_mac)
                        .await
                        .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
                }
            }

            if peer_mac != local_mac {
                return Err(ClavisError::Security(SecurityError::AuthenticationFailure(
                    "MAC verification failed during handshake".into(),
                )));
            }
        }

        let (enc_key, dec_key) = Self::derive_keys(&secret, is_initiator, &transcript_hash)?;

        Ok(Self {
            reader: CryptoContext::new(&dec_key, options.max_packet_size)?,
            writer: CryptoContext::new(&enc_key, options.max_packet_size)?,
        })
    }

    async fn handshake<S>(
        stream: &mut S,
        psk: Option<&[u8]>,
    ) -> ClavisResult<(
        [u8; SIZES.key],
        [u8; SIZES.key],
        Option<[u8; SIZES.mac]>,
        bool,
    )>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut context = HandshakeContext::new(psk)?;
        let local_nonce = generate_random_bytes::<{ SIZES.key }>();
        let mut peer_nonce = [0u8; SIZES.key];

        stream
            .write_all(&local_nonce)
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
        stream
            .read_exact(&mut peer_nonce)
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;

        let is_initiator = local_nonce < peer_nonce;
        let (first, second) = if is_initiator {
            (&local_nonce, &peer_nonce)
        } else {
            (&peer_nonce, &local_nonce)
        };

        context.append(first);
        context.append(second);

        let (secret, peer_key) = if is_initiator {
            Self::exchange_keys_initiator(stream, &mut context).await?
        } else {
            Self::exchange_keys_responder(stream, &mut context).await?
        };

        let shared_secret = *secret.diffie_hellman(&peer_key).as_bytes();
        let (transcript_hash, mac) = context.finalize();

        Ok((shared_secret, transcript_hash, mac, is_initiator))
    }

    async fn exchange_keys_initiator<S>(
        stream: &mut S,
        context: &mut HandshakeContext,
    ) -> ClavisResult<(EphemeralSecret, PublicKey)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut rng = ChaCha20Rng::from_entropy();
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);

        stream
            .write_all(public.as_bytes())
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
        context.append(public.as_bytes());

        let mut peer_bytes = [0u8; SIZES.key];
        stream
            .read_exact(&mut peer_bytes)
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
        context.append(&peer_bytes);

        Ok((secret, PublicKey::from(peer_bytes)))
    }

    async fn exchange_keys_responder<S>(
        stream: &mut S,
        context: &mut HandshakeContext,
    ) -> ClavisResult<(EphemeralSecret, PublicKey)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut peer_bytes = [0u8; SIZES.key];
        stream
            .read_exact(&mut peer_bytes)
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
        context.append(&peer_bytes);

        let mut rng = ChaCha20Rng::from_entropy();
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);

        stream
            .write_all(public.as_bytes())
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
        context.append(public.as_bytes());

        Ok((secret, PublicKey::from(peer_bytes)))
    }

    fn derive_keys(
        shared: &[u8],
        is_initiator: bool,
        transcript_hash: &[u8; SIZES.key],
    ) -> ClavisResult<([u8; SIZES.key], [u8; SIZES.key])> {
        let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared);
        let mut initiator_key = [0u8; SIZES.key];
        let mut responder_key = [0u8; SIZES.key];

        hkdf.expand(b"initiator", &mut initiator_key)
            .and_then(|_| hkdf.expand(b"responder", &mut responder_key))
            .map_err(|e| {
                ClavisError::crypto_failure(
                    CryptoOperation::KeyDerivation,
                    format!("HKDF expansion failed: {}", e),
                )
            })?;

        Ok(if is_initiator {
            (initiator_key, responder_key)
        } else {
            (responder_key, initiator_key)
        })
    }

    pub fn split(self) -> (CryptoReader, CryptoWriter) {
        (CryptoReader(self.reader), CryptoWriter(self.writer))
    }
}
