use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    error::{ClavisError, ClavisResult, CryptoError, CryptoOperation, MessageError, StreamError},
    stream::EncryptedStreamOptions,
};

type HmacSha256 = Hmac<Sha256>;

struct CryptoContext {
    cipher: XChaCha20Poly1305,
    buffer: Vec<u8>,
    max_message_size: usize,
}

impl CryptoContext {
    fn new(key: &[u8], max_message_size: usize) -> ClavisResult<Self> {
        Ok(Self {
            cipher: XChaCha20Poly1305::new_from_slice(key).map_err(|e| {
                ClavisError::Crypto(CryptoError::InvalidKeyMaterial(format!(
                    "Invalid key material: {}",
                    e
                )))
            })?,
            buffer: Vec::with_capacity(4096),
            max_message_size,
        })
    }

    #[inline]
    fn validate_message_size(&self, size: usize) -> ClavisResult<()> {
        if size > self.max_message_size {
            Err(ClavisError::Message(MessageError::MessageTooLarge {
                size,
                max_size: self.max_message_size,
            }))
        } else {
            Ok(())
        }
    }

    async fn read_message<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
    ) -> ClavisResult<Vec<u8>> {
        let length = stream.read_u32_le().await.map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => ClavisError::Stream(StreamError::UnexpectedClose),
            _ => ClavisError::Stream(StreamError::Io(e)),
        })? as usize;

        self.validate_message_size(length)?;

        let mut nonce = [0u8; 24];
        stream
            .read_exact(&mut nonce)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    ClavisError::Stream(StreamError::UnexpectedClose)
                }
                _ => ClavisError::Stream(StreamError::Io(e)),
            })?;

        let mut ciphertext = vec![0u8; length];
        stream
            .read_exact(&mut ciphertext)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    ClavisError::Stream(StreamError::UnexpectedClose)
                }
                _ => ClavisError::Stream(StreamError::Io(e)),
            })?;

        let plaintext = self
            .cipher
            .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|e| ClavisError::crypto_failure(CryptoOperation::Decryption, e.to_string()))?;

        Ok(plaintext)
    }

    async fn write_message<W: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut W,
        message: &[u8],
    ) -> ClavisResult<()> {
        self.validate_message_size(message.len())?;

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, message)
            .map_err(|e| ClavisError::crypto_failure(CryptoOperation::Encryption, e.to_string()))?;

        self.buffer.clear();
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
    transcript: Sha256,
    mac: Option<HmacSha256>,
}

impl HandshakeContext {
    fn new(psk: Option<&[u8]>) -> ClavisResult<Self> {
        let mac = psk
            .map(<HmacSha256 as KeyInit>::new_from_slice)
            .transpose()
            .map_err(|e| {
                ClavisError::crypto_failure(
                    CryptoOperation::Authentication,
                    format!("Failed to create HMAC: {}", e),
                )
            })?;

        Ok(Self {
            transcript: Sha256::new(),
            mac,
        })
    }

    fn append(&mut self, data: &[u8]) {
        self.transcript.update(data);
        if let Some(mac) = &mut self.mac {
            mac.update(data);
        }
    }

    fn finalize(self) -> ([u8; 32], Option<[u8; 32]>) {
        let transcript_hash = self.transcript.finalize().into();
        let mac = self.mac.map(|mac| mac.finalize().into_bytes().into());
        (transcript_hash, mac)
    }
}

pub struct CryptoReader {
    context: CryptoContext,
}

impl CryptoReader {
    pub async fn read<R: AsyncRead + Unpin + Send>(
        &mut self,
        stream: &mut R,
    ) -> ClavisResult<Vec<u8>> {
        self.context.read_message(stream).await
    }
}

pub struct CryptoWriter {
    context: CryptoContext,
}

impl CryptoWriter {
    pub async fn write<W: AsyncWrite + Unpin + Send>(
        &mut self,
        stream: &mut W,
        message: &[u8],
    ) -> ClavisResult<()> {
        self.context.write_message(stream, message).await
    }
}

pub struct CryptoCore {
    pub(crate) reader: CryptoReader,
    pub(crate) writer: CryptoWriter,
}

impl CryptoCore {
    pub async fn establish<S: AsyncRead + AsyncWrite + Unpin + Send>(
        stream: &mut S,
        options: EncryptedStreamOptions,
    ) -> ClavisResult<Self> {
        let is_initiator = Self::determine_role(stream).await?;
        Self::validate_psk(&options)?;

        let (shared_secret, transcript_hash, mac) =
            Self::handshake(stream, options.psk.as_deref(), is_initiator).await?;
        Self::verify_mac(stream, mac, is_initiator).await?;
        let (enc_key, dec_key) = Self::derive_keys(&shared_secret, &transcript_hash, is_initiator)?;

        Ok(Self {
            reader: CryptoReader {
                context: CryptoContext::new(&dec_key, options.max_packet_size)?,
            },
            writer: CryptoWriter {
                context: CryptoContext::new(&enc_key, options.max_packet_size)?,
            },
        })
    }

    async fn determine_role<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
    ) -> ClavisResult<bool> {
        let mut local_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut local_nonce);

        stream
            .write_all(&local_nonce)
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
        stream
            .flush()
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;

        let mut peer_nonce = [0u8; 32];
        stream
            .read_exact(&mut peer_nonce)
            .await
            .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;

        Ok(local_nonce > peer_nonce)
    }

    fn validate_psk(options: &EncryptedStreamOptions) -> ClavisResult<()> {
        if let Some(psk) = &options.psk {
            if psk.len() < 16 {
                return Err(ClavisError::Crypto(CryptoError::InvalidKeyMaterial(
                    "Pre-shared key must be at least 16 bytes".into(),
                )));
            }
        }
        Ok(())
    }

    async fn verify_mac<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        mac: Option<[u8; 32]>,
        is_initiator: bool,
    ) -> ClavisResult<()> {
        if let Some(local_mac) = mac {
            let mut peer_mac = [0u8; 32];

            if is_initiator {
                stream
                    .write_all(&local_mac)
                    .await
                    .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
                stream
                    .flush()
                    .await
                    .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
                stream
                    .read_exact(&mut peer_mac)
                    .await
                    .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
            } else {
                stream
                    .read_exact(&mut peer_mac)
                    .await
                    .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
                stream
                    .write_all(&local_mac)
                    .await
                    .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
                stream
                    .flush()
                    .await
                    .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
            }

            if local_mac.ct_eq(&peer_mac).unwrap_u8() == 0 {
                return Err(ClavisError::Crypto(CryptoError::AuthenticationFailure(
                    "MAC verification failed".into(),
                )));
            }
        }
        Ok(())
    }

    async fn handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
        stream: &mut S,
        psk: Option<&[u8]>,
        is_initiator: bool,
    ) -> ClavisResult<([u8; 32], [u8; 32], Option<[u8; 32]>)> {
        let mut context = HandshakeContext::new(psk)?;
        let (secret, peer_key) = Self::exchange_keys(stream, &mut context, is_initiator).await?;

        let shared_secret = secret.diffie_hellman(&peer_key);
        let shared_secret_bytes = shared_secret.as_bytes();
        let (transcript_hash, mac) = context.finalize();

        Ok((*shared_secret_bytes, transcript_hash, mac))
    }

    async fn exchange_keys<S: AsyncRead + AsyncWrite + Unpin + Send>(
        stream: &mut S,
        context: &mut HandshakeContext,
        is_initiator: bool,
    ) -> ClavisResult<(EphemeralSecret, PublicKey)> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut peer_bytes = [0u8; 32];

        if is_initiator {
            stream
                .write_all(public.as_bytes())
                .await
                .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
            stream
                .flush()
                .await
                .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
            stream
                .read_exact(&mut peer_bytes)
                .await
                .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
        } else {
            stream
                .read_exact(&mut peer_bytes)
                .await
                .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
            stream
                .write_all(public.as_bytes())
                .await
                .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
            stream
                .flush()
                .await
                .map_err(|e| ClavisError::Stream(StreamError::Io(e)))?;
        }

        if is_initiator {
            context.append(public.as_bytes());
            context.append(&peer_bytes);
        } else {
            context.append(&peer_bytes);
            context.append(public.as_bytes());
        }

        let peer_key = PublicKey::from(peer_bytes);
        Ok((secret, peer_key))
    }

    fn derive_keys(
        shared_secret: &[u8; 32],
        transcript_hash: &[u8; 32],
        is_initiator: bool,
    ) -> ClavisResult<([u8; 32], [u8; 32])> {
        let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret);
        let mut enc_key = [0u8; 32];
        let mut dec_key = [0u8; 32];

        if is_initiator {
            hkdf.expand(b"enc", &mut enc_key).map_err(|_| {
                ClavisError::Crypto(CryptoError::KeyDerivationFailure(
                    "Failed to derive encryption key".into(),
                ))
            })?;
            hkdf.expand(b"dec", &mut dec_key).map_err(|_| {
                ClavisError::Crypto(CryptoError::KeyDerivationFailure(
                    "Failed to derive decryption key".into(),
                ))
            })?;
        } else {
            hkdf.expand(b"dec", &mut enc_key).map_err(|_| {
                ClavisError::Crypto(CryptoError::KeyDerivationFailure(
                    "Failed to derive encryption key".into(),
                ))
            })?;
            hkdf.expand(b"enc", &mut dec_key).map_err(|_| {
                ClavisError::Crypto(CryptoError::KeyDerivationFailure(
                    "Failed to derive decryption key".into(),
                ))
            })?;
        }

        Ok((enc_key, dec_key))
    }
}
