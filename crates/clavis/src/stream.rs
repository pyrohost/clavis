use crate::{
    crypto::{CryptoCore, CryptoReader, CryptoWriter},
    error::{ClavisError, ClavisResult, MessageError, StreamError},
    PacketTrait,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tracing::warn;

/// Trait for handling encrypted packet operations
pub trait EncryptedPacket {
    /// Reads and deserializes an encrypted packet of type P
    fn read_packet<P: PacketTrait>(
        &mut self,
    ) -> impl std::future::Future<Output = ClavisResult<P>> + Send
    where
        Self: Sized;

    /// Serializes and writes an encrypted packet
    fn write_packet(
        &mut self,
        packet: &impl PacketTrait,
    ) -> impl std::future::Future<Output = ClavisResult<()>> + Send
    where
        Self: Sized;
}

/// Options for configuring an encrypted stream
#[derive(Debug, Clone)]
pub struct EncryptedStreamOptions {
    /// The maximum size of a packet in bytes (default: 65536)
    pub max_packet_size: usize,
    /// A pre-shared key to use for the handshake (default: None)
    pub psk: Option<Vec<u8>>,
}

impl Default for EncryptedStreamOptions {
    fn default() -> Self {
        Self {
            max_packet_size: 65536,
            psk: None,
        }
    }
}

/// Stream wrapper that handles both reading and writing encrypted data
pub struct EncryptedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    stream: S,
    crypto_reader: CryptoReader,
    crypto_writer: CryptoWriter,
    options: EncryptedStreamOptions,
}

impl<S> EncryptedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Creates a new encrypted stream by establishing crypto parameters
    pub async fn new(mut stream: S, options: Option<EncryptedStreamOptions>) -> ClavisResult<Self> {
        let options = options.unwrap_or_default();
        if options.psk.is_none() {
            warn!("No pre-shared key is set, this connection may be vulnerable to man-in-the-middle attacks.");
        }

        let core = CryptoCore::establish(&mut stream, options.clone())
            .await
            .map_err(|e| {
                ClavisError::crypto_failure(crate::error::CryptoOperation::Handshake, e.to_string())
            })?;

        let crypto_reader = core.reader;
        let crypto_writer = core.writer;

        Ok(Self {
            stream,
            crypto_reader,
            crypto_writer,
            options,
        })
    }

    /// Splits the stream into separate reader and writer components
    pub fn split(self) -> (EncryptedReader<ReadHalf<S>>, EncryptedWriter<WriteHalf<S>>) {
        let (read, write) = tokio::io::split(self.stream);
        (
            EncryptedReader::new(read, self.crypto_reader, self.options.clone()),
            EncryptedWriter::new(write, self.crypto_writer, self.options),
        )
    }
}

impl<S> EncryptedPacket for EncryptedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Reads and decrypts a packet from the stream
    async fn read_packet<P: PacketTrait>(&mut self) -> ClavisResult<P> {
        let data = self.crypto_reader.read(&mut self.stream).await?;

        // Check packet size
        if data.len() > self.options.max_packet_size {
            return Err(ClavisError::Message(MessageError::MessageTooLarge {
                size: data.len(),
                max_size: self.options.max_packet_size,
            }));
        }

        P::deserialize(&data).map_err(|e| ClavisError::deserialization_failed(e.to_string()))
    }

    /// Encrypts and writes a packet to the stream
    async fn write_packet(&mut self, packet: &impl PacketTrait) -> ClavisResult<()> {
        let data = packet
            .serialize()
            .map_err(|e| ClavisError::serialization_failed(e.to_string()))?;

        // Check packet size before encryption
        if data.len() > self.options.max_packet_size {
            return Err(ClavisError::Message(MessageError::MessageTooLarge {
                size: data.len(),
                max_size: self.options.max_packet_size,
            }));
        }

        self.crypto_writer.write(&mut self.stream, &data).await
    }
}

/// Handles reading encrypted data from a stream
pub struct EncryptedReader<R> {
    inner: R,
    crypto: CryptoReader,
    options: EncryptedStreamOptions,
}

impl<R> EncryptedReader<R> {
    /// Creates a new encrypted reader from a stream and crypto reader
    fn new(inner: R, crypto: CryptoReader, options: EncryptedStreamOptions) -> Self {
        Self {
            inner,
            crypto,
            options,
        }
    }
}

/// Handles writing encrypted data to a stream
pub struct EncryptedWriter<W> {
    inner: W,
    crypto: CryptoWriter,
    options: EncryptedStreamOptions,
}

impl<W> EncryptedWriter<W> {
    /// Creates a new encrypted writer from a stream and crypto writer
    fn new(inner: W, crypto: CryptoWriter, options: EncryptedStreamOptions) -> Self {
        Self {
            inner,
            crypto,
            options,
        }
    }
}

impl<R: AsyncRead + Unpin + Send> EncryptedPacket for EncryptedReader<R> {
    /// Reads and decrypts a packet from the read-only stream
    async fn read_packet<P: PacketTrait>(&mut self) -> ClavisResult<P> {
        let data = self.crypto.read(&mut self.inner).await?;

        // Check packet size
        if data.len() > self.options.max_packet_size {
            return Err(ClavisError::Message(MessageError::MessageTooLarge {
                size: data.len(),
                max_size: self.options.max_packet_size,
            }));
        }

        P::deserialize(&data).map_err(|e| ClavisError::deserialization_failed(e.to_string()))
    }

    /// Returns an error as writing is not supported on a read-only stream
    async fn write_packet(&mut self, _packet: &impl PacketTrait) -> ClavisResult<()> {
        Err(ClavisError::Stream(StreamError::InvalidOperation(
            "Cannot write to a read-only stream".into(),
        )))
    }
}

impl<W: AsyncWrite + Unpin + Send> EncryptedPacket for EncryptedWriter<W> {
    /// Returns an error as reading is not supported on a write-only stream
    async fn read_packet<P: PacketTrait>(&mut self) -> ClavisResult<P> {
        Err(ClavisError::Stream(StreamError::InvalidOperation(
            "Cannot read from a write-only stream".into(),
        )))
    }

    /// Encrypts and writes a packet to the write-only stream
    async fn write_packet(&mut self, packet: &impl PacketTrait) -> ClavisResult<()> {
        let data = packet
            .serialize()
            .map_err(|e| ClavisError::serialization_failed(e.to_string()))?;

        // Check packet size before encryption
        if data.len() > self.options.max_packet_size {
            return Err(ClavisError::Message(MessageError::MessageTooLarge {
                size: data.len(),
                max_size: self.options.max_packet_size,
            }));
        }

        self.crypto.write(&mut self.inner, &data).await
    }
}
