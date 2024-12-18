use std::fmt;
use thiserror::Error;

/// Represents the type of a cryptographic operation that failed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOperation {
    Authentication,
    Encryption,
    Decryption,
    KeyExchange,
    Handshake,
}

impl fmt::Display for CryptoOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoOperation::Authentication => write!(f, "authentication"),
            CryptoOperation::Encryption => write!(f, "encryption"),
            CryptoOperation::Decryption => write!(f, "decryption"),
            CryptoOperation::KeyExchange => write!(f, "key exchange"),
            CryptoOperation::Handshake => write!(f, "handshake"),
        }
    }
}

/// Represents cryptographic errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Cryptographic operation failed during {operation}: {details}")]
    OperationFailure {
        operation: CryptoOperation,
        details: String,
    },

    #[error("Authentication failed: {0}")]
    AuthenticationFailure(String),

    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailure(String),
}

/// Represents message format and processing errors
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("Message size {size} exceeds maximum allowed size of {max_size}")]
    MessageTooLarge { size: usize, max_size: usize },

    #[error("Message serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Message deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("Invalid message format: {0}")]
    InvalidFormat(String),
}

/// Represents stream operation errors
#[derive(Debug, Error)]
pub enum StreamError {
    #[error("Invalid stream operation: {0}")]
    InvalidOperation(String),

    #[error("Stream closed unexpectedly")]
    UnexpectedClose,

    #[error("Stream timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Main error type for the Clavis library
#[derive(Debug, Error)]
pub enum ClavisError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Message(#[from] MessageError),

    #[error(transparent)]
    Stream(#[from] StreamError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ClavisError {
    /// Returns true if the error is related to cryptographic operations
    pub fn is_crypto_error(&self) -> bool {
        matches!(self, ClavisError::Crypto(_))
    }

    /// Returns true if the error is related to message processing
    pub fn is_message_error(&self) -> bool {
        matches!(self, ClavisError::Message(_))
    }

    /// Returns true if the error is related to stream operations
    pub fn is_stream_error(&self) -> bool {
        matches!(self, ClavisError::Stream(_))
    }

    /// Returns true if the error might be resolved by retrying the operation
    pub fn is_retriable(&self) -> bool {
        match self {
            ClavisError::Stream(StreamError::Timeout { .. }) => true,
            ClavisError::Stream(StreamError::Io(e)) => {
                e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::Interrupted
            }
            _ => false,
        }
    }

    /// Creates a new cryptographic error for a failed operation
    pub fn crypto_failure(operation: CryptoOperation, details: impl Into<String>) -> Self {
        ClavisError::Crypto(CryptoError::OperationFailure {
            operation,
            details: details.into(),
        })
    }

    /// Creates a new error for message serialization failures
    pub fn serialization_failed(details: impl Into<String>) -> Self {
        ClavisError::Message(MessageError::SerializationFailed(details.into()))
    }

    /// Creates a new error for message deserialization failures
    pub fn deserialization_failed(details: impl Into<String>) -> Self {
        ClavisError::Message(MessageError::DeserializationFailed(details.into()))
    }

    /// Creates a new error for invalid stream operations
    pub fn invalid_operation(details: impl Into<String>) -> Self {
        ClavisError::Stream(StreamError::InvalidOperation(details.into()))
    }
}

/// Type alias for Result with ClavisError as the error type
pub type ClavisResult<T> = std::result::Result<T, ClavisError>;
