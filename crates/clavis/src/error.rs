use std::fmt;
use thiserror::Error;

/// Represents the type of a cryptographic operation that failed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOperation {
    Encryption,
    Decryption,
    KeyDerivation,
    KeyExchange,
    Authentication,
    Handshake,
}

impl fmt::Display for CryptoOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoOperation::Encryption => write!(f, "encryption"),
            CryptoOperation::Decryption => write!(f, "decryption"),
            CryptoOperation::KeyDerivation => write!(f, "key derivation"),
            CryptoOperation::KeyExchange => write!(f, "key exchange"),
            CryptoOperation::Authentication => write!(f, "authentication"),
            CryptoOperation::Handshake => write!(f, "handshake"),
        }
    }
}

/// Represents security-related errors
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Cryptographic operation failed during {operation}: {details}")]
    CryptoFailure {
        operation: CryptoOperation,
        details: String,
    },

    #[error("Authentication failed: {0}")]
    AuthenticationFailure(String),

    #[error("Potential replay attack detected: {0}")]
    ReplayAttack(String),

    #[error("Sequence number overflow occurred")]
    SequenceOverflow,

    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),

    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),
}

/// Represents message format and processing errors
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("Message size {size} exceeds maximum allowed size of {max_size}")]
    MessageTooLarge { size: usize, max_size: usize },

    #[error("Invalid packet type identifier: {0}")]
    InvalidPacketType(u8),

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

    #[error("Stream split error: {0}")]
    SplitError(String),

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
    Security(#[from] SecurityError),

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
    /// Returns true if the error is related to security
    pub fn is_security_error(&self) -> bool {
        matches!(self, ClavisError::Security(_))
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

    /// Creates a new security error for a failed crypto operation
    pub fn crypto_failure(operation: CryptoOperation, details: impl Into<String>) -> Self {
        ClavisError::Security(SecurityError::CryptoFailure {
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
