use thiserror::Error;

/// Custom error type for packet and encryption operations.
#[derive(Error, Debug)]
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
