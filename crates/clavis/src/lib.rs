#![forbid(unsafe_code)]

//! # Clavis
//!
//! Clavis provides a secure and efficient abstraction, `EncryptedStream`, over asynchronous streams.
//! It enables encrypted and authenticated communication using the XChaCha20Poly1305 algorithm, ensuring both
//! data integrity and confidentiality.
//!
//! ## Usage Example
//! ```rust,no_run
//! use clavis::{EncryptedStream, Role, define_packets};
//! use tokio::net::TcpStream;
//!
//! // Define a custom message structure
//! #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
//! struct Message {
//!     content: String,
//! }
//!
//! // Use the define_packets! macro to create a custom packet enum
//! define_packets! {
//!     enum MyPacket {
//!         VoidMessage,
//!         Message(String),
//!         StructMessage(Message),
//!         StructuredMessage { content: String },
//!     }
//! }
//! ```

mod crypto;
mod error;
mod packet;
mod stream;
mod utils;

#[cfg(test)]
mod tests;

pub use error::{PacketError, Result};
pub use packet::PacketTrait;
pub use stream::{EncryptedReader, EncryptedStream, EncryptedWriter, Role};

/// Maximum allowed data length for packets (12 MiB).
pub const MAX_DATA_LENGTH: u32 = 1024 * 1024 * 12;

pub mod prelude {
    pub use {bincode, serde};
}

#[macro_export]
macro_rules! define_packets {
    (
        $(
            $(#[$enum_meta:meta])*
            $enum_vis:vis enum $enum_name:ident {
                $(
                    $(#[$variant_meta:meta])*
                    $variant_vis:vis $variant:ident
                    $(($inner:ty))?
                    $({ $( $field_vis:vis $field:ident : $ftype:ty ),+ $(,)? })?
                ),* $(,)?
            }
        )*
    ) => {
        $(
            #[derive(Debug, Clone, PartialEq, Eq, $crate::prelude::serde::Serialize, $crate::prelude::serde::Deserialize)]
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                $(
                    $(#[$variant_meta])*
                    $variant_vis $variant
                    $(($inner))?
                    $({ $( $field_vis $field : $ftype ),+ })?,
                )*
            }

            impl $crate::PacketTrait for $enum_name {
                fn serialize(&self) -> $crate::Result<Vec<u8>> {
                    $crate::prelude::bincode::serialize(self).map_err(|_| {
                        $crate::PacketError::Serialization
                    })
                }
                fn deserialize(data: &[u8]) -> $crate::Result<Self> {
                    $crate::prelude::bincode::deserialize(data).map_err(|_| {
                        $crate::PacketError::Deserialization
                    })
                }
            }

            impl std::fmt::Display for $enum_name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "{:?}", self)
                }
            }
        )*
    };
}
