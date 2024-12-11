#![forbid(unsafe_code)]

//! Clavis is a robust, asynchronous Rust library for establishing secure, encrypted
//! communication channels over network streams. Built on Tokio, it provides high-level
//! abstractions for encrypted packet-based communication while maintaining strong security
//! guarantees through modern cryptographic primitives.
//!
//! The library implements XChaCha20-Poly1305 encryption and features
//! a type-safe protocol DSL macro for defining custom communication protocols and includes
//! built-in serialization support.
//!
//! # Quick Start
//!
//! Add Clavis to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! clavis = { git = "https://github.com/pyrohost/clavis" }
//! ```
//!
//! Define your protocol using the `protocol!` macro:
//!
//! ```rust
//! use clavis::protocol;
//!
//! protocol! {
//!     pub enum Message {
//!         Ping(PingPongData),
//!         Pong(PingPongData),
//!         Shutdown,
//!     }
//! }
//!
//! #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
//! pub struct PingPongData {
//!     pub message: String,
//! }
//! ```
//!
//! Create an encrypted connection:
//!
//! ```rust
//! use clavis::{EncryptedStream, EncryptedPacket};
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let stream = TcpStream::connect("127.0.0.1:7272").await?;
//!     let mut encrypted = EncryptedStream::new(stream, None).await?;
//!
//!     let ping = Message::Ping(PingPongData {
//!         message: "Hello!".into(),
//!     });
//!     encrypted.write_packet(&ping).await?;
//!
//!     if let Message::Pong(pong) = encrypted.read_packet().await? {
//!         println!("Received pong: {:?}", pong);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Core Types
//!
//! The main types in Clavis are [`EncryptedStream`] for wrapping any AsyncRead + AsyncWrite stream,
//! [`EncryptedPacket`] for defining the packet communication interface, and [`PacketTrait`] for
//! protocol message serialization.
//!
//! Configure streams with [`EncryptedStreamOptions`]:
//!
//! ```rust
//! use clavis::EncryptedStreamOptions;
//!
//! let options = EncryptedStreamOptions {
//!     max_packet_size: 1024 * 1024,  // 1MB packet size limit
//!     psk: Some(vec![/* 32 bytes of secure random data */]),
//! };
//! ```

mod crypto;
mod error;
mod stream;

pub mod prelude {
    pub use {bincode, serde};
}

pub use crate::error::*;
pub use crate::stream::{EncryptedPacket, EncryptedStream, EncryptedStreamOptions};

pub trait PacketTrait: Send + Sync + Sized {
    fn serialize(&self) -> ClavisResult<Vec<u8>>;
    fn deserialize(data: &[u8]) -> ClavisResult<Self>;
}

#[macro_export]
macro_rules! protocol {
    (
        $(
            $(#[$enum_meta:meta])*
            $enum_vis:vis enum $enum_name:ident {
                $(
                    $(#[$variant_meta:meta])*
                    $variant_vis:vis $variant:ident
                    $(($inner:ty))?
                    $({ $( $field:ident : $ftype:ty ),* $(,)? })?
                ),* $(,)?
            }
        )*
    ) => {
        $(
            #[derive($crate::prelude::serde::Serialize, $crate::prelude::serde::Deserialize)]
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                $(
                    $(#[$variant_meta])*
                    $variant_vis $variant
                    $(($inner))?
                    $({ $( $field : $ftype ),* })?,
                )*
            }

            impl $crate::PacketTrait for $enum_name {
                fn serialize(&self) -> $crate::ClavisResult<Vec<u8>> {
                    $crate::prelude::bincode::serialize(self)
                        .map_err(|e| $crate::ClavisError::serialization_failed(format!(
                            "Failed to serialize {}: {}", stringify!($enum_name), e
                        )))
                }

                fn deserialize(data: &[u8]) -> $crate::ClavisResult<Self> {
                    use $crate::MessageError;

                    if data.is_empty() {
                        return Err($crate::ClavisError::Message(
                            MessageError::InvalidFormat("Empty packet data".into())
                        ));
                    }

                    $crate::prelude::bincode::deserialize(data)
                        .map_err(|e| $crate::ClavisError::deserialization_failed(format!(
                            "Failed to deserialize {}: {}", stringify!($enum_name), e
                        )))
                }
            }
        )*
    };
}

