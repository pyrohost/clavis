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
        $(#[$meta_root:meta])*
        $vis:vis enum $name:ident {
            $($contents:tt)*
        }
    ) => {
        protocol! {
        @subparser
        {
            $(#[$meta_root])*
        },
        ($vis, $name),
        {},
        $($contents)*
        }
    };

    (
    @subparser
    {
        $(#[$meta_root:meta])*
    },
    ($vis:vis, $name:ident),
    { $($acc:tt)* },
    ) => {
        #[derive($crate::prelude::serde::Serialize, $crate::prelude::serde::Deserialize)]
        $(#[$meta_root])*
        $vis enum $name {
            $($acc)*
        }

        impl $crate::PacketTrait for $name {
            fn serialize(&self) -> $crate::ClavisResult<std::vec::Vec<u8>> {
                $crate::prelude::bincode::serialize(self)
                    .map_err(|e| $crate::ClavisError::serialization_failed(::std::format!(
                        "Failed to serialize {}: {}", stringify!($enum_name), e
                    )))
            }

            fn deserialize(data: &[u8]) -> $crate::ClavisResult<Self> {
                use $crate::MessageError;

                if data.is_empty() {
                    return std::result::Result::Err($crate::ClavisError::Message(
                        MessageError::InvalidFormat("Empty packet data".into())
                    ));
                }

                $crate::prelude::bincode::deserialize(data)
                    .map_err(|e| $crate::ClavisError::deserialization_failed(::std::format!(
                        "Failed to deserialize {}: {}", stringify!($enum_name), e
                    )))
            }
        }
    };

    (
    @subparser
    {
        $(#[$meta_root:meta])*
    },
    ($vis:vis, $name:ident),
    { $($acc:tt)* },
    $(#[$vmeta:meta])*
    $v:ident,
    $($tail:tt)*
    ) => {
        protocol! {
        @subparser
        {
            $(#[$meta_root])*
        },
        ($vis, $name),
        {
            $($acc)*
            $(#[$vmeta])*
            $v,
        },
        $($tail)*
        }
    };

    (
    @subparser
    {
        $(#[$meta_root:meta])*
    },
    ($vis:vis, $name:ident),
    { $($acc:tt)* },
    $(#[$vmeta:meta])*
    $v:ident {
        $(
            $(#[$fmeta:meta])*
            $field:ident : $fty:ty
        ),* $(,)?
    } $(,)?
    $($tail:tt)*
    ) => {
        protocol! {
        @subparser
        {
            $(#[$meta_root])*
        },
        ($vis, $name),
        {
            $($acc)*
            $(#[$vmeta])*
            $v {
                $(
                    $(#[$fmeta])*
                    $field : $fty
                ),*
            },
        },
        $($tail)*
        }
    };

    (
    @subparser
    {
        $(#[$meta_root:meta])*
    },
    ($vis:vis, $name:ident),
    { $($acc:tt)* },
    $(#[$vmeta:meta])*
    $v:ident (
        $( $(#[$tmeta:meta])* $sty:ty),+ $(,)?
    ),
    $($tail:tt)*
    ) => {
        protocol! {
        @subparser
        {
            $(#[$meta_root])*
        },
        ($vis, $name),
        {
            $($acc)*
            $(#[$vmeta])*
            $v (
                $(
                    $(#[$tmeta])*
                    $sty
                ),+
            ),
        },
        $($tail)*
        }
    };
}

protocol! {
    #[derive(Default)]
    pub enum Test {
        /// Doc comment
        #[default]
        Default,

        Variant(#[doc = "hello"] String),
        /// Doc comment 2
        Variant2(#[doc = "hello 2"] u32, u32),

        Variant3 {
            field: Vec<u32>,
            field2: String,
            /// Docs
            field3: i32,
        }
    }
}

