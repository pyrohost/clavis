# Clavis

![Crates.io](https://img.shields.io/crates/v/clavis)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Rust Version](https://img.shields.io/badge/rust-1.75%2B-orange.svg)

Clavis is an asynchronous Rust library designed for secure, encrypted communication over network streams. Built on `tokio`, it provides abstractions for encrypted packet-based communication with strong security guarantees, utilizing modern cryptographic primitives.

The library implements XChaCha20-Poly1305 encryption, along with a type-safe protocol DSL macro for custom protocol definitions and built-in serialization.

## Installation

To add Clavis to your project, include these dependencies in `Cargo.toml`:

```toml
[dependencies]
clavis = { git = "https://github.com/pyrohost/clavis" }
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

## Quick Start

### Defining a Protocol

Define custom protocol messages using the `protocol!` macro:

```rust
use clavis::protocol;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    username: String,
    content: String,
    timestamp: u64,
}

protocol! {
    enum ChatProtocol {
        Heartbeat,
        Join(String),
        Leave(String),
        Message(ChatMessage),
        Status {
            users_online: u32,
            server_uptime: u64,
        },
    }
}
```

### Client Implementation

Set up a client to connect, send, and receive encrypted messages:

```rust
use clavis::{EncryptedStream, EncryptedStreamOptions, EncryptedPacket};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect("127.0.0.1:8080").await?;
    let options = EncryptedStreamOptions {
        max_packet_size: 65536,
        psk: Some(b"pre-shared_key".to_vec()),
    };
    let encrypted = EncryptedStream::new(stream, Some(options)).await?;
    let (mut reader, mut writer) = encrypted.split()?;

    writer.write_packet(&ChatProtocol::Join("Alice".into())).await?;

    if let Ok(packet) = reader.read_packet::<ChatProtocol>().await {
        println!("Received packet: {:?}", packet);
    }
    
    Ok(())
}
```

### Server Implementation

Set up a server to handle encrypted client connections and process messages:

```rust
use clavis::{EncryptedStream, EncryptedStreamOptions, EncryptedPacket};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server listening on :8080");

    while let Ok((stream, addr)) = listener.accept().await {
        tokio::spawn(async move {
            let options = EncryptedStreamOptions {
                max_packet_size: 65536,
                psk: Some(b"shared_secret".to_vec()),
            };
            match EncryptedStream::new(stream, Some(options)).await {
                Ok(mut encrypted) => {
                    if let Ok(packet) = encrypted.read_packet::<ChatProtocol>().await {
                        println!("Received packet: {:?}", packet);
                    }
                }
                Err(e) => eprintln!("Connection error: {}", e),
            }
        });
    }

    Ok(())
}
```

## Contributing

We welcome contributions! For suggestions, bug reports, or feature requests, please open an issue or submit a pull request on our GitHub repository.

## Security

Clavis is designed to provide strong security guarantees. However, no software is perfect, and security vulnerabilities may exist. If you discover a security issue, please report it [here](https://github.com/pyrohost/clavis/security) so we can address it promptly.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
