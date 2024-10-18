# Clavis

![Crates.io](https://img.shields.io/crates/v/clavis)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

Clavis is a **Rust** library that facilitates **secure, encrypted communication** over asynchronous streams. It provides a robust framework for establishing encrypted connections and exchanging custom packets between clients and servers. Clavis is built on top of the [Tokio](https://tokio.rs/) runtime and uses the [X25519](https://crates.io/crates/x25519-dalek) and [ChaCha20Poly1305](https://crates.io/crates/chacha20poly1305) crates for encryption and key exchange.

## Table of Contents

- [Installation](#installation)
- [Getting Started](#getting-started)
  - [Define Your Packets](#define-your-packets)
  - [Establishing a Secure Connection](#establishing-a-secure-connection)
    - [Client Example](#client-example)
    - [Server Example](#server-example)
- [Advanced Usage](#advanced-usage)
  - [Using Static Secrets](#using-static-secrets)
  - [Splitting Streams](#splitting-streams)
- [API Documentation](#api-documentation)
- [License](#license)

## Installation

Add Clavis to your `Cargo.toml`:

```toml
[dependencies]
clavis = { git = "https://github.com/pyrohost/clavis.git" }
tokio = { version = "1.0", features = ["full"] }
```

## Getting Started

### Define Your Packets

Use the `define_packets!` macro to define your custom packet types:

```rust
use clavis::{define_packets, PacketTrait};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingData {
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PongData {
    pub reply: String,
}

define_packets! {
    pub enum Packet {
        Ping(PingData),
        Pong(PongData)
    }
}
```

### Establishing a Secure Connection

#### Client Example

```rust
use clavis::{EncryptedStream, Role, Result};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    let stream = TcpStream::connect("127.0.0.1:7272").await?;
    let mut client_stream = EncryptedStream::new(stream, Role::Client, None).await?;

    // Create and send a Ping packet
    let ping = Packet::Ping(PingData {
        message: "Hello, Server!".into(),
    });
    client_stream.write_packet(&ping).await?;

    // Read the Pong response
    let response: Packet = client_stream.read_packet().await?;
    println!("Received response: {:?}", response);

    Ok(())
}
```

#### Server Example

```rust
use clavis::{EncryptedStream, Role, Result};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:7272").await?;
    println!("Server listening on 127.0.0.1:7272");

    while let Ok((stream, addr)) = listener.accept().await {
        println!("New connection from {}", addr);
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("Error handling {}: {:?}", addr, e);
            }
        });
    }

    Ok(())
}

async fn handle_client(stream: TcpStream) -> Result<()> {
    let mut server_stream = EncryptedStream::new(stream, Role::Server, None).await?;

    loop {
        match server_stream.read_packet().await? {
            Packet::Ping(ping) => {
                println!("Received Ping: {:?}", ping);
                let pong = Packet::Pong(PongData {
                    reply: format!("Pong: {}", ping.message),
                });
                server_stream.write_packet(&pong).await?;
            }
            _ => {
                // Handle unexpected packets
                continue;
            }
        }
    }
}
```

## Advanced Usage

### Using Static Secrets

For scenarios requiring persistent identities, you can provide a static secret:

```rust
use x25519_dalek::StaticSecret;
use rand::rngs::OsRng;

let static_secret = StaticSecret::random_from_rng(&mut OsRng);

let stream = EncryptedStream::new(
    tcp_stream,
    Role::Client,
    Some(static_secret)
).await?;
```

### Splitting Streams

You can split an `EncryptedStream` into separate read and write halves:

```rust
let (mut reader, mut writer) = encrypted_stream.split();

// Use reader and writer concurrently
tokio::join!(
    async move { reader.read_packet().await },
    async move { writer.write_packet(&some_packet).await }
);
```

## API Documentation

For detailed API documentation, please run `cargo doc --open` in your project directory after adding Clavis as a dependency.

## License

This project is licensed under the [MIT License](LICENSE).
