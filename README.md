# Clavis

![Crates.io](https://img.shields.io/crates/v/clavis)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

Clavis is a **Rust** library that provides secure, encrypted communication over asynchronous streams. It implements a robust protocol using XChaCha20Poly1305 for encryption and X25519 for key exchange, with optional pre-shared key (PSK) authentication. Built on top of the [Tokio](https://tokio.rs/) runtime, Clavis offers a high-level abstraction for building secure network applications.

## Installation

Add Clavis to your `Cargo.toml`:

```toml
[dependencies]
clavis = { git = "https://github.com/pyrohost/clavis.git" }
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
```

## Quick Start

### 1. Define Your Packets

Use the `define_packets!` macro to create your packet types:

```rust
use clavis::define_packets;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct StructPacket {
    content: String,
}

define_packets! {
    pub enum MyPacket {
        VoidMessage,
        Message(String),
        StructPacket(MyPacket),
        StructuredMessage { content: String },
    }
}
```

### 2. Establish an Encrypted Connection

#### Client Example

```rust
use clavis::{EncryptedStream, Role};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the server
    let stream = TcpStream::connect("127.0.0.1:8080").await?;
    
    // Optional: Use a pre-shared key for additional security
    let psk = b"my_secret_key";
    
    // Create an encrypted stream
    let mut client = EncryptedStream::new(stream, Role::Client, Some(psk)).await?;
    
    // Send an encrypted message
    client.write_packet(&MyPacket::Message("Hello, server!".to_string())).await?;
    
    // Receive the response
    let response: MyPacket = client.read_packet().await?;
    println!("Server response: {:?}", response);
    
    Ok(())
}
```

#### Server Example

```rust
use clavis::{EncryptedStream, Role};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server listening on :8080");

    while let Ok((stream, addr)) = listener.accept().await {
        println!("New connection from {}", addr);
        let psk = b"my_secret_key";
        
        tokio::spawn(async move {
            match EncryptedStream::new(stream, Role::Server, Some(psk)).await {
                Ok(mut server) => {
                    if let Ok(packet) = server.read_packet::<MyPacket>().await {
                        println!("Received: {:?}", packet);
                        
                        // Send a response
                        let _ = server
                            .write_packet(&MyPacket::Message("Hello, client!".to_string()))
                            .await;
                    }
                }
                Err(e) => eprintln!("Connection error: {}", e),
            }
        });
    }

    Ok(())
}
```

## Advanced Usage

### Splitting Streams

You can split an `EncryptedStream` into separate reader and writer halves for concurrent operations:

```rust
let (mut reader, mut writer) = encrypted_stream.split();

// Use reader and writer independently
tokio::spawn(async move {
    while let Ok(packet) = reader.read_packet::<MyPacket>().await {
        println!("Received: {:?}", packet);
    }
});

// Write packets from another task
writer.write_packet(&MyPacket::Message("Hello!".to_string())).await?;
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
