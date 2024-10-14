# Clavis

![Crates.io](https://img.shields.io/crates/v/clavis)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

Clavis is a **Rust** library that facilitates **secure, encrypted communication** over asynchronous streams. Leveraging **X25519** for key exchange and **AES-256-GCM-SIV** for encryption, Clavis ensures the **confidentiality** and **integrity** of transmitted data while providing a **simple and efficient API**.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Getting Started](#getting-started)
  - [Define Your Packets](#define-your-packets)
  - [Establishing a Secure Connection](#establishing-a-secure-connection)
    - [Client Example](#client-example)
    - [Server Example](#server-example)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [License](#license)

## Installation

Add Clavis to your `Cargo.toml`:

```toml
[dependencies]
clavis = "0.1.0" # Replace with the latest version from crates.io
```

*Alternatively, to use the latest development version:*

```toml
[dependencies]
clavis = { git = "https://github.com/pyrohost/clavis.git" }
```

## Getting Started

### Define Your Packets

Clavis uses macros to define custom packet types for communication. This allows you to serialize and deserialize your data seamlessly.

First, ensure you have the necessary dependencies in your `Cargo.toml`:

```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
clavis = "0.1.0"
```

Now, define your packet types:

```rust
use clavis::define_user_packets;
use serde::{Serialize, Deserialize};

// Define your data structure
#[derive(Serialize, Deserialize)]
struct MyData {
    id: u32,
    message: String,
    // Add other fields as needed
}

// Use the macro to define your packet
define_user_packets! {
    MyPacket = 1 => MyData, // PacketName = PacketId => DataType
}
```

### Establishing a Secure Connection

Clavis supports both **client** and **server** roles. Below are examples demonstrating how to set up each.

#### Client Example

```rust
use clavis::{EncryptedPacketStream, Role, Result};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    // Connect to the server
    let stream = TcpStream::connect("127.0.0.1:7272").await?;
    
    // Initialize the encrypted stream as a client
    let mut encrypted_stream = EncryptedPacketStream::new(stream, Role::Client, None, None).await?;
    
    // Create a packet with your data
    let data = MyData {
        id: 1,
        message: "Hello, Server!".into(),
    };
    let packet = MyPacket::new(data);
    
    // Send the packet
    encrypted_stream.write_packet(&packet).await?;
    println!("Packet sent to the server.");
    
    // Await a response
    if let Some(response) = encrypted_stream.read_packet::<MyPacket>().await? {
        println!("Received response: {:?}", response);
    }
    
    Ok(())
}
```

#### Server Example

```rust
use clavis::{EncryptedPacketStream, Role, Result};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    // Bind the server to a local address
    let listener = TcpListener::bind("127.0.0.1:7272").await?;
    println!("Server listening on 127.0.0.1:7272");
    
    loop {
        // Accept incoming connections
        let (stream, addr) = listener.accept().await?;
        println!("New connection from {}", addr);
        
        // Spawn a new task for each connection
        tokio::spawn(async move {
            match handle_client(stream).await {
                Ok(_) => println!("Connection with {} closed.", addr),
                Err(e) => eprintln!("Error handling {}: {:?}", addr, e),
            }
        });
    }
}

async fn handle_client(stream: tokio::net::TcpStream) -> Result<()> {
    // Initialize the encrypted stream as a server
    let mut encrypted_stream = EncryptedPacketStream::new(stream, Role::Server, None, None).await?;
    
    // Read a packet from the client
    if let Some(packet) = encrypted_stream.read_packet::<MyPacket>().await? {
        println!("Received packet: {:?}", packet);
        
        // Respond to the client
        let response_data = MyData {
            id: packet.id,
            message: "Hello, Client!".into(),
        };
        let response_packet = MyPacket::new(response_data);
        encrypted_stream.write_packet(&response_packet).await?;
        println!("Response sent to client.");
    }
    
    Ok(())
}
```

## API Documentation

Comprehensive API documentation is available [here](https://docs.rs/clavis). Explore the various modules, structs, and functions to leverage the full capabilities of Clavis in your projects.

## License

This project is licensed under the [MIT License](LICENSE).
