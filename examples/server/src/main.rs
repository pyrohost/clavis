use clavis::{EncryptedStream, Result, Role};
use packets::{Packet, PingPongData};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let listener = TcpListener::bind("127.0.0.1:7272").await?;
    info!("Server listening on 127.0.0.1:7272");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New client connected: {}", addr);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream).await {
                        error!("Error handling client {}: {:?}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting client: {:?}", e);
            }
        }
    }
}

async fn handle_client(stream: tokio::net::TcpStream) -> Result<()> {
    let encrypted_stream = EncryptedStream::new(stream, Role::Server, None).await?;
    let (mut reader, mut writer) = encrypted_stream.split();

    loop {
        match timeout(Duration::from_secs(30), reader.read_packet()).await {
            Ok(Ok(Packet::Ping(ping))) => {
                info!("Received Ping: {:?}", ping);
                let pong = Packet::Pong(PingPongData {
                    message: ping.message,
                });
                writer.write_packet(&pong).await?;
                debug!("Sent Pong response");
            }
            Ok(Ok(Packet::Shutdown)) => {
                info!("Received shutdown request");
                break;
            }
            Ok(Ok(_)) => {
                warn!("Received unexpected packet");
                break;
            }
            Ok(Err(e)) => {
                error!("Error reading packet: {:?}", e);
                break;
            }
            Err(_) => {
                warn!("Timeout waiting for packet");
                break;
            }
        }
    }

    info!("Client handler exiting");
    Ok(())
}
