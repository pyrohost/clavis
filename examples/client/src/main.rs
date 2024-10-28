use clavis::{EncryptedPacket, EncryptedStream};
use packets::{Packet, PingPongData};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let stream = TcpStream::connect("127.0.0.1:7272").await?;
    info!("Connected to server");

    let encrypted_stream = EncryptedStream::new(stream, None).await?;
    let (mut reader, mut writer) = match encrypted_stream.split() {
        Ok(split) => split,
        Err(e) => {
            error!("Failed to split encrypted stream: {:?}", e);
            return Err(e.into());
        }
    };

    for i in 1..=5 {
        let ping = Packet::Ping(PingPongData {
            message: format!("hello {}", i),
        });
        writer.write_packet(&ping).await?;
        debug!("Sent Ping {}", i);

        match timeout(Duration::from_secs(5), reader.read_packet()).await {
            Ok(Ok(Packet::Pong(pong))) => {
                info!("Received Pong {}: {:?}", i, pong);
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
                warn!("Timeout waiting for Pong");
                break;
            }
        }
    }

    writer.write_packet(&Packet::Shutdown).await?;
    info!("Sent shutdown request");

    Ok(())
}
