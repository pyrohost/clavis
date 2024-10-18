use clavis::{EncryptedStream, Result, Role};
use packets::{Packet, PingPongData};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let stream = TcpStream::connect("127.0.0.1:7272").await?;
    info!("Connected to server");

    let encrypted_stream = EncryptedStream::new(stream, Role::Client, None).await?;
    let (mut reader, mut writer) = encrypted_stream.split();

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
