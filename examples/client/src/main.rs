use clavis::{EncryptedPacketStream, Role};
use packets::{PingPongData, UserPacket};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> clavis::Result<()> {
    tracing_subscriber::fmt::init();

    let stream = TcpStream::connect("127.0.0.1:7272").await?;
    let mut encrypted_stream = EncryptedPacketStream::new(stream, Role::Client, None, None).await?;

    let ping = UserPacket::Ping(PingPongData {
        message: "hello".to_string(),
    });
    encrypted_stream.write_packet(&ping).await?;

    if let UserPacket::Pong(pong) = encrypted_stream.read_packet().await? {
        println!("Received Pong: {:?}", pong);
    }

    Ok(())
}
