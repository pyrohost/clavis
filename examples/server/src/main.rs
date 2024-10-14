use clavis::{EncryptedPacketStream, Role};
use packets::{PingPongData, UserPacket};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> clavis::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let listener = TcpListener::bind("127.0.0.1:7272").await?;
    println!("Server listening on 127.0.0.1:7272");

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("Error handling client: {:?}", e);
            }
        });
    }
}

async fn handle_client(stream: tokio::net::TcpStream) -> clavis::Result<()> {
    let mut encrypted_stream = EncryptedPacketStream::new(stream, Role::Server, None, None).await?;

    loop {
        match encrypted_stream.read_packet().await {
            Ok(UserPacket::Ping(ping)) => {
                println!("Received Ping: {:?}", ping);
                let pong = UserPacket::Pong(PingPongData {
                    message: "world".to_string(),
                });
                encrypted_stream.write_packet(&pong).await?;
            }
            _ => {
                println!("Received unexpected packet or client disconnected");
                break;
            }
        }
    }

    Ok(())
}
