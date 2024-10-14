use clavis::{define_user_packets, EncryptedPacketStream, Role};
use criterion::{criterion_group, criterion_main, Criterion};
use futures::channel::mpsc;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Serialize, Deserialize, Debug)]
pub struct PingPongData {
    pub message: String,
}

define_user_packets!(
    Ping = 1 => PingPongData,
    Pong = 2 => PingPongData
);

struct DuplexStream {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}

impl AsyncRead for DuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.incoming.poll_next_unpin(cx) {
            Poll::Ready(Some(data)) => {
                let len = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..len]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for DuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.outgoing.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let _ = self.outgoing.start_send(buf.to_vec());
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn create_duplex_pair() -> (DuplexStream, DuplexStream) {
    let (client_tx, server_rx) = mpsc::channel(100);
    let (server_tx, client_rx) = mpsc::channel(100);

    (
        DuplexStream {
            incoming: client_rx,
            outgoing: client_tx,
        },
        DuplexStream {
            incoming: server_rx,
            outgoing: server_tx,
        },
    )
}

async fn perform_roundtrip(
    encrypted_stream: &mut EncryptedPacketStream<DuplexStream>,
) -> clavis::Result<()> {
    let ping = UserPacket::Ping(PingPongData {
        message: "hello".to_string(),
    });

    encrypted_stream.write_packet(&ping).await?;
    let _: UserPacket = encrypted_stream.read_packet().await?;

    Ok(())
}

fn benchmark_packet_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    c.bench_function("packet_roundtrip", |b| {
        b.to_async(&rt).iter(|| async {
            let (client_stream, server_stream) = create_duplex_pair();

            let server_handle = tokio::spawn(async move {
                let mut server = EncryptedPacketStream::new(server_stream, Role::Server, None, None)
                    .await
                    .expect("Failed to create server stream");

                while let Ok(UserPacket::Ping(ping)) = server.read_packet::<UserPacket>().await {
                    let pong = UserPacket::Pong(PingPongData {
                        message: format!("Pong: {}", ping.message),
                    });
                    let _ = server.write_packet(&pong).await;
                }
            });

            let mut client = EncryptedPacketStream::new(client_stream, Role::Client, None, None)
                .await
                .expect("Failed to create client stream");

            criterion::black_box(perform_roundtrip(&mut client).await.unwrap());
            
            server_handle.abort();
        });
    });
}

criterion_group!(benches, benchmark_packet_roundtrip);
criterion_main!(benches);