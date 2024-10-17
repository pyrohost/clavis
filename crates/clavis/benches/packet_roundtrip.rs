use clavis::{
    define_packets, EncryptedReader, EncryptedStream, EncryptedWriter, PacketError, Result, Role,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use futures::channel::mpsc;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingPongData {
    pub message: String,
}

define_packets!(Ping(PingPongData), Pong(PingPongData));

struct DuplexStream {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}

impl AsyncRead for DuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
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
    ) -> Poll<std::io::Result<usize>> {
        match self.outgoing.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                self.outgoing.try_send(buf.to_vec()).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Channel closed")
                })?;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
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

async fn perform_roundtrip<R, W>(
    reader: &mut EncryptedReader<R>,
    writer: &mut EncryptedWriter<W>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let ping = Packet::Ping(PingPongData {
        message: "hello".to_string(),
    });

    writer.write_packet(&ping).await?;

    let response_packet = reader.read_packet().await?;

    match response_packet {
        Packet::Pong(pong) => {
            assert_eq!(pong.message, "Pong: hello");
            Ok(())
        }
        _ => Err(PacketError::Deserialization(
            "Unexpected packet type".into(),
        )),
    }
}

fn benchmark_packet_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    c.bench_function("packet_roundtrip", |b| {
        b.to_async(&rt).iter(|| async {
            let (client_stream, server_stream) = create_duplex_pair();

            let server_handle = tokio::spawn(async move {
                let server_stream = EncryptedStream::new(server_stream, Role::Server, None, None)
                    .await
                    .expect("Failed to create server stream");

                let (mut server_reader, mut server_writer) = server_stream.split();

                loop {
                    match server_reader.read_packet().await {
                        Ok(Packet::Ping(ping)) => {
                            let pong = Packet::Pong(PingPongData {
                                message: format!("Pong: {}", ping.message),
                            });
                            server_writer.write_packet(&pong).await?;
                        }
                        Ok(_) => {
                            continue;
                        }
                        Err(e) => {
                            eprintln!("Server encountered an error: {}", e);
                            break;
                        }
                    }
                }

                Ok::<(), PacketError>(())
            });

            let client_stream = EncryptedStream::new(client_stream, Role::Client, None, None)
                .await
                .expect("Failed to create client stream");

            let (mut client_reader, mut client_writer) = client_stream.split();

            perform_roundtrip(&mut client_reader, &mut client_writer)
                .await
                .expect("Roundtrip failed");

            server_handle.abort();

            black_box((client_reader, client_writer));
        });
    });
}

criterion_group!(benches, benchmark_packet_roundtrip);
criterion_main!(benches);
