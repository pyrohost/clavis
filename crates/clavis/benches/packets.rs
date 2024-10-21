use clavis::{define_packets, EncryptedReader, EncryptedStream, EncryptedWriter, Result, Role};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use futures::channel::mpsc;
use futures::StreamExt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

define_packets! {
    enum Packet {
        Ping,
        Pong,
    }
}

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
            Poll::Ready(Ok(())) => match self.outgoing.try_send(buf.to_vec()) {
                Ok(_) => Poll::Ready(Ok(buf.len())),
                Err(_) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Channel closed",
                ))),
            },
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

async fn send_packet<W>(writer: &mut EncryptedWriter<W>) -> Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let ping = Packet::Ping;
    writer.write_packet(&ping).await
}

async fn receive_packet<R>(reader: &mut EncryptedReader<R>) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
{
    let _ = reader.read_packet::<Packet>().await?;
    Ok(())
}

fn run_benchmarks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("send_packet", |b| {
        b.to_async(&rt).iter_batched(
            || async {
                let (client_stream, _) = create_duplex_pair();
                let client_stream = EncryptedStream::new(client_stream, Role::Client, None)
                    .await
                    .unwrap();
                let (_, writer) = client_stream.split();
                Arc::new(Mutex::new(writer))
            },
            |writer| async move {
                let binding = writer.await;
                let mut writer = binding.lock().await;
                black_box(send_packet(&mut writer).await.unwrap());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("receive_packet", |b| {
        b.to_async(&rt).iter_batched(
            || async {
                let (client_stream, server_stream) = create_duplex_pair();
                let client_stream = EncryptedStream::new(client_stream, Role::Client, None)
                    .await
                    .unwrap();
                let (_, mut client_writer) = client_stream.split();

                let server_stream = EncryptedStream::new(server_stream, Role::Server, None)
                    .await
                    .unwrap();
                let (server_reader, _) = server_stream.split();

                // Pre-populate the channel with a packet
                send_packet(&mut client_writer).await.unwrap();

                Arc::new(Mutex::new(server_reader))
            },
            |reader| async move {
                let binding = reader.await;
                let mut reader = binding.lock().await;
                black_box(receive_packet(&mut reader).await.unwrap());
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, run_benchmarks);
criterion_main!(benches);
