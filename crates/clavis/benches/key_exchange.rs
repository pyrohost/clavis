use clavis::{EncryptedStream, Role};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use futures::channel::mpsc;
use futures::StreamExt;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
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

fn key_exchange_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    c.bench_function("key_exchange", |b| {
        b.to_async(&rt).iter(|| async {
            let (client_stream, server_stream) = create_duplex_pair();

            let server_handle = tokio::spawn(async move {
                let _server = EncryptedStream::new(server_stream, Role::Server, None)
                    .await
                    .expect("Server failed to perform key exchange");
            });

            let client = EncryptedStream::new(client_stream, Role::Client, None)
                .await
                .expect("Client failed to perform key exchange");

            server_handle.await.expect("Server task panicked");

            black_box(client);
        });
    });
}

criterion_group!(benches, key_exchange_benchmark);
criterion_main!(benches);
