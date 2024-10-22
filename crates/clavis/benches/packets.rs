use clavis::{define_packets, EncryptedStream, Result, Role};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::io::DuplexStream;
use tokio::runtime::Runtime;

define_packets! {
    enum Packet {
        Ping,
        Pong,
    }
}

async fn setup_encrypted_streams(
) -> Result<(EncryptedStream<DuplexStream>, EncryptedStream<DuplexStream>)> {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let server_setup =
        tokio::spawn(async move { EncryptedStream::new(server_stream, Role::Server, None).await });

    let client = EncryptedStream::new(client_stream, Role::Client, None).await?;
    let server = server_setup.await.unwrap()?;

    Ok((client, server))
}

fn run_benchmarks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("send_packet", |b| {
        b.to_async(&rt).iter_batched(
            || async { setup_encrypted_streams().await.unwrap() },
            |streams| async move {
                let (mut client, server) = streams.await;
                let ping = Packet::Ping;
                client.write_packet(&ping).await.unwrap();
                black_box((client, server));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("receive_packet", |b| {
        b.to_async(&rt).iter_batched(
            || async {
                let (mut client, server) = setup_encrypted_streams().await.unwrap();
                // Pre-populate with a packet
                let ping = Packet::Ping;
                client.write_packet(&ping).await.unwrap();
                (client, server)
            },
            |streams| async move {
                let (client, mut server) = streams.await;
                let _ = server.read_packet::<Packet>().await.unwrap();
                black_box((client, server));
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, run_benchmarks);
criterion_main!(benches);
