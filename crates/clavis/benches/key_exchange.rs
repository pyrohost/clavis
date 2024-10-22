use clavis::{EncryptedStream, Role};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;

async fn perform_key_exchange() -> clavis::Result<EncryptedStream<tokio::io::DuplexStream>> {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let server_setup =
        tokio::spawn(async move { EncryptedStream::new(server_stream, Role::Server, None).await });

    let client = EncryptedStream::new(client_stream, Role::Client, None).await?;

    server_setup.await.unwrap()?;

    Ok(client)
}

fn key_exchange_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("key_exchange", |b| {
        b.to_async(&rt).iter(|| async {
            let client = perform_key_exchange().await.expect("Key exchange failed");
            black_box(client);
        });
    });
}

criterion_group!(benches, key_exchange_benchmark);
criterion_main!(benches);
