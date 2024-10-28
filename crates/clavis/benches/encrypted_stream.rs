use clavis::{
    protocol, ClavisResult, EncryptedPacket, EncryptedStream, EncryptedStreamOptions, PacketTrait,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::{io::DuplexStream, runtime::Runtime};

const BUFFER_SIZES: &[usize] = &[1024, 4096, 16384, 65536];
const TEST_PSK: &[u8; 32] = b"benchmark_test_key_32_bytes_long";

protocol! {
    enum Packet {
        Heartbeat,
    }
}

async fn setup_streams(
    size: usize,
    use_psk: bool,
) -> ClavisResult<(EncryptedStream<DuplexStream>, EncryptedStream<DuplexStream>)> {
    let (client_stream, server_stream) = tokio::io::duplex(size);

    let options = if use_psk {
        Some(EncryptedStreamOptions {
            psk: Some(TEST_PSK.to_vec()),
            ..Default::default()
        })
    } else {
        None
    };

    let server_options = options.clone();
    let server_setup =
        tokio::spawn(async move { EncryptedStream::new(server_stream, server_options).await });

    let client = EncryptedStream::new(client_stream, options).await?;
    let server = server_setup.await.unwrap()?;
    Ok((client, server))
}

fn run_benchmarks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Stream benchmarks
    {
        let mut group = c.benchmark_group("encrypted_stream");
        for &size in BUFFER_SIZES {
            group.throughput(Throughput::Bytes(size as u64));

            // Benchmark key exchange without PSK
            group.bench_function(BenchmarkId::new("key_exchange_no_psk", size), |b| {
                b.to_async(&rt)
                    .iter(|| async { setup_streams(size, false).await });
            });

            // Benchmark key exchange with PSK
            group.bench_function(BenchmarkId::new("key_exchange_with_psk", size), |b| {
                b.to_async(&rt)
                    .iter(|| async { setup_streams(size, true).await });
            });

            // Benchmark packet sending without PSK
            group.bench_function(BenchmarkId::new("packet_send_no_psk", size), |b| {
                b.to_async(&rt).iter_batched(
                    || setup_streams(size, false),
                    |fut| async {
                        let (mut client, _server) = fut.await.unwrap();
                        client.write_packet(&Packet::Heartbeat).await.unwrap()
                    },
                    criterion::BatchSize::LargeInput,
                );
            });

            // Benchmark packet sending with PSK
            group.bench_function(BenchmarkId::new("packet_send_with_psk", size), |b| {
                b.to_async(&rt).iter_batched(
                    || setup_streams(size, true),
                    |fut| async {
                        let (mut client, _server) = fut.await.unwrap();
                        client.write_packet(&Packet::Heartbeat).await.unwrap()
                    },
                    criterion::BatchSize::LargeInput,
                );
            });

            // Benchmark packet receiving without PSK
            group.bench_function(BenchmarkId::new("packet_receive_no_psk", size), |b| {
                b.to_async(&rt).iter_batched(
                    || async {
                        let (mut client, server) = setup_streams(size, false).await.unwrap();
                        client.write_packet(&Packet::Heartbeat).await.unwrap();
                        (client, server)
                    },
                    |fut| async {
                        let (_client, mut server) = fut.await;
                        server.read_packet::<Packet>().await.unwrap()
                    },
                    criterion::BatchSize::LargeInput,
                );
            });

            // Benchmark packet receiving with PSK
            group.bench_function(BenchmarkId::new("packet_receive_with_psk", size), |b| {
                b.to_async(&rt).iter_batched(
                    || async {
                        let (mut client, server) = setup_streams(size, true).await.unwrap();
                        client.write_packet(&Packet::Heartbeat).await.unwrap();
                        (client, server)
                    },
                    |fut| async {
                        let (_client, mut server) = fut.await;
                        server.read_packet::<Packet>().await.unwrap()
                    },
                    criterion::BatchSize::LargeInput,
                );
            });
        }
        group.finish();
    }

    // Serialization benchmarks
    {
        let mut group = c.benchmark_group("packet_serialization");
        // Heartbeat serialization/deserialization
        {
            let packet = Packet::Heartbeat;
            let serialized = packet.serialize().unwrap();
            group.bench_function("serialize_heartbeat", |b| {
                b.iter(|| packet.serialize().unwrap());
            });
            group.bench_function("deserialize_heartbeat", |b| {
                b.iter(|| Packet::deserialize(&serialized).unwrap());
            });
        }
        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = run_benchmarks
}

criterion_main!(benches);
