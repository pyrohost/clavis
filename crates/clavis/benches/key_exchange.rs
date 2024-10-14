// TODO: Don't use real network connections in benchmarks to avoid flakiness

use clavis::{EncryptedPacketStream, Role};
use criterion::{criterion_group, criterion_main, Criterion};
use std::io::ErrorKind;
use std::sync::mpsc;
use std::thread;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

fn start_server() -> (mpsc::Receiver<()>, u16) {
    let (tx, rx) = mpsc::channel();

    let rt = Runtime::new().expect("Failed to create Tokio runtime");
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
    let addr = std_listener.local_addr().unwrap();
    let port = addr.port();

    std_listener
        .set_nonblocking(true)
        .expect("Cannot set non-blocking");

    thread::spawn(move || {
        rt.block_on(async {
            let listener = TcpListener::from_std(std_listener).expect("Failed to convert listener");
            tx.send(()).expect("Failed to send server ready signal");

            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        tokio::spawn(async move {
                            match EncryptedPacketStream::new(stream, Role::Server, None, None).await
                            {
                                Ok(_) => {}
                                Err(e) => {
                                    eprintln!(
                                        "Server failed to initialize EncryptedPacketStream: {}",
                                        e
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        if e.kind() != ErrorKind::WouldBlock {
                            eprintln!("Server failed to accept connection: {}", e);
                        }
                        // Sleep briefly to avoid busy loop
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
            }
        });
    });

    (rx, port)
}

fn key_exchange_benchmark(c: &mut Criterion) {
    let (ready_rx, port) = start_server();

    ready_rx
        .recv()
        .expect("Failed to receive server ready signal");

    let rt = Runtime::new().expect("Failed to create Tokio runtime");

    c.bench_function("key_exchange", |b| {
        b.to_async(&rt).iter(|| async {
            let addr = format!("127.0.0.1:{}", port);

            let stream = TcpStream::connect(&addr)
                .await
                .expect("Client failed to connect to server");

            let encrypted_stream = EncryptedPacketStream::new(stream, Role::Client, None, None)
                .await
                .expect("Client failed to perform key exchange");

            criterion::black_box(encrypted_stream);
        });
    });
}

criterion_group!(benches, key_exchange_benchmark);
criterion_main!(benches);
