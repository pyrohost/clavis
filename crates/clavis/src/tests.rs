use super::*;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::time::timeout;

define_packets! {
    enum TestPacket {
        Message(String),
    }
}

/// Helper function to set up encrypted streams with proper timing
async fn setup_encrypted_streams(
    psk: Option<&[u8]>,
) -> Result<(EncryptedStream<DuplexStream>, EncryptedStream<DuplexStream>)> {
    let (client_stream, server_stream) = tokio::io::duplex(1024);

    // Convert PSK to owned bytes to avoid lifetime issues
    let psk_owned = psk.map(|p| p.to_vec());

    // First set up server
    let server_setup = tokio::spawn(async move {
        EncryptedStream::new(server_stream, Role::Server, psk_owned.as_deref()).await
    });

    // Small delay to ensure server is ready
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Then set up client
    let client = EncryptedStream::new(client_stream, Role::Client, psk).await?;
    let server = server_setup.await.unwrap()?;

    Ok((client, server))
}

/// Helper function to send and verify a message
async fn send_and_verify_message<T, U>(
    sender: &mut EncryptedStream<T>,
    receiver: &mut EncryptedStream<U>,
    message: &str,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    sender
        .write_packet(&TestPacket::Message(message.to_string()))
        .await?;

    match receiver.read_packet::<TestPacket>().await? {
        TestPacket::Message(received) => assert_eq!(received, message),
    }

    Ok(())
}

#[tokio::test]
async fn test_basic_communication() -> Result<()> {
    let (mut client, mut server) = setup_encrypted_streams(None).await?;
    send_and_verify_message(&mut client, &mut server, "Hello from client").await?;
    Ok(())
}

#[tokio::test]
async fn test_bidirectional_communication() -> Result<()> {
    let (mut client, mut server) = setup_encrypted_streams(None).await?;

    // Test both directions
    send_and_verify_message(&mut client, &mut server, "Hello from client").await?;
    send_and_verify_message(&mut server, &mut client, "Hello from server").await?;

    Ok(())
}

#[tokio::test]
async fn test_split_stream() -> Result<()> {
    let (client, server) = setup_encrypted_streams(None).await?;

    let (_, mut client_writer) = client.split();
    let (mut server_reader, _) = server.split();

    let write_task = tokio::spawn(async move {
        client_writer
            .write_packet(&TestPacket::Message("Hello from client".to_string()))
            .await
    });

    let read_task = tokio::spawn(async move {
        let received = server_reader.read_packet::<TestPacket>().await?;
        match received {
            TestPacket::Message(msg) => assert_eq!(msg, "Hello from client"),
        }
        Ok::<_, PacketError>(())
    });

    write_task.await.unwrap()?;
    read_task.await.unwrap()?;

    Ok(())
}

#[tokio::test]
async fn test_authenticated_communication() -> Result<()> {
    let psk = b"test-pre-shared-key";
    let (mut client, mut server) = setup_encrypted_streams(Some(psk)).await?;
    send_and_verify_message(&mut client, &mut server, "Authenticated message").await?;
    Ok(())
}

#[tokio::test]
async fn test_authentication_failure() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);

    let server_setup = tokio::spawn(async move {
        EncryptedStream::new(server_stream, Role::Server, Some(b"key1")).await
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let client_result = EncryptedStream::new(client_stream, Role::Client, Some(b"key2")).await;
    let server_result = server_setup.await.unwrap();

    assert!(client_result.is_err() || server_result.is_err());
}

#[tokio::test]
async fn test_large_message() -> Result<()> {
    let (mut client, _server) = setup_encrypted_streams(None).await?;

    // Create a message that's too large
    let large_message = "x".repeat(MAX_DATA_LENGTH as usize + 1);

    let result = client
        .write_packet(&TestPacket::Message(large_message))
        .await;

    assert!(matches!(result, Err(PacketError::DataTooLarge)));
    Ok(())
}

#[tokio::test]
async fn test_concurrent_messages() -> Result<()> {
    let (client, server) = setup_encrypted_streams(None).await?;

    let (mut client_reader, mut client_writer) = client.split();
    let (mut server_reader, mut server_writer) = server.split();

    let message_count = 100;

    let tasks = vec![
        tokio::spawn(async move {
            for i in 0..message_count {
                client_writer
                    .write_packet(&TestPacket::Message(format!("Message {}", i)))
                    .await?;
            }
            Ok::<_, PacketError>(())
        }),
        tokio::spawn(async move {
            for i in 0..message_count {
                server_writer
                    .write_packet(&TestPacket::Message(format!("Response {}", i)))
                    .await?;
            }
            Ok::<_, PacketError>(())
        }),
        tokio::spawn(async move {
            for i in 0..message_count {
                let msg = client_reader.read_packet::<TestPacket>().await?;
                match msg {
                    TestPacket::Message(content) => assert_eq!(content, format!("Response {}", i)),
                }
            }
            Ok::<_, PacketError>(())
        }),
        tokio::spawn(async move {
            for i in 0..message_count {
                let msg = server_reader.read_packet::<TestPacket>().await?;
                match msg {
                    TestPacket::Message(content) => assert_eq!(content, format!("Message {}", i)),
                }
            }
            Ok::<_, PacketError>(())
        }),
    ];

    for task in tasks {
        task.await.unwrap()?;
    }

    Ok(())
}

#[tokio::test]
async fn test_timeout_handling() -> Result<()> {
    let (_client, mut server) = setup_encrypted_streams(None).await?;
    let result = timeout(
        Duration::from_millis(100),
        server.read_packet::<TestPacket>(),
    )
    .await;

    assert!(result.is_err(), "Expected timeout error");
    Ok(())
}