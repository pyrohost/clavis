use super::*;
use tokio::io::duplex;

define_packets! {
    enum TestPacket {
        Message(String),
    }
}

#[tokio::test]
async fn test_encrypted_stream() {
    let (client, server) = duplex(1024);
    let psk = b"test_psk";

    let client_task = tokio::spawn(async move {
        let mut client_stream = EncryptedStream::new(client, Role::Client, Some(psk))
            .await
            .unwrap();
        client_stream
            .write_packet(&TestPacket::Message("Hello, server!".to_string()))
            .await
            .unwrap();
        let response: TestPacket = client_stream.read_packet().await.unwrap();
        assert_eq!(response, TestPacket::Message("Hello, client!".to_string()));
    });

    let server_task = tokio::spawn(async move {
        let mut server_stream = EncryptedStream::new(server, Role::Server, Some(psk))
            .await
            .unwrap();
        let message: TestPacket = server_stream.read_packet().await.unwrap();
        assert_eq!(message, TestPacket::Message("Hello, server!".to_string()));
        server_stream
            .write_packet(&TestPacket::Message("Hello, client!".to_string()))
            .await
            .unwrap();
    });

    tokio::try_join!(client_task, server_task).unwrap();
}
