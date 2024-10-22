use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

use crate::{packet::InternalPacket, PacketError, PacketTrait, MAX_DATA_LENGTH};

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub(crate) async fn read_packet_unencrypted<S>(
    stream: &mut S,
    psk: Option<&[u8]>,
) -> crate::Result<InternalPacket>
where
    S: AsyncRead + Unpin + Send,
{
    trace!("Reading unencrypted packet");

    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes).await?;
    let data_length = u32::from_le_bytes(length_bytes);

    trace!("Unencrypted packet data length: {}", data_length);

    if data_length > MAX_DATA_LENGTH {
        return Err(PacketError::DataTooLarge);
    }

    let mut data = vec![0u8; data_length as usize];
    stream.read_exact(&mut data).await?;

    let mut hmac_bytes = [0u8; 32];
    stream.read_exact(&mut hmac_bytes).await?;

    if let Some(psk) = psk {
        let mut mac = <HmacSha256>::new_from_slice(psk).map_err(|_| PacketError::KeyDerivation)?;
        mac.update(&length_bytes);
        mac.update(&data);
        mac.verify_slice(&hmac_bytes)
            .map_err(|_| PacketError::AuthenticationFailed)?;
    }

    trace!("Read unencrypted packet data");
    InternalPacket::deserialize(&data)
}

pub(crate) async fn write_packet_unencrypted<S>(
    stream: &mut S,
    packet: &InternalPacket,
    psk: Option<&[u8]>,
) -> crate::Result<()>
where
    S: AsyncWrite + Unpin + Send,
{
    trace!("Writing unencrypted packet");

    let data = packet.serialize()?;
    let data_length = data.len() as u32;
    if data_length > MAX_DATA_LENGTH {
        return Err(PacketError::DataTooLarge);
    }

    let length_bytes = data_length.to_le_bytes();

    let mut hmac_data = Vec::with_capacity(4 + data.len());
    hmac_data.extend_from_slice(&length_bytes);
    hmac_data.extend_from_slice(&data);

    let hmac = if let Some(psk) = psk {
        let mut mac = <HmacSha256>::new_from_slice(psk).map_err(|_| PacketError::KeyDerivation)?;
        mac.update(&hmac_data);
        mac.finalize().into_bytes()
    } else {
        [0u8; 32].into()
    };

    let mut buffer = Vec::with_capacity(hmac_data.len() + 32);
    buffer.extend_from_slice(&hmac_data);
    buffer.extend_from_slice(&hmac);

    stream.write_all(&buffer).await?;
    stream.flush().await?;

    trace!("Wrote unencrypted packet to stream");
    Ok(())
}
