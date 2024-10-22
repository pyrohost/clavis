use std::fmt::Debug;

use crate::{define_packets, error::Result};

/// Trait that defines serialization and deserialization for packets.
pub trait PacketTrait: Send + Sync + Sized + Debug {
    /// Serializes the packet into a byte vector.
    fn serialize(&self) -> Result<Vec<u8>>;
    /// Deserializes the packet from a byte slice.
    fn deserialize(data: &[u8]) -> Result<Self>;
}

define_packets! {
    pub(crate) enum InternalPacket {
        KeyExchange { public_key: [u8; 32], initial_sequence: u64 },
    }
}
