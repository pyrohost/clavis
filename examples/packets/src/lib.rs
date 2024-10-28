use clavis::protocol;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingPongData {
    pub message: String,
}

protocol! {
    pub enum Packet {
        Ping(PingPongData),
        Pong(PingPongData),
        Shutdown,
    }
}
