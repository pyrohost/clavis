use clavis::define_packets;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingPongData {
    pub message: String,
}

define_packets!(Ping(PingPongData), Pong(PingPongData), Shutdown);
