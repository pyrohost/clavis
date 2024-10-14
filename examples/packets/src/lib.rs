use clavis::define_user_packets;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PingPongData {
    pub message: String,
}

define_user_packets!(
    Ping = 1 => PingPongData,
    Pong = 2 => PingPongData
);
