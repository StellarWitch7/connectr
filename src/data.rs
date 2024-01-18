use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub uuid: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Channel {
    pub uuid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub contents: String,
    pub sender_uuid: String,
    pub unix_timestamp: u64,
}
