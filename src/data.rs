use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct User {
    pub uuid: Uuid,
    pub name: String,
    pub hashed_pass: String,
    pub reset_key: Vec<u8>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Thread {
    pub uuid: Uuid,
    pub name: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Message {
    pub uuid: Uuid,
    pub thread_uuid: Uuid,
    pub sender_uuid: Uuid,
    pub sent_time: u64,
    pub contents: String,
}
