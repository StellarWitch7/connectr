use hex::{FromHex};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct User {
    pub user_uuid: Uuid,
    pub username: String,
    pub hashed_pass: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Thread {
    pub thread_uuid: Uuid,
    pub threadname: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Message {
    pub message_uuid: Uuid,
    pub sender_uuid: Uuid,
    pub unix_timestamp: u64,
    pub contents: String,
}
