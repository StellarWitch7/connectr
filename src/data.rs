use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct User {
    pub user_uuid: Uuid,
    pub username: String,
    pub hashed_pass: String,
    pub reset_key: Vec<u8>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Thread {
    pub thread_uuid: Uuid,
    pub thread_name: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Message {
    pub message_uuid: Uuid,
    pub owner_thread_uuid: Uuid,
    pub sender_uuid: Uuid,
    pub sent_time: u64,
    pub message_contents: String,
}
