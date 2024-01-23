use std::ops::Deref;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Error, Executor, FromRow, MySql, Pool};
use sqlx::mysql::MySqlQueryResult;
use uuid::Uuid;
use once_cell::sync::Lazy;
use crate::data::{Message, Thread, User};

static DB_USER: Lazy<String> = Lazy::new(|| {
    "connectr".to_string()
});
static DB_PASS: Lazy<String> = Lazy::new(|| {
    "werconnectr".to_string()
});
static DB_ADDR: Lazy<String> = Lazy::new(|| {
    "localhost".to_string()
});
static DB_NAME: Lazy<String> = Lazy::new(|| {
    "connectr".to_string()
});
static POOL: Lazy<Pool<MySql>> = Lazy::new(|| {
    println!("Connecting to MySQL database...");
    MySqlPoolOptions::new()
        .max_connections(32)
        .connect_lazy(&format!("mysql://{}:{}@{}/{}", DB_USER, DB_PASS, DB_ADDR, DB_NAME))
        .expect("Failed to connect to MySQL database")
});

pub async fn get_user_by_uuid(user_uuid: Uuid) -> Result<User, Error> {
    let result = sqlx::query_as::<MySql, User>("SELECT * FROM users \
    WHERE users.user_uuid = ? \
    LIMIT 1")
        .bind(user_uuid)
        .fetch_one(POOL.deref())
        .await;
    result
}

pub async fn get_thread_by_uuid(thread_uuid: Uuid) -> Result<Thread, Error> {
    let result = sqlx::query_as::<MySql, Thread>("SELECT * FROM threads \
    WHERE threads.thread_uuid = ? \
    LIMIT 1")
        .bind(thread_uuid)
        .fetch_one(POOL.deref())
        .await;
    result
}

pub async fn get_user_by_username(username: &str) -> Result<User, Error> {
    let result = sqlx::query_as::<MySql, User>("SELECT * FROM users \
    WHERE users.username = ? \
    LIMIT 1")
        .bind(username)
        .fetch_one(POOL.deref())
        .await;
    result
}

pub async fn add_user(user: User) -> Result<MySqlQueryResult, Error> {
    sqlx::query("INSERT INTO users (user_uuid, username, hashed_pass, reset_key) \
    VALUES (?, ?, ?, ?)")
        .bind(user.user_uuid)
        .bind(user.username)
        .bind(user.hashed_pass)
        .bind(user.reset_key)
        .execute(POOL.deref())
        .await
}

pub async fn get_messages_of_thread(thread_uuid: Uuid, amount: u64) -> Result<Vec<Message>, Error> {
    let result = sqlx::query_as::<MySql, Message>("SELECT * FROM messages \
    WHERE messages.owner_thread_uuid = ? \
    ORDER BY messages.sent_time DESC \
    LIMIT ?")
        .bind(thread_uuid)
        .bind(amount)
        .fetch_all(POOL.deref())
        .await;
    result
}

