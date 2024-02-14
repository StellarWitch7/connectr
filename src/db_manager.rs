use std::sync::OnceLock;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Error, Executor, MySql, Pool};
use sqlx::mysql::MySqlQueryResult;
use uuid::Uuid;
use crate::data::{Message, Thread, User};

const DB_USER: &str = "connectr";
const DB_PASS: &str = "werconnectr";
const DB_ADDR: &str = "localhost";
const DB_NAME: &str = "connectr";

fn get_connection_pool() -> &'static Pool<MySql> {
    static POOL: OnceLock<Pool<MySql>> = OnceLock::new();
    POOL.get_or_init(|| {
        println!("Connecting to MySQL database...");
        MySqlPoolOptions::new()
            .max_connections(32)
            .connect_lazy(&format!("mysql://{}:{}@{}/{}", DB_USER, DB_PASS, DB_ADDR, DB_NAME))
            .expect("Failed to connect to MySQL database")
    })
}

pub async fn get_user_by_uuid(user_uuid: Uuid) -> Result<User, Error> {
    let result = sqlx::query_as::<MySql, User>("SELECT * FROM users \
    WHERE users.user_uuid = ? \
    LIMIT 1")
        .bind(user_uuid)
        .fetch_one(get_connection_pool())
        .await;
    result
}

pub async fn get_thread_by_uuid(thread_uuid: Uuid) -> Result<Thread, Error> {
    let result = sqlx::query_as::<MySql, Thread>("SELECT * FROM threads \
    WHERE threads.thread_uuid = ? \
    LIMIT 1")
        .bind(thread_uuid)
        .fetch_one(get_connection_pool())
        .await;
    result
}

pub async fn get_user_by_username(username: &str) -> Result<User, Error> {
    let result = sqlx::query_as::<MySql, User>("SELECT * FROM users \
    WHERE users.username = ? \
    LIMIT 1")
        .bind(username)
        .fetch_one(get_connection_pool())
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
        .execute(get_connection_pool())
        .await
}

pub async fn get_messages_of_thread(thread_uuid: Uuid, amount: u64) -> Result<Vec<Message>, Error> {
    let result = sqlx::query_as::<MySql, Message>("SELECT * FROM messages \
    WHERE messages.owner_thread_uuid = ? \
    ORDER BY messages.sent_time DESC \
    LIMIT ?")
        .bind(thread_uuid)
        .bind(amount)
        .fetch_all(get_connection_pool())
        .await;
    result
}

