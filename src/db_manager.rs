use std::ops::Deref;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Error, Executor, FromRow, MySql, Pool};
use sqlx::mysql::MySqlQueryResult;
use uuid::Uuid;
use once_cell::sync::Lazy;
use crate::data::User;

static POOL: Lazy<Pool<MySql>> = Lazy::new(|| {
    println!("Connecting to MySQL database...");
    MySqlPoolOptions::new()
        .max_connections(32)
        .connect_lazy("mysql://connectr:werconnectr@localhost/connectr")
        .expect("Failed to connect to MySQL database")
});

pub async fn get_user_by_uuid(user_uuid: Uuid) -> Result<User, Error> {
    let result = sqlx::query_as::<MySql, User>("SELECT * FROM users WHERE users.user_uuid = ?")
        .bind(user_uuid)
        .fetch_one(POOL.deref())
        .await;
    result
}

pub async fn get_user_by_username(username: &str) -> Result<User, Error> {
    let result = sqlx::query_as::<MySql, User>("SELECT * FROM users WHERE users.username = ?")
        .bind(username)
        .fetch_one(POOL.deref())
        .await;
    result
}

pub async fn add_user(user: User) -> Result<MySqlQueryResult, Error> {
    sqlx::query("INSERT INTO users (user_uuid, username, hashed_pass, reset_key) VALUES (?, ?, ?, ?)")
        .bind(user.user_uuid)
        .bind(user.username)
        .bind(user.hashed_pass)
        .bind(user.reset_key)
        .execute(POOL.deref())
        .await
}
