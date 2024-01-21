use std::ops::Deref;
use sqlx::{Executor, FromRow};
use sqlx::mysql::MySqlQueryResult;
use crate::data::User;
use crate::POOL;

pub async fn get_user_by_uuid(user_uuid: String) -> User {
    let result: User = sqlx::query_as("SELECT * FROM users WHERE users.user_uuid = ?")
        .bind(user_uuid)
        .fetch_one(POOL.deref())
        .await
        .unwrap();
    result
}

pub async fn get_user_by_username(username: String) -> User {
    let result: User = sqlx::query_as("SELECT * FROM users WHERE users.username = ?")
        .bind(username)
        .fetch_one(POOL.deref())
        .await
        .unwrap();
    result
}

pub async fn add_user(user: User) -> Result<MySqlQueryResult, sqlx::Error> {
    sqlx::query("INSERT INTO users (user_uuid, username, hashed_pass) VALUES (?, ?, ?)")
        .bind(user.user_uuid)
        .bind(user.username)
        .bind(user.hashed_pass)
        .execute(POOL.deref())
        .await
}