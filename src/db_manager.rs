use std::ops::Deref;
use sqlx::{Error, Executor, FromRow, MySql};
use sqlx::mysql::MySqlQueryResult;
use uuid::Uuid;
use crate::data::User;
use crate::POOL;

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
    sqlx::query("INSERT INTO users (user_uuid, username, hashed_pass) VALUES (?, ?, ?)")
        .bind(user.user_uuid)
        .bind(user.username)
        .bind(user.hashed_pass)
        .execute(POOL.deref())
        .await
}