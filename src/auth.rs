use std::path::PathBuf;
use actix_files::NamedFile;
use actix_web::{HttpRequest, HttpResponse, post, Responder};
use actix_web::cookie::CookieBuilder;
use actix_web::cookie::time::Duration;
use actix_web::web::{Form};
use hex::ToHex;
use serde::Deserialize;
use sha2::Digest;
use sha2::digest::{Update};
use uuid::Uuid;
use crate::data::User;
use crate::db_manager::{add_user, get_user_by_username};
use crate::{ROOT_PATH};

static CORE_KEY: &str = "core-key9305732957";

#[post("/auth")]
pub async fn auth(req: HttpRequest, login: Form<Login>) -> impl Responder {
    finish_auth(req, login.into_inner()).await
}

#[post("/register")]
pub async fn register(req: HttpRequest, login: Form<Login>) -> impl Responder {
    let login = login.into_inner();
    let Login { username, password, stay_logged_in_for_days } = login.clone();
    let user_uuid = Uuid::new_v4();
    let hashed_pass = create_hashed_pass(user_uuid.as_bytes(), password.as_bytes());
    let user = User { user_uuid, username, hashed_pass };

    add_user(user).await.expect("Failed to register user, it may already exist");

    finish_auth(req, login).await
}

async fn finish_auth(req: HttpRequest, login: Login) -> impl Responder {
    let Login { username, password, stay_logged_in_for_days } = login;
    let user = verify_user(username, password).await;

    if user.is_none() {
        return HttpResponse::Unauthorized().finish();
    }

    let user = user.expect("Internal failure, could not unwrap user UUID");
    let token = create_token(&user);

    let mut redirect = PathBuf::from(ROOT_PATH.clone());
    redirect.push("redirect.html");

    let mut resp = NamedFile::open(redirect)
        .unwrap()
        .into_response(&req);
    resp.add_cookie(&CookieBuilder::new("auth_token", token)
        .secure(true)
        .http_only(true)
        .max_age(Duration::days(stay_logged_in_for_days as i64))
        .finish())
        .expect("Failed to add cookie to response");
    resp
}

async fn verify_user(username: String, password: String) -> Option<User> {
    let user = get_user_by_username(username).await;
    let hashed_pass = create_hashed_pass(user.user_uuid.as_bytes(), password.as_bytes());

    if user.hashed_pass == hashed_pass {
        return Some(user);
    }

    None
}

fn create_token(user: &User) -> String {
    let mut hasher = sha2::Sha256::new();

    Update::update(&mut hasher, CORE_KEY.as_bytes());
    Update::update(&mut hasher, user.user_uuid.as_bytes());
    Update::update(&mut hasher, user.hashed_pass.as_bytes());

    let result: String = hasher.finalize().to_vec().encode_hex_upper();

    format!("{}|{}|->{}", chrono::Local::now(), user.user_uuid, result)
}

fn create_hashed_pass(user_uuid: &[u8], password: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();

    Update::update(&mut hasher, CORE_KEY.as_bytes());
    Update::update(&mut hasher, user_uuid);
    Update::update(&mut hasher, password);

    hasher.finalize().to_vec().encode_hex_upper()
}

#[derive(Deserialize, Clone)]
struct Login {
    username: String,
    password: String,
    stay_logged_in_for_days: u8
}