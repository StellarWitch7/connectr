use std::path::PathBuf;
use actix_files::NamedFile;
use actix_web::{get, HttpRequest, post, Responder};
use actix_web::cookie::CookieBuilder;
use actix_web::cookie::time::Duration;
use actix_web::web::{Form};
use serde::Deserialize;
use crate::ROOT_PATH;

#[post("/auth")]
pub async fn auth(req: HttpRequest, Form(auth): Form<Login>) -> impl Responder {
    let Login { username, password, stay_logged_in_for_days } = auth;
    let user_uuid = verify_user(username, password);

    if user_uuid.is_none() {
        panic!("No matching UUID")
    }

    let user_uuid = user_uuid.expect("Internal failure, could not unwrap user UUID");
    let token = register_token(user_uuid.clone(), create_token(user_uuid));

    let mut redirect = PathBuf::from(ROOT_PATH.clone());
    redirect.push("redirect.html");

    let mut resp = NamedFile::open(redirect)
        .unwrap()
        .into_response(&req);
    resp.add_cookie(&CookieBuilder::new("auth_token", token)
        .secure(true)
        .http_only(true)
        .max_age(Duration::days(auth.stay_logged_in_for_days as i64))
        .finish());
    resp
}

// returns a result containing the UUID of the user if the password is valid
fn verify_user(username: String, password: String) -> Option<String> {
    Some(String::from("aurora-uuid")) // temporary for testing
}

// returns the token passed to it or panics if it fails
fn register_token(user_uuid: String, token: String) -> String {
    token
}

// creates an auth token for the user from a hash of data or panics if it fails
fn create_token(user_uuid: String) -> String {
    String::from("aurora-token")
}

#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
    stay_logged_in_for_days: u32
}