use std::fs::File;
use std::io::{Read, Write};
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use actix_files::NamedFile;
use actix_web::{HttpRequest, HttpResponse, post, Responder};
use actix_web::cookie::CookieBuilder;
use actix_web::cookie::time::Duration;
use actix_web::web::{Form};
use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit, Nonce};
use chrono::{DateTime, Days, Local};
use hex::ToHex;
use once_cell::sync::Lazy;
use rand::random;
use serde::Deserialize;
use sha2::Digest;
use sha2::digest::{Update};
use uuid::Uuid;
use crate::data::User;
use crate::db_manager::{add_user, get_user_by_username, get_user_by_uuid};
use crate::{ROOT_PATH};

static SALT: Lazy<Vec<u8>> = Lazy::new(|| {
    let mut salt = PathBuf::from(ROOT_PATH.clone());
    salt.push("salt - KEEP SECURE.bin");

    if !salt.try_exists().expect("Couldn't verify if salt exists") {
        println!("Salt does not exist, generating...");
        let random_bytes = random::<[u8; 32]>();
        let mut file = File::create(salt.clone()).expect("Could not open salt");
        file.write_all(random_bytes.as_slice()).expect("Could not generate salt");
    }

    let mut file = File::open(salt).expect("Could not open salt");
    let mut contents: Vec<u8> = vec!();
    file.read_to_end(&mut contents).expect("Could not read salt");
    contents
});

static SERVER_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut salt = PathBuf::from(ROOT_PATH.clone());
    salt.push("key - KEEP SECURE.bin");

    if !salt.try_exists().expect("Couldn't verify if key exists") {
        println!("Key does not exist, generating...");
        let random_bytes = random::<[u8; 32]>();
        let mut file = File::create(salt.clone()).expect("Could not open key");
        file.write_all(random_bytes.as_slice()).expect("Could not generate key");
    }

    let mut file = File::open(salt).expect("Could not open key");
    let mut contents: Vec<u8> = vec!();
    file.read_to_end(&mut contents).expect("Could not read key");

    let result = <[u8; 32]>::try_from(contents.as_slice()).expect("Key is incorrect length");
    result
});

static DEFAULT_NONCE: Lazy<[u8; 12]> = Lazy::new(|| {
    let mut salt = PathBuf::from(ROOT_PATH.clone());
    salt.push("nonce - KEEP SECURE.bin");

    if !salt.try_exists().expect("Couldn't verify if nonce exists") {
        println!("Nonce does not exist, generating...");
        let random_bytes = random::<[u8; 12]>();
        let mut file = File::create(salt.clone()).expect("Could not open nonce");
        file.write_all(random_bytes.as_slice()).expect("Could not generate nonce");
    }

    let mut file = File::open(salt).expect("Could not open nonce");
    let mut contents: Vec<u8> = vec!();
    file.read_to_end(&mut contents).expect("Could not read nonce");

    let result = <[u8; 12]>::try_from(contents.as_slice()).expect("Nonce is incorrect length");
    result
});

#[post("/auth")]
pub async fn auth(req: HttpRequest, login: Form<Login>) -> impl Responder {
    finish_auth(req, login.into_inner()).await
}

#[post("/register")]
pub async fn register(req: HttpRequest, login: Form<Login>) -> impl Responder {
    let login = login.into_inner();
    let Login { username, password } = login.clone();
    let user_uuid = Uuid::new_v4();
    let hashed_pass = create_hashed_pass(user_uuid.as_bytes(), password.as_bytes());
    let reset_key = random::<[u8; 16]>().to_vec();
    let user = User { user_uuid, username, hashed_pass, reset_key };

    add_user(user).await.expect("Failed to register user, it may already exist");

    finish_auth(req, login).await
}

async fn finish_auth(req: HttpRequest, login: Login) -> impl Responder {
    let Login { username, password } = login;
    let user = verify_user_by_password(&username, &password).await;

    if user.is_none() {
        return HttpResponse::Unauthorized().finish();
    }

    let user = user.expect("Internal failure, could not unwrap user UUID");
    let token = create_token(&user, req.connection_info()
        .realip_remote_addr()
        .expect("Could not get client IP"));

    let mut redirect = PathBuf::from(ROOT_PATH.clone());
    redirect.push("redirect.html");

    let mut resp = NamedFile::open(redirect)
        .unwrap()
        .into_response(&req);
    resp.add_cookie(&CookieBuilder::new("auth_token", token)
        .secure(true)
        .http_only(true)
        .max_age(Duration::days(3))
        .finish())
        .expect("Failed to add cookie to response");
    resp
}

async fn verify_user_by_password(username: &str, password: &str) -> Option<User> {
    let user = get_user_by_username(username).await;

    if user.is_err() {
        return None;
    }

    let user = user.unwrap();
    let hashed_pass = create_hashed_pass(user.user_uuid.as_bytes(), password.as_bytes());

    if user.hashed_pass != hashed_pass {
        return None;
    }

    Some(user)
}

fn create_token(user: &User, ip: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    let expiry = chrono::Local::now().checked_add_days(Days::new(2)).unwrap();

    Update::update(&mut hasher, SALT.as_slice());
    Update::update(&mut hasher, expiry.to_string().as_bytes());
    Update::update(&mut hasher, user.user_uuid.as_bytes());
    Update::update(&mut hasher, user.hashed_pass.as_bytes());
    Update::update(&mut hasher, user.reset_key.as_slice());
    Update::update(&mut hasher, ip.as_bytes());

    let mut result: String = hasher.finalize().to_vec().encode_hex();
    result = format!("{}|{}|{}", expiry, user.user_uuid, result);

    encrypt(result, DEFAULT_NONCE.deref())
}

pub fn encrypt(data: String, nonce: &[u8; 12]) -> String {
    let cipher = Aes256GcmSiv::new_from_slice(SERVER_KEY.as_ref()).unwrap();
    let nonce = Nonce::from_slice(nonce);

    let mut buffer: Vec<u8> = vec!();
    buffer.extend_from_slice(data.as_bytes());

    cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("Failed to encrypt data");
    buffer.encode_hex()
}

pub fn decrypt(data: String, nonce: &[u8; 12]) -> String {
    let cipher = Aes256GcmSiv::new_from_slice(SERVER_KEY.as_ref()).unwrap();
    let nonce = Nonce::from_slice(nonce);

    let mut buffer: Vec<u8> = vec!();
    buffer.extend_from_slice(hex::decode(data)
        .expect("Failed to decode hex")
        .as_slice());

    cipher.decrypt_in_place(nonce, b"", &mut buffer).expect("Failed to decrypt data");
    String::from_utf8(buffer.to_vec()).expect("Decrypted data is not valid utf-8")
}

fn create_hashed_pass(user_uuid: &[u8], password: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();

    Update::update(&mut hasher, SALT.iter().as_ref());
    Update::update(&mut hasher, user_uuid);
    Update::update(&mut hasher, password);

    hasher.finalize().to_vec().encode_hex()
}

pub async fn verify_user_by_token(cookie: &str, ip: &str) -> Option<User> {
    let cookie = decrypt(cookie.to_string(), DEFAULT_NONCE.deref());
    let mut split_cookie = cookie.splitn(3, "|");

    let expiry = DateTime::<Local>::from_str(split_cookie.nth(0)
        .expect("Could not read expiry date"))
        .expect("Could not parse expiry date");
    let user_uuid = Uuid::from_str(split_cookie.nth(0)
        .expect("Could not read user UUID"))
        .expect("Could not parse user UUID");
    let token = split_cookie.nth(0)
        .expect("Could not read token");

    if expiry < Local::now() {
        return None;
    }

    let user = get_user_by_uuid(user_uuid).await;

    if user.is_err() {
        return None;
    }

    let user = user.unwrap();

    let mut hasher = sha2::Sha256::new();

    Update::update(&mut hasher, SALT.as_slice());
    Update::update(&mut hasher, expiry.to_string().as_bytes());
    Update::update(&mut hasher, user_uuid.as_bytes());
    Update::update(&mut hasher, user.hashed_pass.as_bytes());
    Update::update(&mut hasher, user.reset_key.as_slice());
    Update::update(&mut hasher, ip.as_bytes());

    let expected: String = hasher.finalize().to_vec().encode_hex();

    if token != expected.as_str() {
        return None;
    }

    Some(user)
}

pub async fn check_auth(req: HttpRequest) -> Option<User> {
    let auth_token = req.cookie("auth_token")
        .expect("Client has no auth token");
    verify_user_by_token(auth_token.value(), req.connection_info()
        .realip_remote_addr()
        .expect("Could not get client IP"))
        .await
}

#[derive(Deserialize, Clone)]
struct Login {
    username: String,
    password: String,
}
