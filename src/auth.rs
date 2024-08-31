use std::io::{Read, Write};
use std::str::FromStr;
use actix_web::{HttpRequest, HttpResponse, post, Responder};
use actix_web::cookie::CookieBuilder;
use actix_web::cookie::time::Duration;
use actix_web::web::{Data, Form};
use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit, Nonce};
use chrono::{DateTime, Days, Local};
use hex::ToHex;
use rand::distributions::{Distribution, Standard};
use rand::random;
use serde::Deserialize;
use sha2::Digest;
use sha2::digest::{Update};
use uuid::Uuid;
use crate::data::User;
use crate::db_manager::{add_user, get_user_by_username, get_user_by_uuid};
use crate::{Args};

#[derive(Deserialize, Clone)]
struct Login {
    username: String,
    password: String,
}

#[derive(Clone)]
pub struct Auth {
    salt: [u8; 32],
    server_key: [u8; 32],
    default_nonce: [u8; 12],
}

impl Auth {
    pub fn create(args: &Args) -> Result<Self, String> {
        fn load_secret<T>(secret: &str, args: &Args) -> Result<T, String>
            where Standard: Distribution<T>, T: TryFrom<Vec<u8>> + AsRef<[u8]>
        {
            let mut salt = args.root_path.clone();
            salt.push(format!("{secret} - KEEP SECURE.bin"));

            match salt.try_exists() {
                Ok(false) => {
                    println!("{secret} does not exist, generating...");
                    let random_bytes = random::<T>();
                    if let Err(err) = std::fs::write(&salt, random_bytes) {
                        return Err(format!("Could not write generated {secret}: {err}"));
                    }
                }
                Err(err) => return Err(format!("Couldn't verify if {secret} exists: {err}")),
                _ => {}
            }

            let contents = match std::fs::read(salt) {
                Ok(vec) => vec,
                Err(err) => return Err(format!("Could not read {secret}: {err}")),
            };

            T::try_from(contents).or_else(|e| Err(format!("Invalid {secret} length")))
        }

        let salt = load_secret("salt", args)?;
        let server_key = load_secret("key", args)?;
        let default_nonce = load_secret("nonce", args)?;

        Ok(
            Self {
                salt,
                server_key,
                default_nonce
            }
        )
    }
}

#[post("/auth")]
pub async fn auth(req: HttpRequest, login: Form<Login>, args: Data<Args>, auth_data: Data<Auth>) -> impl Responder {
    finish_auth(req, login.into_inner(), &auth_data).await
}

#[post("/register")]
pub async fn register(req: HttpRequest, login: Form<Login>, args: Data<Args>, auth_data: Data<Auth>) -> impl Responder {
    let login = login.into_inner();
    let Login { username, password } = login.clone();
    let user_uuid = Uuid::new_v4();
    let hashed_pass = create_hashed_pass(user_uuid.as_bytes(), password.as_bytes(), &auth_data);
    let reset_key = random::<[u8; 16]>().to_vec();
    let user = User { uuid: user_uuid, name: username, hashed_pass, reset_key };

    add_user(user).await.expect("Failed to register user, it may already exist");
    finish_auth(req, login, &auth_data).await
}

async fn finish_auth(req: HttpRequest, login: Login, auth_data: &Auth) -> impl Responder {
    let Login { username, password } = login;

    let user = match verify_user_by_password(&username, &password, auth_data).await {
        Some(val) => val,
        None => return HttpResponse::Unauthorized().finish()
    };

    let ip = match req.connection_info().realip_remote_addr() {
        Some(val) => val.to_string(),
        None => return HttpResponse::Unauthorized().finish()
    };

    let token = match create_token(&user, &ip, auth_data) {
        Ok(val) => val,
        Err(_) => return HttpResponse::Unauthorized().finish()
    };

    let mut resp = HttpResponse::Ok().finish();

    match resp.add_cookie(&CookieBuilder::new("auth_token", token)
        .secure(true)
        .http_only(true)
        .max_age(Duration::days(3))
        .finish()) {
        Ok(_) => println!("User {username} authenticated at {}", Local::now()),
        Err(_) => return HttpResponse::Unauthorized().finish()
    };

    resp
}

async fn verify_user_by_password(username: &str, password: &str, auth_data: &Auth) -> Option<User> {
    let user = get_user_by_username(username).await;

    if user.is_err() {
        return None;
    }

    let user = user.unwrap();
    let hashed_pass = create_hashed_pass(user.uuid.as_bytes(), password.as_bytes(), auth_data);

    if user.hashed_pass != hashed_pass {
        return None;
    }

    Some(user)
}

fn create_token(user: &User, ip: &str, auth_data: &Auth) -> Result<String, String> {
    let mut hasher = sha2::Sha256::new();
    let expiry = Local::now().checked_add_days(Days::new(2)).unwrap();

    Update::update(&mut hasher, &auth_data.salt);
    Update::update(&mut hasher, expiry.to_string().as_bytes());
    Update::update(&mut hasher, user.uuid.as_bytes());
    Update::update(&mut hasher, user.hashed_pass.as_bytes());
    Update::update(&mut hasher, user.reset_key.as_slice());
    Update::update(&mut hasher, ip.as_bytes());

    let mut result: String = hasher.finalize().to_vec().encode_hex();
    result = format!("{}|{}|{}", expiry, user.uuid, result);

    encrypt(result, &auth_data.default_nonce, auth_data)
}

pub fn encrypt(data: String, nonce: &[u8; 12], auth_data: &Auth) -> Result<String, String> {
    let cipher = Aes256GcmSiv::new_from_slice(&auth_data.server_key)
        .or_else(|e| Err(format!("Failed to use private server key: {e}")))?;
    let nonce = Nonce::from_slice(nonce);

    let mut buffer: Vec<u8> = vec!();
    buffer.extend_from_slice(data.as_bytes());

    cipher.encrypt_in_place(nonce, b"", &mut buffer).or_else(|e| Err(format!("Failed to encrypt data: {e}")))?;
    Ok(buffer.encode_hex())
}

pub fn decrypt(data: String, auth_data: &Auth) -> Result<String, String> {
    let cipher = Aes256GcmSiv::new_from_slice(&auth_data.server_key)
        .or_else(|e| Err(format!("Failed to use private server key: {e}")))?;
    let nonce = Nonce::from_slice(&auth_data.default_nonce);

    let mut buffer: Vec<u8> = vec!();
    buffer.extend_from_slice(hex::decode(data)
        .or_else(|e| Err(format!("Failed to decode hex: {e}")))?
        .as_slice());

    cipher.decrypt_in_place(nonce, b"", &mut buffer)
        .or_else(|e| Err("Failed to decrypt data".to_string()))?;
    String::from_utf8(buffer.to_vec())
        .or_else(|e| Err(format!("Decrypted data is not valid UTF-8: {e}")))
}

fn create_hashed_pass(user_uuid: &[u8], password: &[u8], auth_data: &Auth) -> String {
    let mut hasher = sha2::Sha256::new();

    Update::update(&mut hasher, &auth_data.salt);
    Update::update(&mut hasher, user_uuid);
    Update::update(&mut hasher, password);

    hasher.finalize().to_vec().encode_hex()
}

pub async fn verify_user_by_token(cookie: &str, ip: &str, auth_data: &Auth) -> Option<User> {
    match decrypt(cookie.to_string(), auth_data) {
        Ok(cookie) => {
            let mut split_cookie = cookie.splitn(3, "|");

            let expiry = match DateTime::<Local>::from_str(split_cookie.nth(0)?) {
                Ok(val) => val,
                Err(_) => return None
            };

            let user_uuid = match Uuid::from_str(split_cookie.nth(0)?) {
                Ok(val) => val,
                Err(_) => return None
            };

            let token = split_cookie.nth(0)?;

            if expiry < Local::now() {
                return None;
            }

            let user = match get_user_by_uuid(user_uuid).await {
                Ok(val) => val,
                Err(_) => return None
            };

            let mut hasher = sha2::Sha256::new();

            Update::update(&mut hasher, &auth_data.salt);
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
        },
        Err(_) => None
    }
}

pub async fn check_auth(req: &HttpRequest, auth_data: &Auth) -> Option<User> {
    let auth_token = req.cookie("auth_token")?;
    let ip = req.connection_info().realip_remote_addr()?.to_string();

    verify_user_by_token(auth_token.value(), &ip, auth_data).await
}