mod data;
mod request_handler;
mod resource_manager;
mod auth;
mod db_manager;
mod api;

use std::clone::Clone;
use std::collections::HashMap;
use std::io::{Result};
use std::iter::Iterator;
use std::ops::Deref;
use std::string::ToString;
use actix_web::{App, HttpServer, Responder, web};
use once_cell::sync::Lazy;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

static ARGS: Lazy<HashMap<String, String>> = Lazy::new(|| parse_arguments());
static ADDRESS: Lazy<String> = Lazy::new(||
    ARGS.get("addr")
        .map(|p| p.as_str())
        .unwrap_or("localhost")
        .to_string());
static PORT: Lazy<u16> = Lazy::new(||
    ARGS.get("port")
        .map(|p| p.as_str())
        .unwrap_or("80")
        .parse::<u16>()
        .unwrap_or(80));
static ROOT_PATH: Lazy<String> = Lazy::new(|| shellexpand::tilde(ARGS.get("root")
    .unwrap())
    .to_string());
static KEY_PATH: Lazy<String> = Lazy::new(|| shellexpand::tilde(ARGS.get("key")
    .unwrap())
    .to_string());
static CERT_PATH: Lazy<String> = Lazy::new(|| shellexpand::tilde(ARGS.get("cert")
    .unwrap())
    .to_string());

#[actix_web::main]
async fn main() -> Result<()> {
    println!("Starting server on port {} with address {}", PORT.to_string(), ADDRESS);

    let mut ssl_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    ssl_builder.set_private_key_file(KEY_PATH.to_string(), SslFiletype::PEM).unwrap();
    ssl_builder.set_certificate_chain_file(CERT_PATH.to_string()).unwrap();

    let mut server = HttpServer::new(||
        App::new()
            .service(web::scope("/api")
                // .service(api::usr)
                .service(api::thread))
            .service(auth::auth)
            .service(auth::register)
            .service(request_handler::download)
            .service(request_handler::default))
        .bind_openssl(format!("{}:{}", ADDRESS, PORT.to_string()), ssl_builder)
        .expect("Failed to bind to address");

    println!("Server configured, running...");
    server.run().await
}

fn parse_arguments() -> HashMap<String, String> {
    let mut args = std::env::args().skip(1);
    let mut dict = HashMap::new();
    while let Some(arg_name) = args.next() {
        if !arg_name.starts_with("--") {
            panic!("Bad argument: {}", arg_name);
        }

        let arg_value = match args.next() {
            Some(val) => val,
            None => panic!("No value provided for argument: {}", arg_name),
        };

        dict.insert(arg_name[2..].to_string(), arg_value);
    }

    dict
}
