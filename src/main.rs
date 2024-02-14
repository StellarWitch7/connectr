mod data;
mod request_handler;
mod resource_manager;
mod auth;
mod db_manager;
mod api;

use std::collections::HashMap;
use std::io::{Result};
use std::iter::Iterator;
use std::path::PathBuf;
use std::string::ToString;
use actix_web::{App, HttpServer, web};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use crate::auth::Auth;

#[actix_web::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let auth = Auth::create(&args);
    let (addr, port) = (args.addr.clone(), args.port);
    println!("Starting server on port {} with address {}", args.port, args.addr);

    let mut ssl_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    ssl_builder.set_private_key_file(&args.key_path, SslFiletype::PEM).unwrap();
    ssl_builder.set_certificate_chain_file(&args.cert_path).unwrap();

    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(args.clone()))
            .app_data(web::Data::new(auth.clone()))
            .service(web::scope("/api")
                // .service(api::usr)
                .service(api::thread))
            .service(auth::auth)
            .service(auth::register)
            .service(request_handler::download)
            .service(request_handler::default)
    })
    .bind_openssl(format!("{}:{}", addr, port), ssl_builder)
    .expect("Failed to bind to address");

    println!("Server configured, running...");
    server.run().await
}

#[derive(Clone)]
struct Args {
    port: u16,
    addr: String,
    key_path: PathBuf,
    root_path: PathBuf,
    cert_path: PathBuf,
}

impl Args {
    pub fn parse() -> Self {
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

        Self {
            port: match dict.remove("port") {
                None => 80,
                Some(port) => port.parse::<u16>().unwrap_or(80),
            },
            addr: dict.remove("addr").unwrap_or_else(|| "localhost".into()),
            key_path: PathBuf::from(shellexpand::tilde(dict.get("key").unwrap()).to_string()),
            root_path: PathBuf::from(shellexpand::tilde(dict.get("root").unwrap()).to_string()),
            cert_path: PathBuf::from(shellexpand::tilde(dict.get("cert").unwrap()).to_string()),
        }
    }
}
