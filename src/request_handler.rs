use std::path::{Path, PathBuf};
use actix_files::NamedFile;
use actix_web::{Responder, HttpRequest, get};
use crate::resource_manager::{get_file};
use crate::ROOT_PATH;

#[get("/home")]
pub async fn home(req: HttpRequest) -> impl Responder {
    let mut home = PathBuf::from(ROOT_PATH.clone());
    home.push("home.html");

    NamedFile::open(home)
        .unwrap()
        .into_response(&req)
}

#[get("/login")]
pub async fn login(req: HttpRequest) -> impl Responder {
    let mut login = PathBuf::from(ROOT_PATH.clone());
    login.push("login.html");

    NamedFile::open(login)
        .unwrap()
        .into_response(&req)
}

#[get("/{other_url:.*}")]
pub async fn default(req: HttpRequest) -> impl Responder {
    let relative_path = req.path().replacen("/", "", 1);
    let relative_path = Path::new(relative_path.as_str());
    let file = get_file(relative_path);

    file.into_response(&req)
}

#[get("/download/{other_url:.*}")]
pub async fn download(req: HttpRequest) -> impl Responder {
    let relative_path = req.path().replacen("/download/", "", 1);
    let relative_path = Path::new(relative_path.as_str());
    let file = get_file(relative_path);

    file.set_content_type(mime::APPLICATION_OCTET_STREAM)
        .into_response(&req)
}