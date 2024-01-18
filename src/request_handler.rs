use std::path::Path;
use actix_web::{Responder, HttpRequest, get};
use crate::resource_manager::{get_file};

#[get("/{other_url:.*}")]
pub async fn default(req: HttpRequest) -> impl Responder {
    let relative_path = req.path().replacen("/", "", 1);
    let relative_path = Path::new(relative_path.as_str());
    let file = get_file(relative_path);

    file.disable_content_disposition()
        .into_response(&req)
}

#[get("/download/{other_url:.*}")]
pub async fn download(req: HttpRequest) -> impl Responder {
    let relative_path = req.path().replacen("/download/", "", 1);
    let relative_path = Path::new(relative_path.as_str());
    let file = get_file(relative_path);

    file.set_content_type(mime::APPLICATION_OCTET_STREAM)
        .into_response(&req)
}