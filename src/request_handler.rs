use std::path::Path;
use actix_web::{Responder, HttpRequest, get, HttpResponse, web::Data};
use crate::{Args, auth::{ Auth, check_auth }};
use crate::resource_manager::{get_file};

#[get("/{other_url:.*}")]
pub async fn default(req: HttpRequest, args: Data<Args>, auth_data: Data<Auth>) -> impl Responder {
    let user = check_auth(&req, &auth_data, &args).await;

    if user.is_none() {
        return HttpResponse::Unauthorized().finish();
    }

    let user = user.unwrap();
    let relative_path = req.path().replacen("/", "", 1);
    let relative_path = Path::new(relative_path.as_str());
    let file = get_file(relative_path, &args.root_path);

    file.into_response(&req)
}

#[get("/download/{other_url:.*}")]
pub async fn download(req: HttpRequest, args: Data<Args>, auth_data: Data<Auth>) -> impl Responder {
    let user = check_auth(&req, &auth_data, &args).await;

    if user.is_none() {
        return HttpResponse::Unauthorized().finish();
    }

    let user = user.unwrap();
    let relative_path = req.path().replacen("/download/", "", 1);
    let relative_path = Path::new(relative_path.as_str());
    let file = get_file(relative_path, &args.root_path);

    file.set_content_type(mime::APPLICATION_OCTET_STREAM)
        .into_response(&req)
}