use std::path::Path;
use actix_web::{Responder, HttpRequest, get, HttpResponse, web::Data};
use crate::{Args, auth::{ Auth, check_auth }};
use crate::resource_manager::get_file;

#[get("/{other_url:.*}")]
pub async fn default(req: HttpRequest, args: Data<Args>, auth_data: Data<Auth>) -> impl Responder {
    match check_auth(&req, &auth_data, &args).await {
        Some(user) => get_file(req.path(), "/", &args.root_path)
            .into_response(&req),
        None => HttpResponse::Unauthorized().finish()
    }
}

#[get("/download/{other_url:.*}")]
pub async fn download(req: HttpRequest, args: Data<Args>, auth_data: Data<Auth>) -> impl Responder {
    match check_auth(&req, &auth_data, &args).await {
        Some(user) => get_file(req.path(), "/download/", &args.root_path)
            .set_content_type(mime::APPLICATION_OCTET_STREAM)
            .into_response(&req),
        None => HttpResponse::Unauthorized().finish()
    }
}
