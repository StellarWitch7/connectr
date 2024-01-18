use actix_web::{get, HttpRequest, HttpResponse, Responder};

#[get("/usr/{other_url:.*}")]
pub async fn user(req: HttpRequest) -> impl Responder {
    HttpResponse::NotImplemented()
}

#[get("/channel/{other_url:.*}")]
pub async fn thread(req: HttpRequest) -> impl Responder {
    HttpResponse::NotImplemented()
}