use actix_web::{get, HttpRequest, HttpResponse, Responder};
use serde::Serialize;
use uuid::Uuid;
use crate::auth::check_auth;
use crate::db_manager::{get_messages_of_thread, get_thread_by_uuid};

#[get("/thr/{other_url:.*}")]
pub async fn thread(req: HttpRequest) -> impl Responder {
    let user = check_auth(req).await;

    if user.is_none() {
        return HttpResponse::Unauthorized().finish();
    }

    let user = user.unwrap();
    let uuid = req.path().replacen("/thread", "", 1);
    let uuid = Uuid::try_parse(&uuid);

    if uuid.is_err() {
        return HttpResponse::NotFound().finish();
    }

    let uuid = uuid.unwrap();
    let thread = get_thread_by_uuid(uuid).await;

    if thread.is_err() {
        return HttpResponse::NotFound().finish();
    }

    let thread = thread.unwrap();
    HttpResponse::NotImplemented().finish()
}

// #[get("/usr/{other_url:.*}")]
// pub async fn usr(req: HttpRequest) -> impl Responder {
//     let user = check_auth(req).await;
//
//     if user.is_none() {
//         return HttpResponse::Unauthorized().finish();
//     }
//
//     let user = user.unwrap();
// }