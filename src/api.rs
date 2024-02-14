use actix_web::{get, HttpRequest, HttpResponse, Responder};
use actix_web::web::Data;
use uuid::Uuid;
use crate::auth::{Auth, check_auth};
use crate::db_manager::get_thread_by_uuid;

#[get("/thr/{other_url:.*}")]
pub async fn thread(req: HttpRequest, auth_data: Data<Auth>) -> impl Responder {
    let user = check_auth(&req, &auth_data).await;

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