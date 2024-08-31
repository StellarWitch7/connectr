use crate::auth::{check_auth, Auth};
use crate::data::Thread;
use crate::db_manager::get_messages_of_thread;
use crate::Args;
use actix_web::web::Data;
use actix_web::{get, web, Error, HttpRequest, HttpResponse, Responder};
use actix_ws::Session;
use serde::Serializer;
use std::sync::Mutex;
use uuid::Uuid;

pub struct Heartbeat {
    connections: Mutex<Vec<Session>>
}

impl Heartbeat {
    pub fn empty() -> Self {
        Self {
            connections: Mutex::new(Vec::new())
        }
    }

    pub async fn beat(self, thr: Thread) {
        let mut msg = Vec::new();
        msg.push(0u8);
        msg.append(&mut thr.uuid.as_bytes().as_slice().to_vec());

        for session in self.connections.lock().unwrap().iter_mut() {
            let _ = session.binary(msg.clone()).await;
        }
    }
}

pub async fn connect(req: HttpRequest, stream: web::Payload, heartbeat: Data<Heartbeat>) -> Result<HttpResponse, Error> {
    let (res, session, stream) = actix_ws::handle(&req, stream)?;
    heartbeat.connections.lock().unwrap().push(session);
    Ok(res)
}

#[get("/thr/{other_url:.*}")]
pub async fn thread(req: HttpRequest, args: Data<Args>, auth_data: Data<Auth>) -> impl Responder {
    let user = match check_auth(&req, &auth_data, &args).await {
        Some(val) => val,
        None => return HttpResponse::Unauthorized().finish()
    };

    let uuid = match Uuid::try_parse(&req.path().replacen("/api/thr/", "", 1)) {
        Ok(val) => val,
        Err(_) => return HttpResponse::NotFound().finish()
    };

    let messages = match get_messages_of_thread(uuid, 20, &args).await {
        Ok(val) => val,
        Err(_) => return HttpResponse::NotFound().finish()
    };

    HttpResponse::Ok().json(messages)
}

#[get("/usr/{other_url:.*}")]
pub async fn usr(req: HttpRequest, args: Data<Args>, auth_data: Data<Auth>) -> impl Responder {
    let user = match check_auth(&req, &auth_data, &args).await {
        Some(val) => val,
        None => return HttpResponse::Unauthorized().finish()
    };

    HttpResponse::NotImplemented().finish() //TODO
}