use std::{env, io};
use dotenv::dotenv;

use actix_files::Files;
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie,
    http,
    middleware::{self, ErrorHandlers},
    web, App, HttpServer,
};
use actix_identity::IdentityMiddleware;

mod models;
mod errors;
mod db;
mod utils;
mod auth_handler;
mod invitation_handler;
mod register_handler;
mod api;
mod email_service;

#[actix_web::main]
async fn main() -> io::Result<()> {
    dotenv().ok();    
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let database_url = format!("sqlite://{}", env::var("DATABASE_URL").unwrap());
    let domain: String = env::var("DOMAIN").unwrap_or_else(|_| "localhost".to_string());

    let pool = db::init_pool(&database_url).await.map_err(|e| {
        log::error!("Failed to connect to database: {}", e);
        io::Error::new(io::ErrorKind::Other, "Failed to connect to database")
    })?;

    log::info!("starting HTTP server at http://localhost:8080");

    HttpServer::new(move || {

        log::debug!("Constructing the App");

        let error_handlers = ErrorHandlers::new()
        .handler(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            api::internal_server_error,
        )
        .handler(http::StatusCode::BAD_REQUEST, api::bad_request)
        .handler(http::StatusCode::NOT_FOUND, api::not_found);

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(IdentityMiddleware::default())
            .wrap(middleware::Logger::default())
            .wrap(error_handlers)
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    cookie::Key::from(utils::SECRET_KEY.as_bytes()),
                )
                .session_lifecycle(PersistentSession::default().session_ttl(cookie::time::Duration::days(1)))
                .cookie_name("auth-example".to_owned())
                .cookie_secure(false)
                .cookie_domain(Some(domain.clone()))
                .cookie_path("/".to_owned())
                .build(),
            )
            .service(
                web::scope("/api")
                    .service(
                        web::resource("/invitation")
                            .route(web::post().to(invitation_handler::post_invitation)),
                    )
                    .service(
                        web::resource("/register/{invitation_id}")
                            .route(web::post().to(register_handler::register_user)),
                    )
                    .service(
                        web::resource("/auth")
                            .route(web::post().to(auth_handler::login))
                            .route(web::delete().to(auth_handler::logout))
                            .route(web::get().to(auth_handler::get_me)),
                    ),
            )
            .service(Files::new("/static", "static"))
            .service(Files::new("/", "./static/").index_file("index.html"))
    })
    .bind(("127.0.0.1", 8080))?
    .workers(2)
    .run()
    .await
}