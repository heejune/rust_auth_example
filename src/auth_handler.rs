use std::future::{ready, Ready};
use sqlx::sqlite::SqlitePool;

use actix_identity::Identity;
use actix_web::{
    dev::Payload, web, Error, FromRequest, HttpMessage as _, HttpRequest, HttpResponse,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::ServiceError,
    models::{SlimUser, User},
    utils::verify,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthData {
    pub email: String,
    pub password: String,
}

pub type LoggedUser = SlimUser;

impl FromRequest for LoggedUser {
    type Error = Error;
    type Future = Ready<Result<LoggedUser, Error>>;

    fn from_request(req: &HttpRequest, pl: &mut Payload) -> Self::Future {
        if let Ok(identity) = Identity::from_request(req, pl).into_inner() {
            if let Ok(user_json) = identity.id() {
                if let Ok(user) = serde_json::from_str(&user_json) {
                    return ready(Ok(user));
                }
            }
        }

        ready(Err(ServiceError::Unauthorized.into()))
    }
}

pub async fn logout(id: Identity) -> HttpResponse {
    id.logout();
    HttpResponse::NoContent().finish()
}

pub async fn login(
    req: HttpRequest,
    auth_data: web::Json<AuthData>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, actix_web::Error> {
    let user = web::block(move || query(auth_data.into_inner(), pool)).await?.await?;

    let user_string = serde_json::to_string(&user).unwrap();
    Identity::login(&req.extensions(), user_string).unwrap();

    Ok(HttpResponse::NoContent().finish())
}

pub async fn get_me(logged_user: LoggedUser) -> HttpResponse {
    HttpResponse::Ok().json(logged_user)
}

async fn query(auth_data: AuthData, pool: web::Data<SqlitePool>) -> Result<SlimUser, ServiceError> {
    // get user from database
    let user = User::get(auth_data.email.clone(), &pool).await;

    // if user doesn't exist, or password is incorrect, return Unauthorized error
    match user {
        Ok(user) => {
                if let Ok(matching) = verify(&user.hash, &auth_data.password) {
                    if matching {
                        return Ok(user.into());
                    }
                }
            else {
                dbg!(user);
            }
        },
        Err(e) => {
            dbg!(e);
        }
    }

    Err(ServiceError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use actix_identity::IdentityMiddleware;
    use actix_session::{SessionMiddleware, storage::CookieSessionStore};
    use actix_web::{test::{init_service, TestRequest}, web, App, dev::Service, cookie};

    use crate::utils::{hash_password, self};

    use super::*;

    async fn create_test_database() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let mut conn = pool.acquire().await.unwrap();

        sqlx::query(
            r#"
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                hash TEXT NOT NULL,
                created_at DATETIME NOT NULL
            )"#,
        )
        .execute(&mut conn)
        .await
        .unwrap();

        pool
    }

    async fn prepare_test_user_row(auth: &AuthData, pool: &SqlitePool) -> Result<(), sqlx::Error> {
        let mut conn = pool.acquire().await.unwrap();

        let hashed_password = hash_password(&auth.password).unwrap();
        let created_at = chrono::Local::now().naive_local();

        sqlx::query(
            r#"
            INSERT INTO users (email, hash, created_at)
            VALUES (?, ?, ?)"#,
        )
        .bind(&auth.email)
        .bind(hashed_password)
        .bind(created_at)
        .execute(&mut conn)
        .await?;

        // check that the user was inserted
        let new_user = User::get(auth.email.clone(), pool).await.unwrap();

        assert_eq!(new_user.email, auth.email);

        Ok(())
    }

    #[actix_web::test]
    async fn test_query() {

        let pool = create_test_database().await;
        let app_data = web::Data::new(pool);

        let email = "test@email.com";
        let password = "password";

        // test the query function
        let auth_data = AuthData {
            email: email.to_string(),
            password: password.to_string(),
        };

        prepare_test_user_row(&auth_data, &app_data.get_ref()).await.unwrap();

        let user = query(auth_data, app_data.clone()).await.unwrap();
        
        assert_eq!(user.email, email);
    }

    #[actix_web::test]
    async fn test_login() {
        // prepare test database and create a test user
        let pool = create_test_database().await;
        let app_data = web::Data::new(pool);

        let email = "test@email.com";
        let password = "password";

        let auth_data = AuthData {
            email: email.to_string(),
            password: password.to_string(),
        };

        prepare_test_user_row(&auth_data, &app_data.get_ref()).await.unwrap();

        let session_store = SessionMiddleware::builder(CookieSessionStore::default(), cookie::Key::from(utils::SECRET_KEY.as_bytes()),)
        .cookie_secure(false)
        .build();

        // test login function with correct credentials
        // create a service app with IdentityMiddleware using cookie identity
        let app = init_service(
            App::new()
                .app_data(app_data.clone())
                .wrap(IdentityMiddleware::default())
                .wrap(session_store)
                .service(web::resource("/login").route(web::post().to(login))),
        )
        .await;

        // create a test request
        let req = TestRequest::post()
            .uri("/login")
            .set_json(&auth_data)
            .to_request();

        let resp = app.call(req).await.unwrap();

        // check the Identity cookie was set
        assert!(resp.response().cookies().count() > 0);

    }

}