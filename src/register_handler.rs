use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use crate::{
    errors::ServiceError,
    models::{Invitation, SlimUser, User},
    utils::hash_password,
};

// UserData is used to extract data from a post request by the client
#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub password: String,
}

pub async fn register_user(
    invitation_id: web::Path<String>,
    user_data: web::Json<UserData>,
    pool: web::Data<SqlitePool>) -> Result<HttpResponse, actix_web::Error> {

    let user_ = web::block(move || {
        query(
            invitation_id.into_inner(),
            user_data.into_inner().password,
            pool,
        )
    });

    let user = match user_.await {
        Ok(user) => user,
        Err(e) => {
            dbg!(e);
            return Err(actix_web::error::ErrorInternalServerError("Internal Server Error"));
        }
    };
    
    Ok(HttpResponse::Ok().json(user.await.unwrap()))
}

async fn query(
    invitation_id: String,
    password: String,
    pool: web::Data<SqlitePool>,
) -> Result<SlimUser, crate::errors::ServiceError> {

    let mut conn = pool.acquire().await?;

    let invitation_id = uuid::Uuid::parse_str(&invitation_id)?;

    // get invitation from database
    let invitations = sqlx::query_as::<_, Invitation>(
        r#"
        SELECT id, email, expires_at FROM invitations WHERE id = ?
        "#).bind(invitation_id).fetch_one(&mut conn).await;

            match invitations {
                Ok(invitation) => {
                // if invitation is not expired
                if invitation.expires_at > chrono::Utc::now() {
                    // try hashing the password, else return the error that will be converted to ServiceError
                    let hashed_password: String = hash_password(&password)?;
                    dbg!(&hashed_password);

                    let user = User::from_details(invitation.email, hashed_password);
                    dbg!(&user);

                    // insert the user into the database and fetch the inserted result
                    let insert_result_ = sqlx::query_as::<_, User>(r#"
                        INSERT INTO users (email, hash, created_at) VALUES (?, ?, ?) RETURNING *;
                    "#)
                    .bind(user.email)
                    .bind(user.hash)
                    .bind(user.created_at)
                    .fetch_one(&mut conn).await;

                    return match insert_result_ {
                        Ok(user) => {
                            Ok(SlimUser {
                                email: user.email,
                            })
                        },
                        Err(e) => {
                            dbg!(e);
                            Err(ServiceError::InternalServerError)
                        }
                    };

                } else {
                    return Err(ServiceError::BadRequest("Invitation Expired".into()));
                }

            },
            Err(_db_error) => {
                return Err(ServiceError::BadRequest("Invalid Invitation".into()));
            },
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        http,
        test::{self, init_service}, App,
    };
    use sqlx::Executor;

    #[actix_web::test]
    async fn test_register_user_handler() {

        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let mut conn = pool.acquire().await.unwrap();

        let email = "test@email.com";

        // create invitation table and insert a single invitation item into it to test
        let sql =  "CREATE TABLE invitations ( id UUID NOT NULL UNIQUE PRIMARY KEY, email VARCHAR(100) NOT NULL, expires_at TIMESTAMP NOT NULL);
        CREATE TABLE users ( email VARCHAR(100) NOT NULL UNIQUE PRIMARY KEY, hash VARCHAR(122) NOT NULL, created_at TIMESTAMP NOT NULL); ";

        conn.execute(sql).await.unwrap();

        let niv_ = Invitation::from(email);

        let invitation_ = sqlx::query_as::<_, Invitation>(r#"
            INSERT INTO invitations (id, email, expires_at) VALUES (?, ?, ?) RETURNING *;
        "#)
        .bind(niv_.id)
        .bind(niv_.email)
        .bind(niv_.expires_at)
        .fetch_one(&mut conn).await.unwrap();

        // create a test request
        let app_data = web::Data::new(pool);

        let req = test::TestRequest::post()
            .uri(format!( "/register/{}", invitation_.id).as_str())
            .app_data(app_data.clone())
            .set_json(&UserData {
                password: "password".to_string(),
            })
            .to_request();

        // check the register_handler responded SlimUser
        let srv = init_service(App::new().app_data(app_data.clone())
            .route("/register/{invitation_id}", web::post().to(register_user))).await;

        let res = test::call_service(&srv, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        // check the res body is SlimUser
        let user: SlimUser = test::read_body_json(res).await;
        assert_eq!(user.email, email);

    }

}