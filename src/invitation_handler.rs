use actix_web::{web, HttpResponse};
use log::debug;
use sqlx::{FromRow, sqlite::SqlitePool};
use serde::Deserialize;
use futures::executor::block_on;

use crate::{
    email_service::send_invitation,
    models::{Invitation},
};

#[derive(FromRow, Deserialize, Debug)]
pub struct InvitationData {
    pub email: String,
}

pub async fn post_invitation(
    invitation_data: web::Json<InvitationData>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, actix_web::Error> {

    debug!("Invitation data: {:?}", invitation_data);

    web::block(move || create_invitation(invitation_data.into_inner().email, pool)).await??;

    Ok(HttpResponse::Ok().finish())
}

fn create_invitation(
    eml: String,
    pool: web::Data<SqlitePool>,
) -> Result<(), crate::errors::ServiceError> {

    let invitation = dbg!(block_on(query(eml, pool))?);

    send_invitation(&invitation)
}

async fn query(eml: String, pool: web::Data<SqlitePool>) -> Result<Invitation, crate::errors::ServiceError> {

    let mut conn = pool.acquire().await?;
    
    let new_invitation = Invitation::from(eml);

    // insert the invitation into the database and fetch the inserted result
    let insert_result_ = sqlx::query_as::<_, Invitation>(r#"
        INSERT INTO invitations (id, email, expires_at) VALUES (?, ?, ?) RETURNING *;
    "#)
    .bind(new_invitation.id)
    .bind(new_invitation.email)
    .bind(new_invitation.expires_at)
    .fetch_one(&mut conn).await;

    let insert_result = match insert_result_ {
        Ok(invitation) => invitation,
        Err(e) => {
            dbg!(e);
            return Err(crate::errors::ServiceError::InternalServerError);
        }
    };
    
    Ok(insert_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{Executor, Row};

    #[actix_web::test]
    async fn test_create_invitation() {
        // test scenario
        // create a sqlite memory pool and wrap it as web::Data
        // insert a test invitation into the database and check the result
        // check the invitation is inserted into the database
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let mut conn = pool.acquire().await.unwrap();

        let sql =  "CREATE TABLE invitations ( id UUID NOT NULL UNIQUE PRIMARY KEY, email VARCHAR(100) NOT NULL, expires_at TIMESTAMP NOT NULL); ";

        // create sql table to insert test
        conn.execute(sql).await.unwrap();

        // test the table created
        let row = sqlx::query("SELECT name FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert!(row.get::<String, usize>(0).contains("invitations"));

        let app_data = web::Data::new(pool);

        // pass the app_data to the create_invitation function
        // app_data will be tested later
        let invitation = query("test@email.com".to_string(), app_data.clone()).await.unwrap();

        assert_eq!(invitation.email, "test@email.com");

        // check the invitation is inserted into the database
        let row = sqlx::query("SELECT * FROM invitations")
            .fetch_one(&mut conn)
            .await
            .unwrap();

        assert_eq!(row.get::<String, usize>(1), invitation.email);

    }

}