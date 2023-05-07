use serde::{Deserialize, Serialize};
use sqlx::{SqlitePool, FromRow};
use chrono::{Utc,DateTime,};

#[derive(FromRow, Serialize, Deserialize, Debug)]
pub struct User {
    pub email: String,
    pub hash: String,
    pub created_at: chrono::NaiveDateTime,
}

impl User {

    pub async fn get(email: String, connection: &SqlitePool) -> Result<User, sqlx::Error> {

        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users WHERE email = ?
            "#,
        )
        .bind(email)
        .fetch_one(connection)
        .await?;

        Ok(user)
    }

    pub fn from_details<S: Into<String>, T: Into<String>>(email: S, pwd: T) -> Self {
        User {
            email: email.into(),
            hash: pwd.into(),
            created_at: Utc::now().naive_utc(),
        }
    }
}

#[derive(FromRow, Serialize, Deserialize, Debug)]
pub struct Invitation {
    pub id: uuid::Uuid,
    pub email: String,
    pub expires_at: DateTime<Utc>,
}

// any type that implements Into<String> can be used to create Invitation
impl<T> From<T> for Invitation
where
    T: Into<String>,
{
    fn from(email: T) -> Self {
        Invitation {
            id: uuid::Uuid::new_v4(),
            email: email.into(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlimUser {
    pub email: String,
}

impl From<User> for SlimUser {
    fn from(user: User) -> Self {
        SlimUser { email: user.email }
    }
}