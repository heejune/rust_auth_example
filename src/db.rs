use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

pub async fn init_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    SqlitePoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(1))
        .connect(database_url)
        .await
}
