//! The database schema itself: which migrations have been applied.

use sqlx::PgExecutor;

/// Schema state.
#[derive(Clone, Copy, Debug)]
pub struct SchemaRepository;

impl SchemaRepository {
    /// The row holding the highest successfully applied migration version in
    /// its `version` column (NULL before any migration).
    pub async fn current_migration<'e, E>(executor: E) -> Result<sqlx::postgres::PgRow, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("SELECT max(version) AS version FROM _sqlx_migrations WHERE success = true")
            .fetch_one(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use sqlx::{PgPool, Row};

    use super::SchemaRepository;

    /// The current migration is the highest applied version.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_current_migration_is_the_latest_applied(pool: PgPool) {
        let row = SchemaRepository::current_migration(&pool).await.unwrap();
        let version: Option<i64> = row.try_get("version").unwrap();
        let latest = crate::database::MIGRATOR
            .iter()
            .map(|migration| migration.version)
            .max();
        assert_eq!(version, latest);
    }
}
