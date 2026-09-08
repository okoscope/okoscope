use sqlx::{PgPool, Row};
use thiserror::Error;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");
pub const REQUIRED_MIGRATION: i64 = 26;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationReport {
    pub required: i64,
    pub applied: i64,
}

#[derive(Debug, Error)]
pub enum ReadinessError {
    #[error("database query failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error(
        "database schema is not ready: expected migration {expected} or newer, found {actual:?}"
    )]
    MissingMigration { expected: i64, actual: Option<i64> },
}

pub async fn verify_schema(pool: &PgPool) -> Result<(), ReadinessError> {
    let actual = current_migration(pool).await?;
    if !schema_is_compatible(actual, REQUIRED_MIGRATION) {
        return Err(ReadinessError::MissingMigration {
            expected: REQUIRED_MIGRATION,
            actual,
        });
    }
    Ok(())
}

fn schema_is_compatible(actual: Option<i64>, required: i64) -> bool {
    actual.is_some_and(|actual| actual >= required)
}

async fn current_migration(pool: &PgPool) -> Result<Option<i64>, sqlx::Error> {
    let row =
        sqlx::query("SELECT max(version) AS version FROM _sqlx_migrations WHERE success = true")
            .fetch_one(pool)
            .await?;
    row.try_get("version")
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<MigrationReport> {
    MIGRATOR.run(pool).await?;
    verify_schema(pool).await?;
    let applied = current_migration(pool)
        .await?
        .expect("verified schema must have a migration version");
    Ok(MigrationReport {
        required: REQUIRED_MIGRATION,
        applied,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_newer_schema_supports_image_rollback() {
        assert!(!schema_is_compatible(None, 7));
        assert!(!schema_is_compatible(Some(7), 8));
        assert!(schema_is_compatible(Some(8), 8));
        assert!(schema_is_compatible(Some(9), 8));
    }
}
