//! Statements about the caller's transaction itself rather than any table:
//! its isolation and its snapshot time.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;

/// Transaction-level statements.
#[derive(Clone, Copy, Debug)]
pub struct TransactionRepository;

impl TransactionRepository {
    /// Makes the rest of the caller's transaction a repeatable-read snapshot
    /// that may still write.
    ///
    /// Must be the first statement of the transaction; pass `&mut *tx`.
    pub async fn begin_repeatable_read<'e, E>(
        executor: E,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(executor)
            .await
    }

    /// When the caller's transaction started, which is the time its snapshot
    /// was taken.
    pub async fn snapshot_time<'e, E>(executor: E) -> Result<DateTime<Utc>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, DateTime<Utc>>("SELECT transaction_timestamp()")
            .fetch_one(executor)
            .await
    }

    /// Makes the rest of the caller's transaction a read-only snapshot, so
    /// several statements see one state of the data.
    ///
    /// Must be the first statement of the transaction; pass `&mut *tx`.
    pub async fn begin_consistent_read<'e, E>(
        executor: E,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(executor)
            .await
    }
}
