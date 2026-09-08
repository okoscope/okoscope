use std::time::Duration;

use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionConfig {
    pub enabled: bool,
    pub batch_size: i64,
    pub poll_interval: Duration,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RetentionStats {
    pub recovery_operations_deleted: u64,
    pub terminal_deliveries_deleted: u64,
    pub duration_micros: u64,
}

pub async fn delete_once(
    pool: &PgPool,
    config: RetentionConfig,
) -> Result<RetentionStats, sqlx::Error> {
    if !config.enabled {
        return Ok(RetentionStats::default());
    }
    if !(1..=10_000).contains(&config.batch_size) {
        return Err(sqlx::Error::Protocol("invalid retention batch size".into()));
    }
    // A concurrent retry or cleaner can commit after our repeatable-read snapshot.
    // Retry the entire transaction with a fresh policy snapshot, never partial deletes.
    for attempt in 0..3 {
        match delete_batch(pool, config).await {
            Err(sqlx::Error::Database(error))
                if error.code().as_deref() == Some("40001") && attempt < 2 => {}
            result => return result,
        }
    }
    unreachable!("the final attempt always returns")
}

async fn delete_batch(
    pool: &PgPool,
    config: RetentionConfig,
) -> Result<RetentionStats, sqlx::Error> {
    let started_at = std::time::Instant::now();
    let mut tx = pool.begin().await?;
    // One snapshot for all policy reads in this batch. Serialize cleaners so a
    // shared bulk operation cannot be orphaned by two concurrent last-link deletes.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(220022)")
        .fetch_one(&mut *tx)
        .await?;
    if !acquired {
        return Ok(RetentionStats::default());
    }
    let ids = select_expired_deliveries(&mut tx, config.batch_size).await?;
    let operation_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT operation_id FROM notification_recovery_operation_deliveries WHERE delivery_id=ANY($1)",
    ).bind(&ids).fetch_all(&mut *tx).await?;
    let single = sqlx::query(
        "DELETE FROM notification_recovery_operations WHERE target_delivery_id=ANY($1)",
    )
    .bind(&ids)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let deliveries = sqlx::query("DELETE FROM notification_deliveries WHERE id=ANY($1)")
        .bind(&ids)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let shared = sqlx::query("DELETE FROM notification_recovery_operations o WHERE o.id=ANY($1) AND o.target_delivery_id IS NULL AND NOT EXISTS (SELECT 1 FROM notification_recovery_operation_deliveries l WHERE l.operation_id=o.id)")
        .bind(&operation_ids).execute(&mut *tx).await?.rows_affected();
    let empty = delete_empty_operations(&mut tx, config.batch_size).await?;
    tx.commit().await?;
    Ok(RetentionStats {
        recovery_operations_deleted: single + shared + empty,
        terminal_deliveries_deleted: deliveries,
        duration_micros: u64::try_from(started_at.elapsed().as_micros()).unwrap_or(u64::MAX),
    })
}

pub async fn run(pool: PgPool, config: RetentionConfig, mut shutdown: watch::Receiver<bool>) {
    if !config.enabled {
        tracing::info!("notification retention disabled");
        return;
    }
    tracing::info!(
        batch_size = config.batch_size,
        "notification retention active"
    );
    let mut ticker = tokio::time::interval(config.poll_interval);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            _ = ticker.tick() => match delete_once(&pool, config).await {
                Ok(stats) => {
                    crate::metrics::record_notification_retention_success(stats);
                    tracing::info!(?stats, "notification retention batch complete");
                }
                Err(error) => {
                    crate::metrics::record_notification_retention_failure();
                    tracing::error!(error=%error, "notification retention batch failed");
                }
            }
        }
    }
}

async fn delete_empty_operations(
    tx: &mut Transaction<'_, Postgres>,
    batch_size: i64,
) -> Result<u64, sqlx::Error> {
    // Bulk result JSON contains counts only; filters contain no delivery IDs.
    // Single-target results are removed with their target above.
    Ok(sqlx::query("WITH candidates AS (SELECT o.id FROM notification_recovery_operations o JOIN effective_notification_retention e ON e.organization_id=o.organization_id AND e.project_id=o.project_id WHERE e.enabled AND o.target_delivery_id IS NULL AND o.completed_at < now()-make_interval(days=>e.history_days) AND NOT EXISTS (SELECT 1 FROM notification_recovery_operation_deliveries l WHERE l.operation_id=o.id) ORDER BY o.completed_at,o.id LIMIT $1 FOR UPDATE OF o SKIP LOCKED) DELETE FROM notification_recovery_operations o USING candidates c WHERE o.id=c.id")
        .bind(batch_size).execute(&mut **tx).await?.rows_affected())
}

async fn select_expired_deliveries(
    tx: &mut Transaction<'_, Postgres>,
    batch_size: i64,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT d.id FROM notification_deliveries d JOIN effective_notification_retention e ON e.organization_id=d.organization_id AND e.project_id=d.project_id WHERE e.enabled AND d.status IN ('succeeded','failed','suppressed','cancelled') AND d.terminal_at < now()-make_interval(days=>e.history_days) ORDER BY d.terminal_at,d.id LIMIT $1 FOR UPDATE OF d SKIP LOCKED",
    ).bind(batch_size).fetch_all(&mut **tx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires a PostgreSQL server with DATABASE_URL"]
    async fn exact_retention_boundary_is_exclusive(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        let organization = Uuid::new_v4();
        let project = Uuid::new_v4();
        let destination = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name,notification_retention_enabled,notification_retention_days) VALUES($1,'boundary','Boundary',true,1)")
            .bind(organization).execute(&mut *tx).await.unwrap();
        sqlx::query(
            "INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','Project')",
        )
        .bind(project)
        .bind(organization)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("INSERT INTO webhook_destinations(id,organization_id,project_id,name,url,encrypted_secret,secret_nonce) VALUES($1,$2,$3,'receiver','https://example.test/hook',$4,$5)")
            .bind(destination).bind(organization).bind(project).bind(vec![4_u8;48]).bind(vec![5_u8;24])
            .execute(&mut *tx).await.unwrap();
        let boundary = Uuid::new_v4();
        let expired = Uuid::new_v4();
        for (id, offset) in [(boundary, 0_f64), (expired, 0.000_001)] {
            sqlx::query("INSERT INTO notification_deliveries(id,organization_id,project_id,destination_id,origin,source,event_name,payload,status,max_attempts,terminal_at) VALUES($1,$2,$3,$4,'test','test','okoscope.test','{}','succeeded',3,now()-interval '1 day'-make_interval(secs=>$5))")
                .bind(id).bind(organization).bind(project).bind(destination).bind(offset)
                .execute(&mut *tx).await.unwrap();
        }
        // now() is constant within this transaction, so this checks exactly one
        // microsecond either side without wall-clock sleeps or timing tolerances.
        let selected = select_expired_deliveries(&mut tx, 10).await.unwrap();
        assert_eq!(selected, vec![expired]);
        tx.rollback().await.unwrap();
    }
}
