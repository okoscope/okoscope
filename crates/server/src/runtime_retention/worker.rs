use crate::repository::runtime_retention::RuntimeRetentionRepository;
use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

pub static EXPIRED_ARRIVALS: AtomicU64 = AtomicU64::new(0);
static COMPACTED: AtomicU64 = AtomicU64::new(0);
static EXPIRED_SNAPSHOTS: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicU64 = AtomicU64::new(0);
static LAST_SUCCESS: AtomicU64 = AtomicU64::new(0);
static DURATION_US: AtomicU64 = AtomicU64::new(0);
static BACKLOG_PROJECTS: AtomicU64 = AtomicU64::new(0);
static PAUSED: AtomicU64 = AtomicU64::new(0);

pub fn render_metrics() -> String {
    let values = [
        ("compacted_events_total", &COMPACTED),
        ("expired_snapshots_total", &EXPIRED_SNAPSHOTS),
        ("expired_arrivals_total", &EXPIRED_ARRIVALS),
        ("errors_total", &ERRORS),
        ("last_success_timestamp_seconds", &LAST_SUCCESS),
        ("duration_microseconds_total", &DURATION_US),
        ("paused", &PAUSED),
        ("raw_backlog_projects_last_scan", &BACKLOG_PROJECTS),
    ];
    values
        .iter()
        .fold(String::new(), |mut output, (name, value)| {
            let _ = writeln!(
                &mut output,
                "okoscope_runtime_retention_{name} {}",
                value.load(Ordering::Relaxed)
            );
            output
        })
}

/// Shared lock order: organization before project, before projection rows.
pub async fn lock_project(
    tx: &mut Transaction<'_, Postgres>,
    org: Uuid,
    project: Uuid,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    crate::repository::ProjectRepository::lock_for_update(tx, org, project)
        .await?
        .map(|locked| locked.runtime_closed_before)
        .ok_or(sqlx::Error::RowNotFound)
}

pub async fn run(pool: PgPool, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let seconds = std::env::var("OKOSCOPE_RUNTIME_RETENTION_POLL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60)
        .clamp(1, 3600);
    let paused =
        std::env::var("OKOSCOPE_RUNTIME_RETENTION_PAUSED").is_ok_and(|v| v == "true" || v == "1");
    PAUSED.store(u64::from(paused), Ordering::Relaxed);
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(seconds));
    let mut cursor = Uuid::nil();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                if paused { continue; }
                let started=std::time::Instant::now();
                let result = tick(&pool, &mut cursor).await;
                DURATION_US.fetch_add(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),Ordering::Relaxed);
                if result.is_err() { ERRORS.fetch_add(1,Ordering::Relaxed); } else { LAST_SUCCESS.store(u64::try_from(Utc::now().timestamp()).unwrap_or(0),Ordering::Relaxed); }
                match result { Ok(count) => tracing::info!(compacted_events=count,"runtime retention batch complete"), Err(error) => tracing::error!(%error,"runtime retention failed") }
            }
        }
    }
}

async fn tick(pool: &PgPool, cursor: &mut Uuid) -> Result<u64, sqlx::Error> {
    let projects: Vec<(Uuid, Uuid)> =
        RuntimeRetentionRepository::project_page(pool, *cursor).await?;
    if projects.is_empty() {
        *cursor = Uuid::nil();
    }
    let mut count = 0;
    let mut backlog = 0;
    for (org, project) in projects {
        // Advance even on failure so one Project cannot starve the next tick.
        *cursor = project;
        count += process_project(pool, org, project, Utc::now(), 500).await?;
        count += crate::resources::cleanup_project(pool, project, Utc::now(), 500).await?;
        crate::resources::refresh_project_findings(pool, org, project).await;
        let pending: bool = RuntimeRetentionRepository::has_backlog(pool, project).await?;
        backlog += u64::from(pending);
    }
    BACKLOG_PROJECTS.store(backlog, Ordering::Relaxed);
    Ok(count)
}

pub async fn process_project(
    pool: &PgPool,
    org: Uuid,
    project: Uuid,
    now: DateTime<Utc>,
    limit: i64,
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_project(&mut tx, org, project).await?;
    let (enabled, raw, history): (bool, i32, Option<i32>) =
        RuntimeRetentionRepository::policy(&mut *tx, project).await?;
    if !enabled {
        return Ok(0);
    }
    let closed = day_cutoff(now, raw);
    let expired = history.map(|days| day_cutoff(now, days));
    RuntimeRetentionRepository::advance_horizons(&mut *tx, project, closed, expired).await?;
    tx.commit().await?;
    let mut tx = pool.begin().await?;
    let watermark = lock_project(&mut tx, org, project).await?;
    // Re-resolve after the closure commit so a newly disabled policy pauses draining.
    let (enabled, history): (bool, Option<i32>) =
        RuntimeRetentionRepository::enabled_history_days(&mut *tx, project).await?;
    let expired = history.map(|days| day_cutoff(now, days));
    if !enabled {
        return Ok(0);
    }
    let ids: Vec<Uuid> = RuntimeRetentionRepository::closed_events_for_update(
        &mut *tx,
        project,
        watermark,
        limit.clamp(1, 1000),
    )
    .await?;
    compact(&mut tx, &ids, expired).await?;
    let expired_snapshots = expire(&mut tx, project, expired, limit).await?;
    cleanup_empty(&mut tx, project, limit).await?;
    tx.commit().await?;
    EXPIRED_SNAPSHOTS.fetch_add(expired_snapshots, Ordering::Relaxed);
    COMPACTED.fetch_add(ids.len() as u64, Ordering::Relaxed);
    Ok(ids.len() as u64)
}

fn day_cutoff(now: DateTime<Utc>, days: i32) -> DateTime<Utc> {
    (now - Duration::days(i64::from(days)))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc()
}

async fn compact(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[Uuid],
    expired: Option<DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    if ids.is_empty() {
        return Ok(());
    }
    let groups: Vec<Uuid> = RuntimeRetentionRepository::groups_of_events(&mut **tx, ids).await?;
    let items: Vec<Uuid> = RuntimeRetentionRepository::items_of_events(&mut **tx, ids).await?;
    for released in [false, true] {
        RuntimeRetentionRepository::fold_into_history_snapshots(tx, ids, expired, released).await?;
    }
    RuntimeRetentionRepository::mark_correlations_incomplete(&mut **tx, ids).await?;
    RuntimeRetentionRepository::detach_events(tx, ids).await?;
    RuntimeRetentionRepository::delete_events(&mut **tx, ids).await?;
    RuntimeRetentionRepository::clear_restart_loop_windows(&mut **tx, &groups).await?;
    recount_groups(tx, &groups).await?;
    recount_inventory(tx, &items).await?;
    Ok(())
}

async fn expire(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    expired: Option<DateTime<Utc>>,
    limit: i64,
) -> Result<u64, sqlx::Error> {
    let groups: Vec<Uuid> = RuntimeRetentionRepository::expire_snapshots(
        &mut **tx,
        project,
        expired,
        limit.clamp(1, 1000),
    )
    .await?;
    recount_groups(tx, &groups).await?;
    RuntimeRetentionRepository::expire_restart_loop_projections(
        &mut **tx,
        project,
        limit.clamp(1, 1000),
    )
    .await?;
    Ok(groups.len() as u64)
}

async fn recount_groups(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[Uuid],
) -> Result<(), sqlx::Error> {
    for id in ids {
        RuntimeRetentionRepository::restore_group_representative(&mut **tx, *id).await?;
        RuntimeRetentionRepository::recount_group(&mut **tx, *id).await?;
        RuntimeRetentionRepository::clear_group_releases(&mut **tx, *id).await?;
        RuntimeRetentionRepository::rebuild_group_releases(&mut **tx, *id).await?;
    }
    RuntimeRetentionRepository::restore_release_representatives(&mut **tx, ids).await?;
    Ok(())
}

async fn recount_inventory(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[Uuid],
) -> Result<(), sqlx::Error> {
    for id in ids {
        RuntimeRetentionRepository::recount_item(&mut **tx, *id).await?;
        RuntimeRetentionRepository::clear_item_projections(tx, *id).await?;
        RuntimeRetentionRepository::rebuild_item_releases(&mut **tx, *id).await?;
        RuntimeRetentionRepository::rebuild_item_sightings(&mut **tx, *id).await?;
        RuntimeRetentionRepository::rebuild_item_group_links(&mut **tx, *id).await?;
    }
    Ok(())
}

async fn cleanup_empty(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    limit: i64,
) -> Result<(), sqlx::Error> {
    RuntimeRetentionRepository::delete_empty_group_outbox(&mut **tx, project, limit.clamp(1, 1000))
        .await?;
    RuntimeRetentionRepository::delete_empty_items(&mut **tx, project, limit.clamp(1, 1000))
        .await?;
    RuntimeRetentionRepository::delete_empty_groups(&mut **tx, project, limit.clamp(1, 1000))
        .await?;
    Ok(())
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn failed_project_does_not_starve_later_projects(pool: PgPool) {
        let org = Uuid::from_u128(3);
        let failed = Uuid::from_u128(1);
        let healthy = Uuid::from_u128(2);
        sqlx::query("INSERT INTO organizations(id,slug,name,runtime_retention_enabled) VALUES($1,'fairness','Fairness',true)")
            .bind(org).execute(&pool).await.unwrap();
        for (id, slug) in [(failed, "failed"), (healthy, "healthy")] {
            sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,$3,$3)")
                .bind(id)
                .bind(org)
                .bind(slug)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("CREATE FUNCTION fail_retention_project() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected project failure'; END $$")
            .execute(&pool).await.unwrap();
        sqlx::query("CREATE TRIGGER fail_retention_project BEFORE UPDATE ON projects FOR EACH ROW WHEN (OLD.slug='failed') EXECUTE FUNCTION fail_retention_project()")
            .execute(&pool).await.unwrap();
        let mut cursor = Uuid::nil();
        assert!(tick(&pool, &mut cursor).await.is_err());
        assert_eq!(cursor, failed);
        assert_eq!(tick(&pool, &mut cursor).await.unwrap(), 0);
        assert_eq!(cursor, healthy);
        let closed: bool = sqlx::query_scalar(
            "SELECT runtime_closed_before IS NOT NULL FROM projects WHERE id=$1",
        )
        .bind(healthy)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(closed);
    }
}
