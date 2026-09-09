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
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR SHARE")
        .bind(org)
        .execute(&mut **tx)
        .await?;
    sqlx::query_scalar(
        "SELECT runtime_closed_before FROM projects WHERE organization_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(org)
    .bind(project)
    .fetch_one(&mut **tx)
    .await
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
        sqlx::query_as("SELECT organization_id,id FROM projects WHERE id>$1 ORDER BY id LIMIT 32")
            .bind(*cursor)
            .fetch_all(pool)
            .await?;
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
        let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_events e JOIN projects p ON p.id=e.project_id WHERE p.id=$1 AND e.observed_at<p.runtime_closed_before)").bind(project).fetch_one(pool).await?;
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
    let (enabled,raw,history): (bool,i32,Option<i32>)=sqlx::query_as("SELECT COALESCE(p.runtime_retention_enabled,o.runtime_retention_enabled),COALESCE(p.runtime_retention_raw_days,o.runtime_retention_raw_days),CASE WHEN p.runtime_retention_enabled IS NULL THEN o.runtime_retention_history_days ELSE p.runtime_retention_history_days END FROM projects p JOIN organizations o ON o.id=p.organization_id WHERE p.id=$1").bind(project).fetch_one(&mut *tx).await?;
    if !enabled {
        return Ok(0);
    }
    let closed = day_cutoff(now, raw);
    let expired = history.map(|days| day_cutoff(now, days));
    sqlx::query("UPDATE projects SET runtime_closed_before=GREATEST(runtime_closed_before,$2),runtime_history_expired_before=GREATEST(runtime_history_expired_before,$3) WHERE id=$1").bind(project).bind(closed).bind(expired).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut tx = pool.begin().await?;
    let watermark = lock_project(&mut tx, org, project).await?;
    // Re-resolve after the closure commit so a newly disabled policy pauses draining.
    let (enabled,history):(bool,Option<i32>)=sqlx::query_as("SELECT COALESCE(p.runtime_retention_enabled,o.runtime_retention_enabled),CASE WHEN p.runtime_retention_enabled IS NULL THEN o.runtime_retention_history_days ELSE p.runtime_retention_history_days END FROM projects p JOIN organizations o ON o.id=p.organization_id WHERE p.id=$1").bind(project).fetch_one(&mut *tx).await?;
    let expired = history.map(|days| day_cutoff(now, days));
    if !enabled {
        return Ok(0);
    }
    let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM runtime_events WHERE project_id=$1 AND EXISTS(SELECT 1 FROM runtime_event_group_memberships m WHERE m.event_id=runtime_events.id AND m.fingerprint_version=1) AND observed_at<$2 AND (event_kind NOT IN ('container.restart','container.terminated','process.exit') OR observed_at<$2-interval '10 minutes') ORDER BY observed_at,id LIMIT $3 FOR UPDATE").bind(project).bind(watermark).bind(limit.clamp(1,1000)).fetch_all(&mut *tx).await?;
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
    let groups: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT group_id FROM runtime_event_group_memberships WHERE event_id=ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut **tx)
    .await?;
    let items: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT item_id FROM runtime_inventory_event_memberships WHERE event_id=ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut **tx)
    .await?;
    for released in [false, true] {
        let conflict = if released {
            "(group_id,release_id,day,format_version) WHERE release_id IS NOT NULL"
        } else {
            "(group_id,day,format_version) WHERE release_id IS NULL"
        };
        let query = format!(
            "INSERT INTO runtime_history_snapshots(id,organization_id,project_id,application_id,group_id,release_id,day,occurrence_count,first_observed_at,last_observed_at) SELECT gen_random_uuid(),m.organization_id,m.project_id,m.application_id,m.group_id,m.release_id,(e.observed_at AT TIME ZONE 'UTC')::date,count(*),min(e.observed_at),max(e.observed_at) FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE e.id=ANY($1) AND ($2::timestamptz IS NULL OR e.observed_at >= $2) AND (m.release_id IS NOT NULL)=$3 GROUP BY m.organization_id,m.project_id,m.application_id,m.group_id,m.release_id,(e.observed_at AT TIME ZONE 'UTC')::date ON CONFLICT {conflict} DO UPDATE SET occurrence_count=runtime_history_snapshots.occurrence_count+EXCLUDED.occurrence_count,first_observed_at=LEAST(runtime_history_snapshots.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(runtime_history_snapshots.last_observed_at,EXCLUDED.last_observed_at)"
        );
        sqlx::query(&query)
            .bind(ids)
            .bind(expired)
            .bind(released)
            .execute(&mut **tx)
            .await?;
    }
    sqlx::query("INSERT INTO runtime_event_correlation_outcomes(organization_id,project_id,event_id,status,candidate_count,tolerance_seconds,retention_incomplete) SELECT e.organization_id,e.project_id,e.id,'qualified',1,30,true FROM runtime_events e WHERE e.id IN (SELECT kernel_event_id FROM runtime_event_correlations WHERE lifecycle_event_id=ANY($1) UNION SELECT lifecycle_event_id FROM runtime_event_correlations WHERE kernel_event_id=ANY($1)) ON CONFLICT(event_id) DO UPDATE SET retention_incomplete=true").bind(ids).execute(&mut **tx).await?;
    for query in [
        "UPDATE runtime_event_groups SET representative_event_id=NULL WHERE representative_event_id=ANY($1)",
        "UPDATE runtime_event_groups SET first_seen_event_id=NULL WHERE first_seen_event_id=ANY($1)",
        "UPDATE runtime_event_group_releases SET representative_event_id=NULL WHERE representative_event_id=ANY($1)",
    ] {
        sqlx::query(query).bind(ids).execute(&mut **tx).await?;
    }
    sqlx::query("DELETE FROM runtime_events WHERE id=ANY($1)")
        .bind(ids)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE runtime_event_groups g SET semantic_summary=semantic_summary-'latest_termination'-'latest_waiting_reason'-'observed_restart_count'-'window_started_at'-'window_ended_at' WHERE id=ANY($1) AND event_kind='container.restart_loop' AND NOT EXISTS(SELECT 1 FROM runtime_event_group_memberships m WHERE m.group_id=g.id)").bind(&groups).execute(&mut **tx).await?;
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
    let groups:Vec<Uuid>=sqlx::query_scalar("DELETE FROM runtime_history_snapshots WHERE id IN (SELECT id FROM runtime_history_snapshots WHERE project_id=$1 AND day<($2 AT TIME ZONE 'UTC')::date ORDER BY day,id LIMIT $3) RETURNING group_id").bind(project).bind(expired).bind(limit.clamp(1,1000)).fetch_all(&mut **tx).await?;
    recount_groups(tx, &groups).await?;
    sqlx::query("DELETE FROM runtime_restart_loop_projections WHERE ctid IN (SELECT ctid FROM runtime_restart_loop_projections WHERE project_id=$1 AND window_ended_at<(SELECT runtime_closed_before FROM projects WHERE id=$1)-interval '10 minutes' LIMIT $2)").bind(project).bind(limit.clamp(1,1000)).execute(&mut **tx).await?;
    Ok(groups.len() as u64)
}

async fn recount_groups(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[Uuid],
) -> Result<(), sqlx::Error> {
    for id in ids {
        sqlx::query("UPDATE runtime_event_groups SET representative_event_id=(SELECT m.event_id FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.group_id=$1 ORDER BY e.observed_at DESC,e.id DESC LIMIT 1) WHERE id=$1 AND representative_event_id IS NULL").bind(id).execute(&mut **tx).await?;
        sqlx::query("WITH evidence AS (SELECT e.observed_at first_at,e.observed_at last_at,1::bigint n FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.group_id=$1 UNION ALL SELECT first_observed_at,last_observed_at,occurrence_count FROM runtime_history_snapshots WHERE group_id=$1), totals AS (SELECT COALESCE(sum(n),0)::bigint n,min(first_at) first_at,max(last_at) last_at FROM evidence) UPDATE runtime_event_groups SET occurrence_count=totals.n,first_seen_at=COALESCE(totals.first_at,first_seen_at),last_seen_at=COALESCE(totals.last_at,last_seen_at),updated_at=now() FROM totals WHERE id=$1").bind(id).execute(&mut **tx).await?;
        sqlx::query("DELETE FROM runtime_event_group_releases WHERE group_id=$1")
            .bind(id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("WITH evidence AS (SELECT m.organization_id,m.project_id,m.application_id,m.release_id,m.group_id,e.observed_at first_at,e.observed_at last_at,1::bigint n FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.group_id=$1 AND m.release_id IS NOT NULL UNION ALL SELECT organization_id,project_id,application_id,release_id,group_id,first_observed_at,last_observed_at,occurrence_count FROM runtime_history_snapshots WHERE group_id=$1 AND release_id IS NOT NULL) INSERT INTO runtime_event_group_releases(organization_id,project_id,application_id,release_id,group_id,occurrence_count,first_seen_at,last_seen_at,representative_event_id) SELECT organization_id,project_id,application_id,release_id,group_id,sum(n),min(first_at),max(last_at),NULL FROM evidence GROUP BY organization_id,project_id,application_id,release_id,group_id").bind(id).execute(&mut **tx).await?;
    }
    sqlx::query("UPDATE runtime_event_group_releases gr SET representative_event_id=(SELECT m.event_id FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.group_id=gr.group_id AND m.release_id=gr.release_id ORDER BY e.observed_at DESC,e.id DESC LIMIT 1) WHERE gr.group_id=ANY($1)").bind(ids).execute(&mut **tx).await?;
    Ok(())
}

async fn recount_inventory(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[Uuid],
) -> Result<(), sqlx::Error> {
    for id in ids {
        sqlx::query("WITH totals AS (SELECT count(*) n,min(e.observed_at) first_at,max(e.observed_at) last_at,bool_or(e.event_kind='network.listen') listener,bool_or(e.event_kind='network.accept') accept FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.item_id=$1) UPDATE runtime_inventory_items SET occurrence_count=totals.n,first_seen_at=COALESCE(totals.first_at,first_seen_at),last_seen_at=COALESCE(totals.last_at,last_seen_at),semantic_summary=CASE WHEN inventory_kind='inbound_endpoint' THEN semantic_summary || jsonb_build_object('listener_observed',COALESCE(listener,false),'accept_observed',COALESCE(accept,false)) ELSE semantic_summary END,updated_at=now() FROM totals WHERE id=$1").bind(id).execute(&mut **tx).await?;
        for table in [
            "runtime_inventory_releases",
            "runtime_inventory_sightings",
            "runtime_inventory_group_links",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE item_id=$1"))
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }
        sqlx::query("INSERT INTO runtime_inventory_releases(organization_id,project_id,application_id,item_id,release_id,occurrence_count,first_seen_at,last_seen_at) SELECT m.organization_id,m.project_id,m.application_id,m.item_id,e.release_id,count(*),min(e.observed_at),max(e.observed_at) FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.item_id=$1 AND e.release_id IS NOT NULL GROUP BY m.organization_id,m.project_id,m.application_id,m.item_id,e.release_id").bind(id).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO runtime_inventory_sightings(organization_id,project_id,application_id,item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,pod_name,container_name,occurrence_count,first_seen_at,last_seen_at) SELECT m.organization_id,m.project_id,m.application_id,m.item_id,e.cluster_id,e.namespace,e.workload_kind,e.workload_name,e.pod_uid,max(e.pod_name),e.container_name,count(*),min(e.observed_at),max(e.observed_at) FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.item_id=$1 GROUP BY m.organization_id,m.project_id,m.application_id,m.item_id,e.cluster_id,e.namespace,e.workload_kind,e.workload_name,e.pod_uid,e.container_name").bind(id).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO runtime_inventory_group_links(organization_id,project_id,application_id,item_id,group_id) SELECT DISTINCT m.organization_id,m.project_id,m.application_id,m.item_id,g.group_id FROM runtime_inventory_event_memberships m JOIN runtime_event_group_memberships g ON g.event_id=m.event_id WHERE m.item_id=$1").bind(id).execute(&mut **tx).await?;
    }
    Ok(())
}

async fn cleanup_empty(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    limit: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM outbox_messages WHERE id IN (SELECT o.id FROM outbox_messages o JOIN runtime_event_groups g ON g.id=o.aggregate_id WHERE g.project_id=$1 AND g.occurrence_count=0 AND o.processed_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM notification_deliveries d WHERE d.outbox_message_id=o.id) ORDER BY o.created_at,o.id LIMIT $2)").bind(project).bind(limit.clamp(1,1000)).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM runtime_inventory_items WHERE id IN (SELECT i.id FROM runtime_inventory_items i WHERE i.project_id=$1 AND i.occurrence_count=0 AND NOT EXISTS(SELECT 1 FROM runtime_policy_revisions p WHERE p.source_inventory_item_id=i.id) AND NOT EXISTS(SELECT 1 FROM runtime_policy_suppressions p WHERE p.source_inventory_item_id=i.id) LIMIT $2)").bind(project).bind(limit.clamp(1,1000)).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM runtime_event_groups WHERE id IN (SELECT g.id FROM runtime_event_groups g WHERE g.project_id=$1 AND g.occurrence_count=0 AND NOT EXISTS(SELECT 1 FROM runtime_policy_revisions p WHERE p.source_runtime_group_id=g.id) AND NOT EXISTS(SELECT 1 FROM runtime_policy_suppressions p WHERE p.source_runtime_group_id=g.id) AND NOT EXISTS(SELECT 1 FROM outbox_messages o WHERE o.aggregate_id=g.id) LIMIT $2)").bind(project).bind(limit.clamp(1,1000)).execute(&mut **tx).await?;
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
