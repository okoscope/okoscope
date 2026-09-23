use std::time::Duration;

use event_model::{EventPayload, KubernetesAttribution, ProcessIdentity, RuntimeEvent};
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;

use crate::grouping::{GroupingSource, TrustedGroupingScope, assign_event};

#[derive(Clone, Copy, Debug)]
pub struct BackfillOptions {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub fingerprint_version: i16,
    pub batch_size: i64,
    pub throttle: Duration,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackfillStats {
    pub scanned: u64,
    pub grouped: u64,
    pub groups_created: u64,
}

#[derive(Debug, Error)]
pub enum BackfillError {
    #[error("only fingerprint version 1 is supported")]
    UnsupportedFingerprintVersion,
    #[error("batch size must be between 1 and 10000")]
    InvalidBatchSize,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("stored event payload is invalid: {0}")]
    InvalidPayload(#[from] serde_json::Error),
}

#[derive(Debug, FromRow)]
struct BackfillEvent {
    id: Uuid,
    event_id: Uuid,
    project_id: Uuid,
    cluster_id: Uuid,
    application_id: Uuid,
    release_id: Option<Uuid>,
    observed_at: chrono::DateTime<chrono::Utc>,
    node_name: String,
    namespace: String,
    pod_uid: String,
    pod_name: String,
    container_id: String,
    container_name: String,
    workload_uid: String,
    workload_kind: String,
    workload_name: String,
    cgroup_id: i64,
    pid: i64,
    tgid: i64,
    process_command: String,
    event_schema_version: i32,
    payload: serde_json::Value,
}

pub async fn run(pool: &PgPool, options: BackfillOptions) -> Result<BackfillStats, BackfillError> {
    if options.fingerprint_version != 1 {
        return Err(BackfillError::UnsupportedFingerprintVersion);
    }
    if !(1..=10_000).contains(&options.batch_size) {
        return Err(BackfillError::InvalidBatchSize);
    }
    let upper_bound: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM runtime_events WHERE organization_id=$1 AND project_id=$2 ORDER BY id DESC LIMIT 1",
    )
    .bind(options.organization_id)
    .bind(options.project_id)
    .fetch_optional(pool)
    .await?;
    let Some(upper_bound) = upper_bound else {
        return Ok(BackfillStats::default());
    };
    let mut cursor: Option<Uuid> = None;
    let mut stats = BackfillStats::default();
    loop {
        let mut tx = pool.begin().await?;
        let closed = crate::runtime_retention::worker::lock_project(
            &mut tx,
            options.organization_id,
            options.project_id,
        )
        .await?;
        if closed.is_some() {
            tracing::info!(?closed, "backfill covers retained raw evidence only");
        }
        let rows = sqlx::query_as::<_, BackfillEvent>(
            "SELECT e.id,e.event_id,e.project_id,e.cluster_id,e.application_id,e.release_id,e.observed_at,e.node_name,e.namespace,e.pod_uid,e.pod_name,e.container_id,e.container_name,e.workload_uid,e.workload_kind,e.workload_name,e.cgroup_id,e.pid,e.tgid,e.process_command,e.event_schema_version,e.payload FROM runtime_events e LEFT JOIN runtime_event_group_memberships m ON m.event_id=e.id AND m.fingerprint_version=$3 WHERE e.organization_id=$1 AND e.project_id=$2 AND m.event_id IS NULL AND ($4::uuid IS NULL OR e.id>$4) AND e.id<=$5 ORDER BY e.id LIMIT $6",
        )
        .bind(options.organization_id)
        .bind(options.project_id)
        .bind(options.fingerprint_version)
        .bind(cursor)
        .bind(upper_bound)
        .bind(options.batch_size)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let event = row.to_runtime_event()?;
            let scope = TrustedGroupingScope {
                organization_id: options.organization_id,
                project_id: row.project_id,
                application_id: row.application_id,
                cluster_id: row.cluster_id,
                namespace: &row.namespace,
                workload_kind: &row.workload_kind,
                workload_name: &row.workload_name,
            };
            let outcome = assign_event(
                &mut tx,
                row.id,
                row.release_id,
                &scope,
                &event,
                GroupingSource::Backfill,
            )
            .await?;
            stats.scanned = stats.scanned.saturating_add(1);
            stats.grouped = stats
                .grouped
                .saturating_add(u64::from(outcome.membership_created));
            stats.groups_created = stats
                .groups_created
                .saturating_add(u64::from(outcome.group_created));
        }
        tx.commit().await?;
        cursor = rows.last().map(|event| event.id);
        tracing::info!(
            scanned = stats.scanned,
            grouped = stats.grouped,
            groups_created = stats.groups_created,
            cursor = ?cursor,
            "runtime event backfill progress"
        );
        crate::metrics::record_backfill(stats.scanned, stats.grouped);
        if !options.throttle.is_zero() {
            tokio::time::sleep(options.throttle).await;
        }
    }
    Ok(stats)
}

impl BackfillEvent {
    fn to_runtime_event(&self) -> Result<RuntimeEvent, BackfillError> {
        Ok(RuntimeEvent {
            id: self.event_id,
            observed_at: self.observed_at,
            schema_version: u32::try_from(self.event_schema_version).unwrap_or(u32::MAX),
            attribution: KubernetesAttribution {
                project_id: self.project_id,
                application_id: self.application_id,
                node_name: self.node_name.clone(),
                namespace: self.namespace.clone(),
                pod_uid: self.pod_uid.clone(),
                pod_name: self.pod_name.clone(),
                container_id: self.container_id.clone(),
                container_name: self.container_name.clone(),
                workload_uid: self.workload_uid.clone(),
                workload_kind: self.workload_kind.clone(),
                workload_name: self.workload_name.clone(),
                release: None,
                release_identity: None,
            },
            process: ProcessIdentity {
                cgroup_id: u64::try_from(self.cgroup_id).unwrap_or(u64::MAX),
                pid: u32::try_from(self.pid).unwrap_or(u32::MAX),
                tgid: u32::try_from(self.tgid).unwrap_or(u32::MAX),
                command: self.process_command.clone(),
            },
            payload: serde_json::from_value::<EventPayload>(self.payload.clone())?,
        })
    }
}
