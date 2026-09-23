use crate::repository::event_groups::EventGroupRepository;
use crate::repository::events::EventRepository;
use crate::repository::inventory::InventoryRepository;
use std::time::Duration;

use event_model::{EventPayload, KubernetesAttribution, ProcessIdentity, RuntimeEvent};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;

use crate::inventory::{CURRENT_INVENTORY_IDENTITY_VERSION, project_event};

#[derive(Clone, Copy, Debug)]
pub struct InventoryBackfillOptions {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Option<Uuid>,
    pub identity_version: i16,
    pub batch_size: i64,
    pub throttle: Duration,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InventoryBackfillStats {
    pub closed_before: Option<chrono::DateTime<chrono::Utc>>,
    pub scanned: u64,
    pub projected: u64,
    pub skipped: u64,
    pub items_created: u64,
    pub last_cursor: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct InventoryReconciliation {
    pub closed_before: Option<chrono::DateTime<chrono::Utc>>,
    pub detail_scope: &'static str,
    pub source_event_count: i64,
    pub membership_count: i64,
    pub item_occurrence_count: i64,
    pub source_first_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub projected_first_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub source_last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub projected_last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub group_evidence_count: i64,
    pub group_occurrence_count: i64,
    pub mismatch_count: u64,
}

impl InventoryReconciliation {
    pub const fn is_consistent(self) -> bool {
        self.mismatch_count == 0
    }
}

#[derive(Debug, Error)]
pub enum InventoryOperationError {
    #[error("only inventory identity version 1 is supported")]
    UnsupportedIdentityVersion,
    #[error("batch size must be between 1 and 10000")]
    InvalidBatchSize,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("stored event payload is invalid: {0}")]
    InvalidPayload(#[from] serde_json::Error),
}

#[derive(Debug, FromRow)]
struct StoredInventoryEvent {
    id: Uuid,
    event_id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    cluster_id: Uuid,
    application_id: Uuid,
    release_id: Option<Uuid>,
    group_id: Uuid,
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

#[derive(Debug, FromRow)]
struct ReconciliationRow {
    source_event_count: i64,
    membership_count: i64,
    item_occurrence_count: i64,
    source_first_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    projected_first_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    source_last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    projected_last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn backfill(
    pool: &PgPool,
    options: InventoryBackfillOptions,
) -> Result<InventoryBackfillStats, InventoryOperationError> {
    if options.identity_version != CURRENT_INVENTORY_IDENTITY_VERSION.get() {
        return Err(InventoryOperationError::UnsupportedIdentityVersion);
    }
    if !(1..=10_000).contains(&options.batch_size) {
        return Err(InventoryOperationError::InvalidBatchSize);
    }
    let coverage = crate::runtime_retention::history::coverage(
        pool,
        options.organization_id,
        options.project_id,
    )
    .await?;
    let initial = InventoryBackfillStats {
        closed_before: coverage.closed_before,
        ..Default::default()
    };
    let upper_bound: Option<Uuid> = EventRepository::latest_id(
        pool,
        options.organization_id,
        options.project_id,
        options.application_id,
    )
    .await?;
    let Some(upper_bound) = upper_bound else {
        return Ok(initial);
    };

    let mut cursor = None;
    let mut stats = initial;
    loop {
        let mut tx = pool.begin().await?;
        lock_project(&mut tx, options.organization_id, options.project_id).await?;
        let rows = InventoryRepository::projection_backfill_page::<_, StoredInventoryEvent>(
            &mut *tx,
            options.organization_id,
            options.project_id,
            options.application_id,
            options.identity_version,
            cursor,
            upper_bound,
            options.batch_size,
        )
        .await?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let event = row.to_runtime_event()?;
            let outcome = project_event(
                &mut tx,
                row.id,
                row.group_id,
                row.release_id,
                row.cluster_id,
                row.organization_id,
                &event,
            )
            .await?;
            stats.scanned = stats.scanned.saturating_add(1);
            stats.projected = stats
                .projected
                .saturating_add(u64::from(outcome.membership_created));
            stats.skipped = stats
                .skipped
                .saturating_add(u64::from(!outcome.membership_created));
            stats.items_created = stats
                .items_created
                .saturating_add(u64::from(outcome.item_created));
        }
        tx.commit().await?;
        cursor = rows.last().map(|row| row.id);
        stats.last_cursor = cursor;
        crate::metrics::record_inventory_backfill(stats);
        tracing::info!(
            organization_id = %options.organization_id,
            project_id = %options.project_id,
            application_id = ?options.application_id,
            identity_version = options.identity_version,
            scanned = stats.scanned,
            projected = stats.projected,
            skipped = stats.skipped,
            items_created = stats.items_created,
            cursor = ?cursor,
            "runtime inventory backfill progress"
        );
        if !options.throttle.is_zero() {
            tokio::time::sleep(options.throttle).await;
        }
    }
    Ok(stats)
}

pub async fn reconcile(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    identity_version: i16,
) -> Result<InventoryReconciliation, InventoryOperationError> {
    if identity_version != CURRENT_INVENTORY_IDENTITY_VERSION.get() {
        return Err(InventoryOperationError::UnsupportedIdentityVersion);
    }
    let mut tx = pool.begin().await?;
    let closed_before = lock_project(&mut tx, organization_id, project_id)
        .await?
        .runtime_closed_before;
    let row = InventoryRepository::reconciliation::<_, ReconciliationRow>(
        &mut *tx,
        organization_id,
        project_id,
        application_id,
        identity_version,
    )
    .await?;
    let (group_evidence_count, group_occurrence_count): (i64, i64) =
        EventGroupRepository::evidence_counts(
            &mut *tx,
            organization_id,
            project_id,
            application_id,
        )
        .await?;
    tx.commit().await?;
    let mismatch_count = u64::from(group_evidence_count != group_occurrence_count)
        + u64::from(row.source_event_count != row.membership_count)
        + u64::from(row.membership_count != row.item_occurrence_count)
        + u64::from(row.source_first_seen_at != row.projected_first_seen_at)
        + u64::from(row.source_last_seen_at != row.projected_last_seen_at);
    let result = InventoryReconciliation {
        closed_before,
        detail_scope: "raw",
        source_event_count: row.source_event_count,
        membership_count: row.membership_count,
        item_occurrence_count: row.item_occurrence_count,
        source_first_seen_at: row.source_first_seen_at,
        projected_first_seen_at: row.projected_first_seen_at,
        source_last_seen_at: row.source_last_seen_at,
        projected_last_seen_at: row.projected_last_seen_at,
        group_evidence_count,
        group_occurrence_count,
        mismatch_count,
    };
    crate::metrics::record_inventory_reconciliation(result);
    tracing::info!(
        organization_id = %organization_id,
        project_id = %project_id,
        application_id = %application_id,
        identity_version,
        source_event_count = result.source_event_count,
        membership_count = result.membership_count,
        item_occurrence_count = result.item_occurrence_count,
        mismatch_count,
        "runtime inventory reconciliation complete"
    );
    Ok(result)
}

impl StoredInventoryEvent {
    fn to_runtime_event(&self) -> Result<RuntimeEvent, InventoryOperationError> {
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

async fn lock_project(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<crate::repository::LockedProject, sqlx::Error> {
    crate::repository::ProjectRepository::lock_for_update(tx, organization_id, project_id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}
