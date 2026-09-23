use crate::repository::policies::PolicyRepository;
use std::time::Duration;

use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    policy::{POLICY_EVALUATOR_VERSION, PolicyScope},
    policy_projection::{OwnedPlacement, project_existing_group, project_existing_sighting},
};

const DEFAULT_BATCH_SIZE: i64 = 200;

#[derive(Debug, FromRow)]
struct Operation {
    id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    identity_version: i16,
    identity_digest: Vec<u8>,
}
#[derive(Debug, FromRow)]
struct GroupRow {
    item_id: Uuid,
    group_id: Uuid,
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
}
#[derive(Debug, FromRow)]
struct SightingRow {
    item_id: Uuid,
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
    pod_uid: String,
    container_name: String,
}

pub async fn run(pool: PgPool, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let owner = Uuid::new_v4();
    while !*shutdown.borrow() {
        match run_one_batch(&pool, owner, DEFAULT_BATCH_SIZE).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => tracing::error!(%error,"policy recomputation batch failed"),
        }
        tokio::select! {
            _ = shutdown.changed() => {},
            () = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
}

pub async fn run_one_batch(
    pool: &PgPool,
    owner: Uuid,
    batch_size: i64,
) -> Result<bool, sqlx::Error> {
    if !(1..=1000).contains(&batch_size) {
        return Err(sqlx::Error::Protocol(
            "policy recomputation batch_size must be 1..=1000".into(),
        ));
    }
    let mut tx = pool.begin().await?;
    let operation: Option<Operation> =
        PolicyRepository::claim_recomputation(&mut *tx, owner).await?;
    let Some(operation) = operation else {
        tx.commit().await?;
        return Ok(false);
    };
    let scope = PolicyScope {
        organization_id: operation.organization_id,
        project_id: operation.project_id,
        application_id: operation.application_id,
    };
    let groups: Vec<GroupRow> = PolicyRepository::groups_to_evaluate(
        &mut *tx,
        scope.organization_id,
        scope.project_id,
        scope.application_id,
        operation.identity_version,
        &operation.identity_digest,
        POLICY_EVALUATOR_VERSION,
        batch_size,
    )
    .await?;
    for row in &groups {
        project_existing_group(
            &mut tx,
            scope,
            row.item_id,
            row.group_id,
            &OwnedPlacement {
                cluster_id: row.cluster_id,
                namespace: row.namespace.clone(),
                workload_kind: row.workload_kind.clone(),
                workload_name: row.workload_name.clone(),
            },
        )
        .await?;
    }
    let remaining = batch_size - i64::try_from(groups.len()).unwrap_or(batch_size);
    let sightings: Vec<SightingRow> = if remaining > 0 {
        PolicyRepository::sightings_to_evaluate(
            &mut *tx,
            scope.organization_id,
            scope.project_id,
            scope.application_id,
            operation.identity_version,
            &operation.identity_digest,
            POLICY_EVALUATOR_VERSION,
            remaining,
        )
        .await?
    } else {
        Vec::new()
    };
    for row in &sightings {
        project_existing_sighting(
            &mut tx,
            scope,
            row.item_id,
            &OwnedPlacement {
                cluster_id: row.cluster_id,
                namespace: row.namespace.clone(),
                workload_kind: row.workload_kind.clone(),
                workload_name: row.workload_name.clone(),
            },
            &row.pod_uid,
            &row.container_name,
        )
        .await?;
    }
    if i64::try_from(groups.len() + sightings.len()).unwrap_or(batch_size) < batch_size {
        PolicyRepository::complete_recomputation(&mut *tx, operation.id, owner).await?;
    } else {
        PolicyRepository::release_recomputation(&mut *tx, operation.id, owner).await?;
    }
    tx.commit().await?;
    Ok(true)
}

#[derive(Clone, Copy, Debug)]
pub struct BackfillOptions {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Option<Uuid>,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct BackfillStats {
    pub operations_created: u64,
}
pub async fn backfill(
    pool: &PgPool,
    options: BackfillOptions,
) -> Result<BackfillStats, sqlx::Error> {
    let rows = PolicyRepository::backfill_recomputations(
        pool,
        options.organization_id,
        options.project_id,
        options.application_id,
    )
    .await?;
    Ok(BackfillStats {
        operations_created: rows.rows_affected(),
    })
}
