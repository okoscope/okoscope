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
    let operation:Option<Operation>=sqlx::query_as("WITH candidate AS (SELECT id FROM runtime_policy_recomputations WHERE state='pending' OR (state='running' AND lease_expires_at<now()) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE runtime_policy_recomputations o SET state='running',lease_owner=$1,lease_expires_at=now()+interval '30 seconds',attempt_count=attempt_count+1,started_at=COALESCE(started_at,now()),updated_at=now() FROM candidate c WHERE o.id=c.id RETURNING o.id,o.organization_id,o.project_id,o.application_id,o.identity_version,o.identity_digest").bind(owner).fetch_optional(&mut *tx).await?;
    let Some(operation) = operation else {
        tx.commit().await?;
        return Ok(false);
    };
    let scope = PolicyScope {
        organization_id: operation.organization_id,
        project_id: operation.project_id,
        application_id: operation.application_id,
    };
    let groups:Vec<GroupRow>=sqlx::query_as("SELECT l.item_id,g.id group_id,g.cluster_id,g.namespace,g.workload_kind,g.workload_name FROM runtime_inventory_group_links l JOIN runtime_inventory_items i ON i.id=l.item_id JOIN runtime_event_groups g ON g.id=l.group_id LEFT JOIN runtime_group_policy_evaluations e ON e.group_id=g.id LEFT JOIN runtime_policy_states s ON s.organization_id=g.organization_id AND s.project_id=g.project_id AND s.application_id=g.application_id WHERE l.organization_id=$1 AND l.project_id=$2 AND l.application_id=$3 AND i.identity_version=$4 AND i.identity_digest=$5 AND (e.group_id IS NULL OR e.policy_state_version<COALESCE(s.state_version,0) OR e.evaluator_version<>$6) ORDER BY g.id LIMIT $7").bind(scope.organization_id).bind(scope.project_id).bind(scope.application_id).bind(operation.identity_version).bind(&operation.identity_digest).bind(POLICY_EVALUATOR_VERSION).bind(batch_size).fetch_all(&mut *tx).await?;
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
        sqlx::query_as("SELECT s.item_id,s.cluster_id,s.namespace,s.workload_kind,s.workload_name,s.pod_uid,s.container_name FROM runtime_inventory_sightings s JOIN runtime_inventory_items i ON i.id=s.item_id LEFT JOIN runtime_sighting_policy_evaluations e ON e.item_id=s.item_id AND e.cluster_id=s.cluster_id AND e.namespace=s.namespace AND e.workload_kind=s.workload_kind AND e.workload_name=s.workload_name AND e.pod_uid=s.pod_uid AND e.container_name=s.container_name LEFT JOIN runtime_policy_states ps ON ps.organization_id=s.organization_id AND ps.project_id=s.project_id AND ps.application_id=s.application_id WHERE s.organization_id=$1 AND s.project_id=$2 AND s.application_id=$3 AND i.identity_version=$4 AND i.identity_digest=$5 AND (e.item_id IS NULL OR e.policy_state_version<COALESCE(ps.state_version,0) OR e.evaluator_version<>$6) ORDER BY s.item_id,s.cluster_id,s.namespace,s.workload_kind,s.workload_name,s.pod_uid,s.container_name LIMIT $7").bind(scope.organization_id).bind(scope.project_id).bind(scope.application_id).bind(operation.identity_version).bind(&operation.identity_digest).bind(POLICY_EVALUATOR_VERSION).bind(remaining).fetch_all(&mut *tx).await?
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
        sqlx::query("UPDATE runtime_policy_recomputations SET state='completed',completed_at=now(),lease_owner=NULL,lease_expires_at=NULL,updated_at=now() WHERE id=$1 AND lease_owner=$2").bind(operation.id).bind(owner).execute(&mut *tx).await?;
    } else {
        sqlx::query("UPDATE runtime_policy_recomputations SET state='pending',lease_owner=NULL,lease_expires_at=NULL,updated_at=now() WHERE id=$1 AND lease_owner=$2").bind(operation.id).bind(owner).execute(&mut *tx).await?;
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
    let rows=sqlx::query("INSERT INTO runtime_policy_recomputations(id,organization_id,project_id,application_id,identity_version,identity_digest) SELECT gen_random_uuid(),i.organization_id,i.project_id,i.application_id,i.identity_version,i.identity_digest FROM runtime_inventory_items i WHERE i.organization_id=$1 AND i.project_id=$2 AND ($3::uuid IS NULL OR i.application_id=$3) AND NOT EXISTS(SELECT 1 FROM runtime_policy_recomputations o WHERE o.organization_id=i.organization_id AND o.project_id=i.project_id AND o.application_id=i.application_id AND o.identity_version=i.identity_version AND o.identity_digest=i.identity_digest AND o.state IN ('pending','running')) GROUP BY i.organization_id,i.project_id,i.application_id,i.identity_version,i.identity_digest").bind(options.organization_id).bind(options.project_id).bind(options.application_id).execute(pool).await?;
    Ok(BackfillStats {
        operations_created: rows.rows_affected(),
    })
}
