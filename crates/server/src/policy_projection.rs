use crate::repository::inventory::InventoryRepository;
use crate::repository::policies::PolicyRepository;
use event_model::RuntimeEvent;
use serde_json::{Value, json};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::policy::{
    EvaluationInput, POLICY_EVALUATOR_VERSION, Placement, PlacementMatcher, PolicyCandidate,
    PolicyEffect, PolicyScope, ScopedPolicyCandidate, evaluate_scoped,
};

#[derive(Debug, FromRow)]
struct CandidateRow {
    revision_id: Uuid,
    identity_version: i16,
    identity_digest: Vec<u8>,
    cluster_ids: Vec<Uuid>,
    namespaces: Vec<String>,
    workload_kinds: Vec<String>,
    workload_names: Vec<String>,
    inside_effect: String,
    outside_effect: Option<String>,
}

#[derive(Clone, Debug)]
pub struct OwnedPlacement {
    pub cluster_id: Uuid,
    pub namespace: String,
    pub workload_kind: String,
    pub workload_name: String,
}

#[derive(Debug)]
struct MaterializedEvaluation {
    state_version: i64,
    verdict: String,
    reason: String,
    winning_revision_id: Option<Uuid>,
    explanation: Value,
}

async fn evaluate_item(
    tx: &mut Transaction<'_, Postgres>,
    scope: PolicyScope,
    item_id: Uuid,
    placement: &OwnedPlacement,
) -> Result<MaterializedEvaluation, sqlx::Error> {
    let (identity_version, identity_digest): (i16, Vec<u8>) = InventoryRepository::identity_key(
        &mut **tx,
        scope.organization_id,
        scope.project_id,
        scope.application_id,
        item_id,
    )
    .await?;
    let state_version: Option<i64> = PolicyRepository::state_version(
        &mut **tx,
        scope.organization_id,
        scope.project_id,
        scope.application_id,
    )
    .await?;
    let rows: Vec<CandidateRow> = PolicyRepository::enabled_revisions_for_identity(
        &mut **tx,
        scope.organization_id,
        scope.project_id,
        scope.application_id,
        identity_version,
        &identity_digest,
    )
    .await?;
    let candidates = rows
        .into_iter()
        .filter_map(|row| {
            Some(ScopedPolicyCandidate {
                scope,
                identity_version: row.identity_version,
                identity_digest: row.identity_digest.try_into().ok()?,
                candidate: PolicyCandidate {
                    revision_id: row.revision_id,
                    placement: PlacementMatcher {
                        cluster_ids: row.cluster_ids.into_iter().collect(),
                        namespaces: row.namespaces.into_iter().collect(),
                        workload_kinds: row.workload_kinds.into_iter().collect(),
                        workload_names: row.workload_names.into_iter().collect(),
                    },
                    inside_effect: effect(&row.inside_effect)?,
                    outside_effect: row.outside_effect.as_deref().and_then(effect),
                },
            })
        })
        .collect::<Vec<_>>();
    let digest = identity_digest
        .as_slice()
        .try_into()
        .map_err(|_| sqlx::Error::Protocol("invalid inventory identity digest".into()))?;
    let evaluation = evaluate_scoped(
        &EvaluationInput {
            scope,
            identity_version,
            identity_digest: digest,
            placement: Placement {
                cluster_id: placement.cluster_id,
                namespace: &placement.namespace,
                workload_kind: &placement.workload_kind,
                workload_name: &placement.workload_name,
            },
        },
        &candidates,
    );
    Ok(MaterializedEvaluation {
        state_version: state_version.unwrap_or(0),
        verdict: enum_name(evaluation.verdict),
        reason: enum_name(evaluation.reason),
        winning_revision_id: evaluation.winning_revision_id,
        explanation: json!({"specificity":evaluation.specificity,"related_revision_ids":evaluation.related_revision_ids}),
    })
}

fn enum_name<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .expect("policy enum serializes")
        .as_str()
        .expect("policy enum is a string")
        .to_owned()
}

async fn store_group(
    tx: &mut Transaction<'_, Postgres>,
    scope: PolicyScope,
    group_id: Uuid,
    value: &MaterializedEvaluation,
) -> Result<(), sqlx::Error> {
    PolicyRepository::store_group_evaluation(
        &mut **tx,
        scope.organization_id,
        scope.project_id,
        scope.application_id,
        group_id,
        value.state_version,
        POLICY_EVALUATOR_VERSION,
        &value.verdict,
        &value.reason,
        value.winning_revision_id,
        &value.explanation,
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn store_sighting(
    tx: &mut Transaction<'_, Postgres>,
    scope: PolicyScope,
    item_id: Uuid,
    placement: &OwnedPlacement,
    pod_uid: &str,
    container_name: &str,
    value: &MaterializedEvaluation,
) -> Result<(), sqlx::Error> {
    PolicyRepository::store_sighting_evaluation(
        &mut **tx,
        scope.organization_id,
        scope.project_id,
        scope.application_id,
        item_id,
        placement.cluster_id,
        &placement.namespace,
        &placement.workload_kind,
        &placement.workload_name,
        pod_uid,
        container_name,
        value.state_version,
        POLICY_EVALUATOR_VERSION,
        &value.verdict,
        &value.reason,
        value.winning_revision_id,
        &value.explanation,
    )
    .await?;
    Ok(())
}

pub async fn project_current_evaluation(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    cluster_id: Uuid,
    group_id: Uuid,
    item_id: Uuid,
    event: &RuntimeEvent,
) -> Result<(), sqlx::Error> {
    let scope = PolicyScope {
        organization_id,
        project_id: event.attribution.project_id,
        application_id: event.attribution.application_id,
    };
    let placement = OwnedPlacement {
        cluster_id,
        namespace: event.attribution.namespace.clone(),
        workload_kind: event.attribution.workload_kind.clone(),
        workload_name: event.attribution.workload_name.clone(),
    };
    let value = evaluate_item(tx, scope, item_id, &placement).await?;
    store_group(tx, scope, group_id, &value).await?;
    store_sighting(
        tx,
        scope,
        item_id,
        &placement,
        &event.attribution.pod_uid,
        &event.attribution.container_name,
        &value,
    )
    .await
}

pub async fn project_existing_group(
    tx: &mut Transaction<'_, Postgres>,
    scope: PolicyScope,
    item_id: Uuid,
    group_id: Uuid,
    placement: &OwnedPlacement,
) -> Result<(), sqlx::Error> {
    let value = evaluate_item(tx, scope, item_id, placement).await?;
    store_group(tx, scope, group_id, &value).await
}

#[allow(clippy::too_many_arguments)]
pub async fn project_existing_sighting(
    tx: &mut Transaction<'_, Postgres>,
    scope: PolicyScope,
    item_id: Uuid,
    placement: &OwnedPlacement,
    pod_uid: &str,
    container_name: &str,
) -> Result<(), sqlx::Error> {
    let value = evaluate_item(tx, scope, item_id, placement).await?;
    store_sighting(
        tx,
        scope,
        item_id,
        placement,
        pod_uid,
        container_name,
        &value,
    )
    .await
}

fn effect(value: &str) -> Option<PolicyEffect> {
    match value {
        "expected" => Some(PolicyEffect::Expected),
        "requires_review" => Some(PolicyEffect::RequiresReview),
        _ => None,
    }
}
