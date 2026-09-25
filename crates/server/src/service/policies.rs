//! Behaviour policies of an application: managed policies seeded from the
//! runtime inventory, their revisions and recomputations, previews, and
//! suppressions. Mutations take an idempotency key and replay the stored
//! result of an identical request.
//!
//! The path, query and input types below are also the request's, and inputs
//! are hashed to recognise a replayed command, so their fields are part of
//! the API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::IdentityPrincipal;
use crate::policy::{
    BehaviorIdentity, Placement, PlacementMatcher, PolicyEffect, PolicySeed, SeedUnavailableReason,
};
use crate::repository::ApplicationRepository;
use crate::repository::inventory::InventoryRepository;
use crate::repository::policies::PolicyRepository;
use crate::repository::transaction::TransactionRepository;
use crate::service::project_access::project_scope;

/// Why a policy use case failed.
#[derive(Debug, Error)]
pub enum PolicyServiceError {
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(String),
    /// The project, application or policy object does not exist, or the
    /// principal may not see it.
    #[error("resource not found")]
    NotFound,
    /// The request conflicts with the stored state; the message says how.
    #[error("{0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl PolicyServiceError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct ApplicationPath {
    project_id: Uuid,
    application_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct PolicyPath {
    project_id: Uuid,
    application_id: Uuid,
    policy_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct ItemPath {
    project_id: Uuid,
    application_id: Uuid,
    item_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct GroupPath {
    project_id: Uuid,
    application_id: Uuid,
    group_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct SuppressionPath {
    project_id: Uuid,
    application_id: Uuid,
    suppression_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct RecomputePath {
    project_id: Uuid,
    application_id: Uuid,
    recomputation_id: Uuid,
}

#[derive(Debug, FromRow, Serialize)]
pub struct RecomputeSummary {
    id: Uuid,
    state: String,
    attempt_count: i32,
    requested_policy_revision_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct PageQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct SuppressionQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
    active: Option<bool>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct PolicySummary {
    id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    name: String,
    current_revision_id: Option<Uuid>,
    revision_number: Option<i64>,
    enabled: Option<bool>,
    inventory_kind: Option<String>,
    identity_version: Option<i16>,
    behavior_matcher: Option<Value>,
    cluster_ids: Option<Vec<Uuid>>,
    namespaces: Option<Vec<String>>,
    workload_kinds: Option<Vec<String>>,
    workload_names: Option<Vec<String>>,
    inside_effect: Option<String>,
    outside_effect: Option<String>,
    created_by_user_id: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct PolicyRevision {
    id: Uuid,
    policy_id: Uuid,
    revision_number: i64,
    prior_revision_id: Option<Uuid>,
    enabled: bool,
    inventory_kind: String,
    identity_version: i16,
    identity_digest: Vec<u8>,
    behavior_matcher: Value,
    cluster_ids: Vec<Uuid>,
    namespaces: Vec<String>,
    workload_kinds: Vec<String>,
    workload_names: Vec<String>,
    inside_effect: String,
    outside_effect: Option<String>,
    source_inventory_item_id: Option<Uuid>,
    source_runtime_group_id: Option<Uuid>,
    created_by_user_id: Uuid,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, FromRow)]
struct InventoryIdentityRow {
    id: Uuid,
    inventory_kind: String,
    identity_version: i16,
    identity_digest: Vec<u8>,
    semantic_summary: Value,
}

#[derive(Debug, FromRow)]
struct GroupSeedRow {
    item_id: Uuid,
    inventory_kind: String,
    identity_version: i16,
    identity_digest: Vec<u8>,
    semantic_summary: Value,
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
}

#[derive(Debug, FromRow, Serialize)]
pub struct SuppressionSummary {
    id: Uuid,
    inventory_kind: String,
    identity_version: i16,
    identity_digest: Vec<u8>,
    behavior_matcher: Value,
    cluster_ids: Vec<Uuid>,
    namespaces: Vec<String>,
    workload_kinds: Vec<String>,
    workload_names: Vec<String>,
    reason: String,
    expires_at: DateTime<Utc>,
    cancelled_at: Option<DateTime<Utc>>,
    cancelled_by_user_id: Option<Uuid>,
    source_inventory_item_id: Option<Uuid>,
    source_runtime_group_id: Option<Uuid>,
    created_by_user_id: Uuid,
    created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionInput {
    source_inventory_item_id: Uuid,
    source_runtime_group_id: Option<Uuid>,
    #[serde(default)]
    placement: PlacementMatcher,
    inside_effect: PolicyEffect,
    outside_effect: Option<PolicyEffect>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePolicyInput {
    name: String,
    revision: RevisionInput,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacePolicyInput {
    name: Option<String>,
    revision: RevisionInput,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionInput {
    source_inventory_item_id: Uuid,
    source_runtime_group_id: Option<Uuid>,
    #[serde(default)]
    placement: PlacementMatcher,
    reason: String,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MutationResult {
    resource_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recomputation_id: Option<Uuid>,
    policy_state_version: i64,
}

#[derive(Debug, Serialize)]
pub struct PreviewResult {
    snapshot_at: DateTime<Utc>,
    group_count: i64,
    sighting_count: i64,
    cluster_count: i64,
    namespace_count: i64,
    workload_count: i64,
    expected_count: i64,
    requires_review_count: i64,
    representative_group_ids: Vec<Uuid>,
    representative_sightings: Vec<PreviewSighting>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct PreviewSighting {
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
    pod_uid: String,
    container_name: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SeedResponse {
    Available { seed: Box<PolicySeed> },
    Unavailable { reason: SeedUnavailableReason },
}

#[derive(Clone, Copy)]
struct ProjectPrincipal {
    user_id: Uuid,
    organization_id: Uuid,
}

async fn ensure_application(
    state: &PolicyService,
    principal: ProjectPrincipal,
    path: ApplicationPath,
) -> Result<(), PolicyServiceError> {
    let exists = ApplicationRepository::exists(
        &state.pool,
        principal.organization_id,
        path.project_id,
        path.application_id,
    )
    .await
    .map_err(PolicyServiceError::Database)?;
    if exists {
        Ok(())
    } else {
        Err(PolicyServiceError::NotFound)
    }
}

fn page_limit(value: Option<i64>) -> Result<i64, PolicyServiceError> {
    let value = value.unwrap_or(50);
    if (1..=200).contains(&value) {
        Ok(value)
    } else {
        Err(PolicyServiceError::invalid(
            "limit must be between 1 and 200",
        ))
    }
}

fn parse_idempotency_key(key_header: Option<&str>) -> Result<Uuid, PolicyServiceError> {
    key_header
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| PolicyServiceError::invalid("Idempotency-Key must be a canonical UUID"))
}

fn normalized_name(value: &str) -> Result<String, PolicyServiceError> {
    let value = value.trim();
    if (1..=160).contains(&value.chars().count()) {
        Ok(value.to_owned())
    } else {
        Err(PolicyServiceError::invalid(
            "policy name must contain between 1 and 160 characters",
        ))
    }
}

fn request_digest<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    Ok(Sha256::digest(serde_json::to_vec(value)?).to_vec())
}

async fn begin_command<T: DeserializeOwned>(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    key: Uuid,
    digest: &[u8],
) -> Result<Option<T>, PolicyServiceError> {
    PolicyRepository::lock_command(&mut **tx, format!("{organization_id}:{key}"))
        .await
        .map_err(PolicyServiceError::Database)?;
    let existing: Option<(Vec<u8>, Value)> =
        PolicyRepository::command(&mut **tx, organization_id, key)
            .await
            .map_err(PolicyServiceError::Database)?;
    match existing {
        Some((stored, result)) if stored == digest => serde_json::from_value(result)
            .map(Some)
            .map_err(|_| PolicyServiceError::conflict("stored command result is invalid")),
        Some(_) => Err(PolicyServiceError::conflict(
            "idempotency key was already used for another request",
        )),
        None => Ok(None),
    }
}

async fn policy_state_version(
    tx: &mut Transaction<'_, Postgres>,
    principal: ProjectPrincipal,
    path: ApplicationPath,
) -> Result<i64, PolicyServiceError> {
    PolicyRepository::bump_state_version(
        &mut **tx,
        principal.organization_id,
        path.project_id,
        path.application_id,
    )
    .await
    .map_err(PolicyServiceError::Database)
}

async fn load_revision_identity(
    tx: &mut Transaction<'_, Postgres>,
    principal: ProjectPrincipal,
    path: ApplicationPath,
    input: &mut RevisionInput,
) -> Result<InventoryIdentityRow, PolicyServiceError> {
    input
        .placement
        .normalize()
        .map_err(PolicyServiceError::invalid)?;
    if input.outside_effect == Some(PolicyEffect::Expected) {
        return Err(PolicyServiceError::invalid(
            "outside_effect may only be requires_review",
        ));
    }
    let row: InventoryIdentityRow = InventoryRepository::identity(
        &mut **tx,
        principal.organization_id,
        path.project_id,
        path.application_id,
        input.source_inventory_item_id,
    )
    .await
    .map_err(PolicyServiceError::Database)?
    .ok_or(PolicyServiceError::NotFound)?;
    if let Some(group_id) = input.source_runtime_group_id {
        let linked: bool = InventoryRepository::item_linked_to_group(
            &mut **tx,
            principal.organization_id,
            path.project_id,
            path.application_id,
            row.id,
            group_id,
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        if !linked {
            return Err(PolicyServiceError::NotFound);
        }
    }
    BehaviorIdentity::from_inventory(
        &row.inventory_kind,
        row.identity_version,
        &row.identity_digest,
        &row.semantic_summary,
    )
    .map_err(|_| PolicyServiceError::invalid("inventory item cannot seed a managed policy"))?;
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
async fn insert_revision(
    tx: &mut Transaction<'_, Postgres>,
    principal: ProjectPrincipal,
    path: ApplicationPath,
    policy_id: Uuid,
    revision_number: i64,
    prior_revision_id: Option<Uuid>,
    enabled: bool,
    input: &RevisionInput,
    identity: &InventoryIdentityRow,
) -> Result<(Uuid, Uuid, i64), PolicyServiceError> {
    let revision_id = Uuid::new_v4();
    let recomputation_id = Uuid::new_v4();
    let matcher = BehaviorIdentity::from_inventory(
        &identity.inventory_kind,
        identity.identity_version,
        &identity.identity_digest,
        &identity.semantic_summary,
    )
    .map_err(|_| PolicyServiceError::invalid("invalid inventory identity"))?
    .matcher;
    PolicyRepository::insert_revision(
        &mut **tx,
        revision_id,
        policy_id,
        principal.organization_id,
        path.project_id,
        path.application_id,
        revision_number,
        prior_revision_id,
        enabled,
        &identity.inventory_kind,
        identity.identity_version,
        &identity.identity_digest,
        serde_json::to_value(matcher).unwrap(),
        input
            .placement
            .cluster_ids
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        input
            .placement
            .namespaces
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        input
            .placement
            .workload_kinds
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        input
            .placement
            .workload_names
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        match input.inside_effect {
            PolicyEffect::Expected => "expected",
            PolicyEffect::RequiresReview => "requires_review",
        },
        input.outside_effect.map(|_| "requires_review"),
        identity.id,
        input.source_runtime_group_id,
        principal.user_id,
    )
    .await
    .map_err(PolicyServiceError::Database)?;
    PolicyRepository::set_current_revision(
        &mut **tx,
        principal.organization_id,
        path.project_id,
        path.application_id,
        revision_id,
        policy_id,
    )
    .await
    .map_err(PolicyServiceError::Database)?;
    let version = policy_state_version(tx, principal, path).await?;
    PolicyRepository::request_recomputation(
        &mut **tx,
        recomputation_id,
        principal.organization_id,
        path.project_id,
        path.application_id,
        identity.identity_version,
        &identity.identity_digest,
        revision_id,
    )
    .await
    .map_err(PolicyServiceError::Database)?;
    Ok((revision_id, recomputation_id, version))
}

#[allow(clippy::too_many_arguments)]
async fn record_command<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    principal: ProjectPrincipal,
    path: ApplicationPath,
    key: Uuid,
    kind: &str,
    digest: &[u8],
    result: &T,
    resource_id: Uuid,
) -> Result<(), PolicyServiceError> {
    PolicyRepository::record_command(
        &mut **tx,
        Uuid::new_v4(),
        principal.organization_id,
        path.project_id,
        path.application_id,
        key,
        kind,
        digest,
        principal.user_id,
        resource_id,
        serde_json::to_value(result).unwrap(),
    )
    .await
    .map_err(PolicyServiceError::Database)?;
    Ok(())
}

async fn current_policy_state(
    tx: &mut Transaction<'_, Postgres>,
    principal: ProjectPrincipal,
    path: ApplicationPath,
) -> Result<i64, PolicyServiceError> {
    PolicyRepository::current_state_version(
        &mut **tx,
        principal.organization_id,
        path.project_id,
        path.application_id,
    )
    .await
    .map_err(PolicyServiceError::Database)
}

/// Manages an application's policies and suppressions.
#[derive(Clone, Debug)]
pub struct PolicyService {
    pool: PgPool,
}

impl PolicyService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// A policy recomputation's progress.
    pub async fn get_recomputation(
        &self,
        identity: IdentityPrincipal,
        path: RecomputePath,
    ) -> Result<RecomputeSummary, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        ensure_application(
            self,
            principal,
            ApplicationPath {
                project_id: path.project_id,
                application_id: path.application_id,
            },
        )
        .await?;
        let value = PolicyRepository::recomputation::<_, RecomputeSummary>(
            &self.pool,
            principal.organization_id,
            path.project_id,
            path.application_id,
            path.recomputation_id,
        )
        .await
        .map_err(PolicyServiceError::Database)?
        .ok_or(PolicyServiceError::NotFound)?;
        Ok(value)
    }

    /// The application's policies with their current revisions.
    pub async fn list_policies(
        &self,
        identity: IdentityPrincipal,
        path: ApplicationPath,
        query: PageQuery,
    ) -> Result<Page<PolicySummary>, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        ensure_application(self, principal, path).await?;
        let limit = page_limit(query.limit)?;
        let mut items: Vec<PolicySummary> = PolicyRepository::page(
            &self.pool,
            principal.organization_id,
            path.project_id,
            path.application_id,
            query.cursor,
            limit + 1,
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        let next_cursor =
            (items.len() > usize::try_from(limit).unwrap_or(0)).then(|| items.pop().unwrap().id);
        Ok(Page { items, next_cursor })
    }

    /// One policy with its current revision.
    pub async fn get_policy(
        &self,
        identity: IdentityPrincipal,
        path: PolicyPath,
    ) -> Result<PolicySummary, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        let item = PolicyRepository::get(
            &self.pool,
            principal.organization_id,
            path.project_id,
            path.application_id,
            path.policy_id,
        )
        .await
        .map_err(PolicyServiceError::Database)?
        .ok_or(PolicyServiceError::NotFound)?;
        Ok(item)
    }

    /// A policy's revisions, paged by revision id. A policy without revisions
    /// must still exist.
    pub async fn list_revisions(
        &self,
        identity: IdentityPrincipal,
        path: PolicyPath,
        query: PageQuery,
    ) -> Result<Page<PolicyRevision>, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        let limit = page_limit(query.limit)?;
        let mut items: Vec<PolicyRevision> = PolicyRepository::revision_page(
            &self.pool,
            principal.organization_id,
            path.project_id,
            path.application_id,
            path.policy_id,
            query.cursor,
            limit + 1,
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        if items.is_empty() {
            let _ = self.get_policy(identity, path).await?;
        }
        let next_cursor =
            (items.len() > usize::try_from(limit).unwrap_or(0)).then(|| items.pop().unwrap().id);
        Ok(Page { items, next_cursor })
    }

    /// The policy an inventory item would seed, or why it cannot seed one.
    pub async fn inventory_seed(
        &self,
        identity: IdentityPrincipal,
        path: ItemPath,
    ) -> Result<SeedResponse, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        let row: InventoryIdentityRow = InventoryRepository::identity(
            &self.pool,
            principal.organization_id,
            path.project_id,
            path.application_id,
            path.item_id,
        )
        .await
        .map_err(PolicyServiceError::Database)?
        .ok_or(PolicyServiceError::NotFound)?;
        let response = match BehaviorIdentity::from_inventory(
            &row.inventory_kind,
            row.identity_version,
            &row.identity_digest,
            &row.semantic_summary,
        ) {
            Ok(behavior) => SeedResponse::Available {
                seed: Box::new(PolicySeed::from_inventory_item(row.id, behavior)),
            },
            Err(reason) => SeedResponse::Unavailable { reason },
        };
        Ok(response)
    }

    /// The policy a runtime group would seed, placed where the group runs.
    pub async fn group_seed(
        &self,
        identity: IdentityPrincipal,
        path: GroupPath,
    ) -> Result<SeedResponse, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        let row: GroupSeedRow = InventoryRepository::group_seed(
            &self.pool,
            principal.organization_id,
            path.project_id,
            path.application_id,
            path.group_id,
        )
        .await
        .map_err(PolicyServiceError::Database)?
        .ok_or(PolicyServiceError::NotFound)?;
        let response = match BehaviorIdentity::from_inventory(
            &row.inventory_kind,
            row.identity_version,
            &row.identity_digest,
            &row.semantic_summary,
        ) {
            Ok(behavior) => SeedResponse::Available {
                seed: Box::new(PolicySeed::from_runtime_group(
                    row.item_id,
                    path.group_id,
                    behavior,
                    &Placement {
                        cluster_id: row.cluster_id,
                        namespace: &row.namespace,
                        workload_kind: &row.workload_kind,
                        workload_name: &row.workload_name,
                    },
                )),
            },
            Err(reason) => SeedResponse::Unavailable { reason },
        };
        Ok(response)
    }

    /// The application's suppressions, optionally only the active ones.
    pub async fn list_suppressions(
        &self,
        identity: IdentityPrincipal,
        path: ApplicationPath,
        query: SuppressionQuery,
    ) -> Result<Page<SuppressionSummary>, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        ensure_application(self, principal, path).await?;
        let limit = page_limit(query.limit)?;
        let mut items: Vec<SuppressionSummary> = PolicyRepository::suppression_page(
            &self.pool,
            principal.organization_id,
            path.project_id,
            path.application_id,
            query.cursor,
            query.active,
            limit + 1,
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        let next_cursor = (items.len() > usize::try_from(limit).unwrap_or(0))
            .then(|| items.pop().expect("extra suppression row exists").id);
        Ok(Page { items, next_cursor })
    }

    /// Creates a policy from an inventory item and requests its recomputation.
    /// The idempotency key replays the stored result of an identical request.
    pub async fn create_policy(
        &self,
        identity: IdentityPrincipal,
        path: ApplicationPath,
        key_header: Option<&str>,
        mut input: CreatePolicyInput,
    ) -> Result<MutationResult, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        ensure_application(self, principal, path).await?;
        input.name = normalized_name(&input.name)?;
        let key = parse_idempotency_key(key_header)?;
        let digest =
            request_digest(&input).map_err(|_| PolicyServiceError::invalid("invalid request"))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(PolicyServiceError::Database)?;
        if let Some(result) =
            begin_command(&mut tx, principal.organization_id, key, &digest).await?
        {
            return Ok(result);
        }
        let identity =
            load_revision_identity(&mut tx, principal, path, &mut input.revision).await?;
        let policy_id = Uuid::new_v4();
        PolicyRepository::insert(
            &mut *tx,
            policy_id,
            principal.organization_id,
            path.project_id,
            path.application_id,
            &input.name,
            principal.user_id,
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        let (revision_id, recompute, version) = insert_revision(
            &mut tx,
            principal,
            path,
            policy_id,
            1,
            None,
            true,
            &input.revision,
            &identity,
        )
        .await?;
        let result = MutationResult {
            resource_id: policy_id,
            revision_id: Some(revision_id),
            recomputation_id: Some(recompute),
            policy_state_version: version,
        };
        record_command(
            &mut tx, principal, path, key, "create", &digest, &result, policy_id,
        )
        .await?;
        tx.commit().await.map_err(PolicyServiceError::Database)?;
        Ok(result)
    }

    /// What a policy revision would match right now, without storing it.
    #[allow(clippy::too_many_lines)]
    pub async fn preview_policy(
        &self,
        identity: IdentityPrincipal,
        path: ApplicationPath,
        mut input: RevisionInput,
    ) -> Result<PreviewResult, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        ensure_application(self, principal, path).await?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(PolicyServiceError::Database)?;
        TransactionRepository::begin_consistent_read(&mut *tx)
            .await
            .map_err(PolicyServiceError::Database)?;
        let identity = load_revision_identity(&mut tx, principal, path, &mut input).await?;
        let snapshot_at: DateTime<Utc> = TransactionRepository::snapshot_time(&mut *tx)
            .await
            .map_err(PolicyServiceError::Database)?;
        let clusters = input
            .placement
            .cluster_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let namespaces = input
            .placement
            .namespaces
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let kinds = input
            .placement
            .workload_kinds
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let names = input
            .placement
            .workload_names
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let (sighting_count, cluster_count, namespace_count, workload_count, inside_count): (
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = PolicyRepository::preview_counts(
            &mut *tx,
            identity.id,
            &clusters,
            &namespaces,
            &kinds,
            &names,
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        let representative_group_ids: Vec<Uuid> = PolicyRepository::preview_group_ids(
            &mut *tx,
            identity.id,
            &clusters,
            &namespaces,
            &kinds,
            &names,
            input.outside_effect.is_some(),
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        let representative_sightings: Vec<PreviewSighting> = PolicyRepository::preview_sightings(
            &mut *tx,
            identity.id,
            &clusters,
            &namespaces,
            &kinds,
            &names,
            input.outside_effect.is_some(),
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        let group_count: i64 = InventoryRepository::linked_group_count(&mut *tx, identity.id)
            .await
            .map_err(PolicyServiceError::Database)?;
        let outside = if input.outside_effect.is_some() {
            sighting_count - inside_count
        } else {
            0
        };
        let (expected_count, requires_review_count) = match input.inside_effect {
            PolicyEffect::Expected => (inside_count, outside),
            PolicyEffect::RequiresReview => (0, inside_count + outside),
        };
        tx.commit().await.map_err(PolicyServiceError::Database)?;
        Ok(PreviewResult {
            snapshot_at,
            group_count,
            sighting_count,
            cluster_count,
            namespace_count,
            workload_count,
            expected_count,
            requires_review_count,
            representative_group_ids,
            representative_sightings,
        })
    }

    /// Replaces a policy's revision (and optionally its name).
    pub async fn replace_policy(
        &self,
        identity: IdentityPrincipal,
        path: PolicyPath,
        key_header: Option<&str>,
        mut input: ReplacePolicyInput,
    ) -> Result<MutationResult, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        let key = parse_idempotency_key(key_header)?;
        if let Some(name) = &input.name {
            input.name = Some(normalized_name(name)?);
        }
        let digest =
            request_digest(&input).map_err(|_| PolicyServiceError::invalid("invalid request"))?;
        let app = ApplicationPath {
            project_id: path.project_id,
            application_id: path.application_id,
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(PolicyServiceError::Database)?;
        if let Some(result) =
            begin_command(&mut tx, principal.organization_id, key, &digest).await?
        {
            return Ok(result);
        }
        let current: Option<(Uuid, i64)> = PolicyRepository::current_revision_for_update(
            &mut *tx,
            principal.organization_id,
            path.project_id,
            path.application_id,
            path.policy_id,
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        let (prior, number) = current.ok_or(PolicyServiceError::NotFound)?;
        if let Some(name) = &input.name {
            PolicyRepository::rename(&mut *tx, name, path.policy_id)
                .await
                .map_err(PolicyServiceError::Database)?;
        }
        let identity = load_revision_identity(&mut tx, principal, app, &mut input.revision).await?;
        let (revision, recompute, version) = insert_revision(
            &mut tx,
            principal,
            app,
            path.policy_id,
            number + 1,
            Some(prior),
            true,
            &input.revision,
            &identity,
        )
        .await?;
        let result = MutationResult {
            resource_id: path.policy_id,
            revision_id: Some(revision),
            recomputation_id: Some(recompute),
            policy_state_version: version,
        };
        record_command(
            &mut tx,
            principal,
            app,
            key,
            "replace",
            &digest,
            &result,
            path.policy_id,
        )
        .await?;
        tx.commit().await.map_err(PolicyServiceError::Database)?;
        Ok(result)
    }

    /// Enables or disables a policy by writing a new revision.
    pub async fn set_policy_enabled(
        &self,
        identity: IdentityPrincipal,
        path: PolicyPath,
        key_header: Option<&str>,
        enabled: bool,
    ) -> Result<MutationResult, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        let key = parse_idempotency_key(key_header)?;
        let digest = request_digest(&(path.policy_id, enabled)).unwrap();
        let app = ApplicationPath {
            project_id: path.project_id,
            application_id: path.application_id,
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(PolicyServiceError::Database)?;
        if let Some(result) =
            begin_command(&mut tx, principal.organization_id, key, &digest).await?
        {
            return Ok(result);
        }
        let row: Option<PolicyRevision> = PolicyRepository::current_revision_detail_for_update(
            &mut *tx,
            principal.organization_id,
            path.project_id,
            path.application_id,
            path.policy_id,
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        let row = row.ok_or(PolicyServiceError::NotFound)?;
        let mut input = RevisionInput {
            source_inventory_item_id: row.source_inventory_item_id.ok_or_else(|| {
                PolicyServiceError::conflict("policy source inventory item is unavailable")
            })?,
            source_runtime_group_id: row.source_runtime_group_id,
            placement: PlacementMatcher {
                cluster_ids: row.cluster_ids.into_iter().collect(),
                namespaces: row.namespaces.into_iter().collect(),
                workload_kinds: row.workload_kinds.into_iter().collect(),
                workload_names: row.workload_names.into_iter().collect(),
            },
            inside_effect: if row.inside_effect == "expected" {
                PolicyEffect::Expected
            } else {
                PolicyEffect::RequiresReview
            },
            outside_effect: row.outside_effect.map(|_| PolicyEffect::RequiresReview),
        };
        let identity = load_revision_identity(&mut tx, principal, app, &mut input).await?;
        let (revision, recompute, version) = insert_revision(
            &mut tx,
            principal,
            app,
            path.policy_id,
            row.revision_number + 1,
            Some(row.id),
            enabled,
            &input,
            &identity,
        )
        .await?;
        let result = MutationResult {
            resource_id: path.policy_id,
            revision_id: Some(revision),
            recomputation_id: Some(recompute),
            policy_state_version: version,
        };
        record_command(
            &mut tx,
            principal,
            app,
            key,
            if enabled { "enable" } else { "disable" },
            &digest,
            &result,
            path.policy_id,
        )
        .await?;
        tx.commit().await.map_err(PolicyServiceError::Database)?;
        Ok(result)
    }

    /// Suppresses a behaviour until `expires_at`.
    #[allow(clippy::too_many_lines)]
    pub async fn create_suppression(
        &self,
        identity: IdentityPrincipal,
        path: ApplicationPath,
        key_header: Option<&str>,
        mut input: SuppressionInput,
    ) -> Result<MutationResult, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        ensure_application(self, principal, path).await?;
        let normalized_reason = input.reason.trim().to_owned();
        input.reason = normalized_reason;
        input
            .placement
            .normalize()
            .map_err(PolicyServiceError::invalid)?;
        let now = Utc::now();
        if !(1..=500).contains(&input.reason.chars().count())
            || input.expires_at <= now
            || input.expires_at > now + chrono::Duration::days(90)
        {
            return Err(PolicyServiceError::invalid(
                "suppression requires a reason and an expiry within 90 days",
            ));
        }
        let key = parse_idempotency_key(key_header)?;
        let digest = request_digest(&input).unwrap();
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(PolicyServiceError::Database)?;
        if let Some(result) =
            begin_command(&mut tx, principal.organization_id, key, &digest).await?
        {
            return Ok(result);
        }
        let mut seed = RevisionInput {
            source_inventory_item_id: input.source_inventory_item_id,
            source_runtime_group_id: input.source_runtime_group_id,
            placement: input.placement.clone(),
            inside_effect: PolicyEffect::Expected,
            outside_effect: None,
        };
        let identity = load_revision_identity(&mut tx, principal, path, &mut seed).await?;
        let behavior = BehaviorIdentity::from_inventory(
            &identity.inventory_kind,
            identity.identity_version,
            &identity.identity_digest,
            &identity.semantic_summary,
        )
        .map_err(|_| PolicyServiceError::invalid("invalid inventory identity"))?;
        let id = Uuid::new_v4();
        PolicyRepository::insert_suppression(
            &mut *tx,
            id,
            principal.organization_id,
            path.project_id,
            path.application_id,
            &identity.inventory_kind,
            identity.identity_version,
            &identity.identity_digest,
            serde_json::to_value(behavior.matcher).unwrap(),
            input
                .placement
                .cluster_ids
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            input
                .placement
                .namespaces
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            input
                .placement
                .workload_kinds
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            input
                .placement
                .workload_names
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            &input.reason,
            input.expires_at,
            input.source_inventory_item_id,
            input.source_runtime_group_id,
            principal.user_id,
            now,
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        let version = current_policy_state(&mut tx, principal, path).await?;
        let result = MutationResult {
            resource_id: id,
            revision_id: None,
            recomputation_id: None,
            policy_state_version: version,
        };
        record_command(
            &mut tx, principal, path, key, "suppress", &digest, &result, id,
        )
        .await?;
        tx.commit().await.map_err(PolicyServiceError::Database)?;
        Ok(result)
    }

    /// Cancels an active suppression.
    pub async fn cancel_suppression(
        &self,
        identity: IdentityPrincipal,
        path: SuppressionPath,
        key_header: Option<&str>,
    ) -> Result<MutationResult, PolicyServiceError> {
        let principal = self.project_principal(identity, path.project_id).await?;
        let key = parse_idempotency_key(key_header)?;
        let digest = request_digest(&path.suppression_id).unwrap();
        let app = ApplicationPath {
            project_id: path.project_id,
            application_id: path.application_id,
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(PolicyServiceError::Database)?;
        if let Some(result) =
            begin_command(&mut tx, principal.organization_id, key, &digest).await?
        {
            return Ok(result);
        }
        let updated = PolicyRepository::cancel_suppression(
            &mut *tx,
            principal.organization_id,
            path.project_id,
            path.application_id,
            path.suppression_id,
            principal.user_id,
        )
        .await
        .map_err(PolicyServiceError::Database)?;
        if updated.rows_affected() == 0 {
            return Err(PolicyServiceError::NotFound);
        }
        let version = current_policy_state(&mut tx, principal, app).await?;
        let result = MutationResult {
            resource_id: path.suppression_id,
            revision_id: None,
            recomputation_id: None,
            policy_state_version: version,
        };
        record_command(
            &mut tx,
            principal,
            app,
            key,
            "cancel_suppression",
            &digest,
            &result,
            path.suppression_id,
        )
        .await?;
        tx.commit().await.map_err(PolicyServiceError::Database)?;
        Ok(result)
    }

    /// [`Self::set_policy_enabled`] turning the policy on.
    pub async fn enable_policy(
        &self,
        identity: IdentityPrincipal,
        path: PolicyPath,
        key_header: Option<&str>,
    ) -> Result<MutationResult, PolicyServiceError> {
        self.set_policy_enabled(identity, path, key_header, true)
            .await
    }

    /// [`Self::set_policy_enabled`] turning the policy off.
    pub async fn disable_policy(
        &self,
        identity: IdentityPrincipal,
        path: PolicyPath,
        key_header: Option<&str>,
    ) -> Result<MutationResult, PolicyServiceError> {
        self.set_policy_enabled(identity, path, key_header, false)
            .await
    }

    /// Resolves the project's organization and checks the principal may see
    /// the project; a project they cannot see does not exist for them.
    async fn project_principal(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<ProjectPrincipal, PolicyServiceError> {
        let scope = project_scope(&self.pool, identity, project_id)
            .await
            .map_err(PolicyServiceError::Database)?
            .ok_or(PolicyServiceError::NotFound)?;
        Ok(ProjectPrincipal {
            user_id: identity.user_id,
            organization_id: scope.organization_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::OrganizationRole;
    use crate::repository::test_support::{Tenant, exec, ingest, tenant, user};

    fn owner(tenant: &Tenant, user_id: Uuid) -> IdentityPrincipal {
        IdentityPrincipal {
            user_id,
            session_id: Uuid::new_v4(),
            active_organization_id: Some(tenant.organization_id),
            organization_role: Some(OrganizationRole::Owner),
            is_super_admin: false,
            privileged_until: None,
        }
    }

    fn app(tenant: &Tenant) -> ApplicationPath {
        ApplicationPath {
            project_id: tenant.project_id,
            application_id: tenant.application_id,
        }
    }

    fn policy_path(tenant: &Tenant, policy_id: Uuid) -> PolicyPath {
        PolicyPath {
            project_id: tenant.project_id,
            application_id: tenant.application_id,
            policy_id,
        }
    }

    fn revision(item: Uuid) -> RevisionInput {
        RevisionInput {
            source_inventory_item_id: item,
            source_runtime_group_id: None,
            placement: PlacementMatcher::default(),
            inside_effect: PolicyEffect::Expected,
            outside_effect: None,
        }
    }

    fn page() -> PageQuery {
        PageQuery {
            cursor: None,
            limit: None,
        }
    }

    /// Ingests one execution of `/bin/a` and returns its inventory item.
    async fn seed(pool: &PgPool, tenant: &Tenant) -> Uuid {
        ingest(
            pool,
            tenant,
            &[exec(
                tenant,
                "/bin/a",
                Utc::now() - chrono::Duration::minutes(5),
            )],
        )
        .await;
        sqlx::query_scalar("SELECT id FROM runtime_inventory_items WHERE application_id=$1")
            .bind(tenant.application_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn access_and_validation_come_first(pool: PgPool) {
        let other = tenant(&pool, "policy-service-other").await;
        let tenant = tenant(&pool, "policy-service-access").await;
        let service = PolicyService::new(pool.clone());
        let principal = owner(&tenant, user(&pool).await);
        let bad_page = PageQuery {
            cursor: None,
            limit: Some(0),
        };

        assert!(matches!(
            service
                .list_policies(owner(&other, Uuid::new_v4()), app(&tenant), bad_page)
                .await,
            Err(PolicyServiceError::NotFound)
        ));
        assert!(matches!(
            service
                .list_policies(principal, app(&other), bad_page)
                .await,
            Err(PolicyServiceError::NotFound)
        ));
        assert!(matches!(
            service.list_policies(principal, app(&tenant), bad_page).await,
            Err(PolicyServiceError::Invalid(message)) if message == "limit must be between 1 and 200"
        ));
        // The name is checked before the idempotency key.
        let unnamed = CreatePolicyInput {
            name: "  ".into(),
            revision: revision(Uuid::new_v4()),
        };
        assert!(matches!(
            service.create_policy(principal, app(&tenant), None, unnamed).await,
            Err(PolicyServiceError::Invalid(message)) if message.starts_with("policy name")
        ));
        let named = CreatePolicyInput {
            name: "Allowed".into(),
            revision: revision(Uuid::new_v4()),
        };
        assert!(matches!(
            service.create_policy(principal, app(&tenant), Some("x"), named.clone()).await,
            Err(PolicyServiceError::Invalid(message)) if message == "Idempotency-Key must be a canonical UUID"
        ));
        let key = Uuid::new_v4().to_string();
        assert!(matches!(
            service
                .create_policy(principal, app(&tenant), Some(&key), named)
                .await,
            Err(PolicyServiceError::NotFound)
        ));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn policies_are_created_idempotently_and_revised(pool: PgPool) {
        let tenant = tenant(&pool, "policy-service-lifecycle").await;
        let item = seed(&pool, &tenant).await;
        let service = PolicyService::new(pool.clone());
        let principal = owner(&tenant, user(&pool).await);

        let seeded = service
            .inventory_seed(
                principal,
                ItemPath {
                    project_id: tenant.project_id,
                    application_id: tenant.application_id,
                    item_id: item,
                },
            )
            .await
            .unwrap();
        assert!(matches!(seeded, SeedResponse::Available { .. }));

        let mut outside_expected = revision(item);
        outside_expected.outside_effect = Some(PolicyEffect::Expected);
        let key = Uuid::new_v4().to_string();
        assert!(matches!(
            service
                .create_policy(
                    principal,
                    app(&tenant),
                    Some(&key),
                    CreatePolicyInput {
                        name: "Allowed".into(),
                        revision: outside_expected,
                    },
                )
                .await,
            Err(PolicyServiceError::Invalid(message)) if message == "outside_effect may only be requires_review"
        ));
        let input = CreatePolicyInput {
            name: " Allowed ".into(),
            revision: revision(item),
        };
        let key = Uuid::new_v4().to_string();
        let created = service
            .create_policy(principal, app(&tenant), Some(&key), input.clone())
            .await
            .unwrap();
        let replayed = service
            .create_policy(principal, app(&tenant), Some(&key), input)
            .await
            .unwrap();
        assert_eq!(replayed.resource_id, created.resource_id);
        assert_eq!(replayed.revision_id, created.revision_id);
        assert!(matches!(
            service
                .create_policy(
                    principal,
                    app(&tenant),
                    Some(&key),
                    CreatePolicyInput {
                        name: "Other".into(),
                        revision: revision(item),
                    },
                )
                .await,
            Err(PolicyServiceError::Conflict(message)) if message == "idempotency key was already used for another request"
        ));

        let policy = created.resource_id;
        let stored = service
            .get_policy(principal, policy_path(&tenant, policy))
            .await
            .unwrap();
        assert_eq!(stored.name, "Allowed");
        assert_eq!(stored.enabled, Some(true));
        let disabled = service
            .disable_policy(
                principal,
                policy_path(&tenant, policy),
                Some(&Uuid::new_v4().to_string()),
            )
            .await
            .unwrap();
        assert!(disabled.policy_state_version > created.policy_state_version);
        let revisions = service
            .list_revisions(principal, policy_path(&tenant, policy), page())
            .await
            .unwrap();
        assert_eq!(revisions.items.len(), 2);
        // Revisions page by id, which carries no order; the second one is off.
        let second = revisions
            .items
            .iter()
            .find(|item| item.revision_number == 2)
            .unwrap();
        assert!(!second.enabled);
        assert!(matches!(
            service
                .list_revisions(principal, policy_path(&tenant, Uuid::new_v4()), page())
                .await,
            Err(PolicyServiceError::NotFound)
        ));
        let listed = service
            .list_policies(principal, app(&tenant), page())
            .await
            .unwrap();
        assert_eq!(listed.items.len(), 1);
        let recomputation = disabled.recomputation_id.unwrap();
        let progress = service
            .get_recomputation(
                principal,
                RecomputePath {
                    project_id: tenant.project_id,
                    application_id: tenant.application_id,
                    recomputation_id: recomputation,
                },
            )
            .await
            .unwrap();
        assert_eq!(progress.id, recomputation);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn suppressions_expire_within_bounds_and_cancel(pool: PgPool) {
        let tenant = tenant(&pool, "policy-service-suppressions").await;
        let item = seed(&pool, &tenant).await;
        let service = PolicyService::new(pool.clone());
        let principal = owner(&tenant, user(&pool).await);
        let suppression = |expires_at| SuppressionInput {
            source_inventory_item_id: item,
            source_runtime_group_id: None,
            placement: PlacementMatcher::default(),
            reason: "known maintenance".into(),
            expires_at,
        };

        assert!(matches!(
            service
                .create_suppression(
                    principal,
                    app(&tenant),
                    Some(&Uuid::new_v4().to_string()),
                    suppression(Utc::now() + chrono::Duration::days(91)),
                )
                .await,
            Err(PolicyServiceError::Invalid(message)) if message == "suppression requires a reason and an expiry within 90 days"
        ));
        let created = service
            .create_suppression(
                principal,
                app(&tenant),
                Some(&Uuid::new_v4().to_string()),
                suppression(Utc::now() + chrono::Duration::days(1)),
            )
            .await
            .unwrap();
        let active = SuppressionQuery {
            cursor: None,
            limit: None,
            active: Some(true),
        };
        let listed = service
            .list_suppressions(principal, app(&tenant), active)
            .await
            .unwrap();
        assert_eq!(listed.items.len(), 1);
        assert_eq!(listed.items[0].id, created.resource_id);

        let preview = service
            .preview_policy(principal, app(&tenant), revision(item))
            .await
            .unwrap();
        assert_eq!(preview.group_count, 1);

        service
            .cancel_suppression(
                principal,
                SuppressionPath {
                    project_id: tenant.project_id,
                    application_id: tenant.application_id,
                    suppression_id: created.resource_id,
                },
                Some(&Uuid::new_v4().to_string()),
            )
            .await
            .unwrap();
        let listed = service
            .list_suppressions(principal, app(&tenant), active)
            .await
            .unwrap();
        assert!(listed.items.is_empty());
        assert!(matches!(
            service
                .cancel_suppression(
                    principal,
                    SuppressionPath {
                        project_id: tenant.project_id,
                        application_id: tenant.application_id,
                        suppression_id: Uuid::new_v4(),
                    },
                    Some(&Uuid::new_v4().to_string()),
                )
                .await,
            Err(PolicyServiceError::NotFound)
        ));
    }
}
