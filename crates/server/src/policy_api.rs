use crate::error_code::ErrorCode;
use crate::repository::inventory::InventoryRepository;
use crate::repository::policies::PolicyRepository;
use crate::repository::transaction::TransactionRepository;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::repository::{ApplicationRepository, ProjectRepository};
use crate::{
    access_control::resolve_project_access,
    auth::{IdentityPrincipal, UserSessionAuthenticator},
    policy::{
        BehaviorIdentity, Placement, PlacementMatcher, PolicyEffect, PolicySeed,
        SeedUnavailableReason,
    },
    web_api::{RequestId, error_response},
};

#[derive(Clone)]
struct PolicyApiState {
    pool: PgPool,
    auth: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = PolicyApiState {
        auth: UserSessionAuthenticator::new(pool.clone()),
        pool,
    };
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies",
            get(list_policies).post(create_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/preview",
            post(preview_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}",
            get(get_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/revisions",
            get(list_revisions),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/replace",
            post(replace_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/enable",
            post(enable_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/disable",
            post(disable_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/policy-seed",
            get(inventory_seed),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-groups/{group_id}/policy-seed",
            get(group_seed),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policy-suppressions",
            get(list_suppressions).post(create_suppression),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policy-suppressions/{suppression_id}/cancel",
            post(cancel_suppression),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policy-recomputations/{recomputation_id}",
            get(get_recomputation),
        )
        .with_state(state)
}

#[derive(Debug)]
struct PolicyApiError {
    status: StatusCode,
    code: ErrorCode,
    message: String,
    request_id: RequestId,
}

impl PolicyApiError {
    fn unauthorized(request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: ErrorCode::UNAUTHORIZED,
            message: "invalid or missing bearer credential".into(),
            request_id: request_id.clone(),
        }
    }
    fn invalid(message: impl Into<String>, request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: ErrorCode::INVALID_REQUEST,
            message: message.into(),
            request_id: request_id.clone(),
        }
    }
    fn not_found(request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: ErrorCode::NOT_FOUND,
            message: "resource not found".into(),
            request_id: request_id.clone(),
        }
    }
    fn conflict(message: impl Into<String>, request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: ErrorCode::CONFLICT,
            message: message.into(),
            request_id: request_id.clone(),
        }
    }
    fn database(error: &sqlx::Error, request_id: &RequestId) -> Self {
        tracing::error!(%error, request_id=%request_id.0, "policy API database error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ErrorCode::INTERNAL_ERROR,
            message: "internal server error".into(),
            request_id: request_id.clone(),
        }
    }
}

impl IntoResponse for PolicyApiError {
    fn into_response(self) -> Response {
        error_response(self.status, self.code, self.message, &self.request_id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct ApplicationPath {
    project_id: Uuid,
    application_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
struct PolicyPath {
    project_id: Uuid,
    application_id: Uuid,
    policy_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
struct ItemPath {
    project_id: Uuid,
    application_id: Uuid,
    item_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
struct GroupPath {
    project_id: Uuid,
    application_id: Uuid,
    group_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
struct SuppressionPath {
    project_id: Uuid,
    application_id: Uuid,
    suppression_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
struct RecomputePath {
    project_id: Uuid,
    application_id: Uuid,
    recomputation_id: Uuid,
}

#[derive(Debug, FromRow, Serialize)]
struct RecomputeSummary {
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
struct PageQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct SuppressionQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
    active: Option<bool>,
}

#[derive(Debug, FromRow, Serialize)]
struct PolicySummary {
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
struct PolicyRevision {
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
struct Page<T> {
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
struct SuppressionSummary {
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
struct RevisionInput {
    source_inventory_item_id: Uuid,
    source_runtime_group_id: Option<Uuid>,
    #[serde(default)]
    placement: PlacementMatcher,
    inside_effect: PolicyEffect,
    outside_effect: Option<PolicyEffect>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreatePolicyInput {
    name: String,
    revision: RevisionInput,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplacePolicyInput {
    name: Option<String>,
    revision: RevisionInput,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SuppressionInput {
    source_inventory_item_id: Uuid,
    source_runtime_group_id: Option<Uuid>,
    #[serde(default)]
    placement: PlacementMatcher,
    reason: String,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MutationResult {
    resource_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recomputation_id: Option<Uuid>,
    policy_state_version: i64,
}

#[derive(Debug, Serialize)]
struct PreviewResult {
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
struct PreviewSighting {
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
    pod_uid: String,
    container_name: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum SeedResponse {
    Available { seed: Box<PolicySeed> },
    Unavailable { reason: SeedUnavailableReason },
}

async fn principal(
    headers: &HeaderMap,
    state: &PolicyApiState,
    project_id: Uuid,
    request_id: &RequestId,
) -> Result<ProjectPrincipal, PolicyApiError> {
    let identity: IdentityPrincipal = state
        .auth
        .authenticate_identity_headers(headers)
        .await
        .map_err(|error| PolicyApiError::database(&error, request_id))?
        .ok_or_else(|| PolicyApiError::unauthorized(request_id))?;
    let organization_id: Uuid = ProjectRepository::organization_of(&state.pool, project_id)
        .await
        .map_err(|error| PolicyApiError::database(&error, request_id))?
        .ok_or_else(|| PolicyApiError::not_found(request_id))?;
    resolve_project_access(&state.pool, identity, organization_id, project_id)
        .await
        .map_err(|error| PolicyApiError::database(&error, request_id))?
        .ok_or_else(|| PolicyApiError::not_found(request_id))?;
    Ok(ProjectPrincipal {
        user_id: identity.user_id,
        organization_id,
    })
}

#[derive(Clone, Copy)]
struct ProjectPrincipal {
    user_id: Uuid,
    organization_id: Uuid,
}

async fn get_recomputation(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RecomputePath>,
) -> Result<Json<RecomputeSummary>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    ensure_application(
        &state,
        principal,
        ApplicationPath {
            project_id: path.project_id,
            application_id: path.application_id,
        },
        &request_id,
    )
    .await?;
    let value = PolicyRepository::recomputation::<_, RecomputeSummary>(
        &state.pool,
        principal.organization_id,
        path.project_id,
        path.application_id,
        path.recomputation_id,
    )
    .await
    .map_err(|error| PolicyApiError::database(&error, &request_id))?
    .ok_or_else(|| PolicyApiError::not_found(&request_id))?;
    Ok(Json(value))
}

async fn ensure_application(
    state: &PolicyApiState,
    principal: ProjectPrincipal,
    path: ApplicationPath,
    request_id: &RequestId,
) -> Result<(), PolicyApiError> {
    let exists = ApplicationRepository::exists(
        &state.pool,
        principal.organization_id,
        path.project_id,
        path.application_id,
    )
    .await
    .map_err(|error| PolicyApiError::database(&error, request_id))?;
    if exists {
        Ok(())
    } else {
        Err(PolicyApiError::not_found(request_id))
    }
}

fn page_limit(value: Option<i64>, request_id: &RequestId) -> Result<i64, PolicyApiError> {
    let value = value.unwrap_or(50);
    if (1..=200).contains(&value) {
        Ok(value)
    } else {
        Err(PolicyApiError::invalid(
            "limit must be between 1 and 200",
            request_id,
        ))
    }
}

async fn list_policies(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ApplicationPath>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<PolicySummary>>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    ensure_application(&state, principal, path, &request_id).await?;
    let limit = page_limit(query.limit, &request_id)?;
    let mut items: Vec<PolicySummary> = PolicyRepository::page(
        &state.pool,
        principal.organization_id,
        path.project_id,
        path.application_id,
        query.cursor,
        limit + 1,
    )
    .await
    .map_err(|error| PolicyApiError::database(&error, &request_id))?;
    let next_cursor =
        (items.len() > usize::try_from(limit).unwrap_or(0)).then(|| items.pop().unwrap().id);
    Ok(Json(Page { items, next_cursor }))
}

async fn get_policy(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PolicyPath>,
) -> Result<Json<PolicySummary>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    let item = PolicyRepository::get(
        &state.pool,
        principal.organization_id,
        path.project_id,
        path.application_id,
        path.policy_id,
    )
    .await
    .map_err(|error| PolicyApiError::database(&error, &request_id))?
    .ok_or_else(|| PolicyApiError::not_found(&request_id))?;
    Ok(Json(item))
}

async fn list_revisions(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PolicyPath>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<PolicyRevision>>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    let limit = page_limit(query.limit, &request_id)?;
    let mut items: Vec<PolicyRevision> = PolicyRepository::revision_page(
        &state.pool,
        principal.organization_id,
        path.project_id,
        path.application_id,
        path.policy_id,
        query.cursor,
        limit + 1,
    )
    .await
    .map_err(|error| PolicyApiError::database(&error, &request_id))?;
    if items.is_empty() {
        let _ = get_policy(
            State(state.clone()),
            headers,
            Extension(request_id.clone()),
            Path(path),
        )
        .await?;
    }
    let next_cursor =
        (items.len() > usize::try_from(limit).unwrap_or(0)).then(|| items.pop().unwrap().id);
    Ok(Json(Page { items, next_cursor }))
}

async fn inventory_seed(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ItemPath>,
) -> Result<Json<SeedResponse>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    let row: InventoryIdentityRow = InventoryRepository::identity(
        &state.pool,
        principal.organization_id,
        path.project_id,
        path.application_id,
        path.item_id,
    )
    .await
    .map_err(|error| PolicyApiError::database(&error, &request_id))?
    .ok_or_else(|| PolicyApiError::not_found(&request_id))?;
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
    Ok(Json(response))
}

async fn group_seed(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<GroupPath>,
) -> Result<Json<SeedResponse>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    let row: GroupSeedRow = InventoryRepository::group_seed(
        &state.pool,
        principal.organization_id,
        path.project_id,
        path.application_id,
        path.group_id,
    )
    .await
    .map_err(|error| PolicyApiError::database(&error, &request_id))?
    .ok_or_else(|| PolicyApiError::not_found(&request_id))?;
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
    Ok(Json(response))
}

async fn list_suppressions(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ApplicationPath>,
    Query(query): Query<SuppressionQuery>,
) -> Result<Json<Page<SuppressionSummary>>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    ensure_application(&state, principal, path, &request_id).await?;
    let limit = page_limit(query.limit, &request_id)?;
    let mut items: Vec<SuppressionSummary> = PolicyRepository::suppression_page(
        &state.pool,
        principal.organization_id,
        path.project_id,
        path.application_id,
        query.cursor,
        query.active,
        limit + 1,
    )
    .await
    .map_err(|error| PolicyApiError::database(&error, &request_id))?;
    let next_cursor = (items.len() > usize::try_from(limit).unwrap_or(0))
        .then(|| items.pop().expect("extra suppression row exists").id);
    Ok(Json(Page { items, next_cursor }))
}

fn idempotency_key(headers: &HeaderMap, request_id: &RequestId) -> Result<Uuid, PolicyApiError> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            PolicyApiError::invalid("Idempotency-Key must be a canonical UUID", request_id)
        })
}

fn normalized_name(value: &str, request_id: &RequestId) -> Result<String, PolicyApiError> {
    let value = value.trim();
    if (1..=160).contains(&value.chars().count()) {
        Ok(value.to_owned())
    } else {
        Err(PolicyApiError::invalid(
            "policy name must contain between 1 and 160 characters",
            request_id,
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
    request_id: &RequestId,
) -> Result<Option<T>, PolicyApiError> {
    PolicyRepository::lock_command(&mut **tx, format!("{organization_id}:{key}"))
        .await
        .map_err(|error| PolicyApiError::database(&error, request_id))?;
    let existing: Option<(Vec<u8>, Value)> =
        PolicyRepository::command(&mut **tx, organization_id, key)
            .await
            .map_err(|error| PolicyApiError::database(&error, request_id))?;
    match existing {
        Some((stored, result)) if stored == digest => serde_json::from_value(result)
            .map(Some)
            .map_err(|_| PolicyApiError::conflict("stored command result is invalid", request_id)),
        Some(_) => Err(PolicyApiError::conflict(
            "idempotency key was already used for another request",
            request_id,
        )),
        None => Ok(None),
    }
}

async fn policy_state_version(
    tx: &mut Transaction<'_, Postgres>,
    principal: ProjectPrincipal,
    path: ApplicationPath,
    request_id: &RequestId,
) -> Result<i64, PolicyApiError> {
    PolicyRepository::bump_state_version(
        &mut **tx,
        principal.organization_id,
        path.project_id,
        path.application_id,
    )
    .await
    .map_err(|error| PolicyApiError::database(&error, request_id))
}

async fn load_revision_identity(
    tx: &mut Transaction<'_, Postgres>,
    principal: ProjectPrincipal,
    path: ApplicationPath,
    input: &mut RevisionInput,
    request_id: &RequestId,
) -> Result<InventoryIdentityRow, PolicyApiError> {
    input
        .placement
        .normalize()
        .map_err(|message| PolicyApiError::invalid(message, request_id))?;
    if input.outside_effect == Some(PolicyEffect::Expected) {
        return Err(PolicyApiError::invalid(
            "outside_effect may only be requires_review",
            request_id,
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
    .map_err(|error| PolicyApiError::database(&error, request_id))?
    .ok_or_else(|| PolicyApiError::not_found(request_id))?;
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
        .map_err(|error| PolicyApiError::database(&error, request_id))?;
        if !linked {
            return Err(PolicyApiError::not_found(request_id));
        }
    }
    BehaviorIdentity::from_inventory(
        &row.inventory_kind,
        row.identity_version,
        &row.identity_digest,
        &row.semantic_summary,
    )
    .map_err(|_| {
        PolicyApiError::invalid("inventory item cannot seed a managed policy", request_id)
    })?;
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
    request_id: &RequestId,
) -> Result<(Uuid, Uuid, i64), PolicyApiError> {
    let revision_id = Uuid::new_v4();
    let recomputation_id = Uuid::new_v4();
    let matcher = BehaviorIdentity::from_inventory(
        &identity.inventory_kind,
        identity.identity_version,
        &identity.identity_digest,
        &identity.semantic_summary,
    )
    .map_err(|_| PolicyApiError::invalid("invalid inventory identity", request_id))?
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
    .map_err(|error| PolicyApiError::database(&error, request_id))?;
    PolicyRepository::set_current_revision(
        &mut **tx,
        principal.organization_id,
        path.project_id,
        path.application_id,
        revision_id,
        policy_id,
    )
    .await
    .map_err(|error| PolicyApiError::database(&error, request_id))?;
    let version = policy_state_version(tx, principal, path, request_id).await?;
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
    .map_err(|error| PolicyApiError::database(&error, request_id))?;
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
    request_id: &RequestId,
) -> Result<(), PolicyApiError> {
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
    .map_err(|error| PolicyApiError::database(&error, request_id))?;
    Ok(())
}

async fn create_policy(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ApplicationPath>,
    Json(mut input): Json<CreatePolicyInput>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    ensure_application(&state, principal, path, &request_id).await?;
    input.name = normalized_name(&input.name, &request_id)?;
    let key = idempotency_key(&headers, &request_id)?;
    let digest = request_digest(&input)
        .map_err(|_| PolicyApiError::invalid("invalid request", &request_id))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    if let Some(result) = begin_command(
        &mut tx,
        principal.organization_id,
        key,
        &digest,
        &request_id,
    )
    .await?
    {
        return Ok(Json(result));
    }
    let identity =
        load_revision_identity(&mut tx, principal, path, &mut input.revision, &request_id).await?;
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
    .map_err(|e| PolicyApiError::database(&e, &request_id))?;
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
        &request_id,
    )
    .await?;
    let result = MutationResult {
        resource_id: policy_id,
        revision_id: Some(revision_id),
        recomputation_id: Some(recompute),
        policy_state_version: version,
    };
    record_command(
        &mut tx,
        principal,
        path,
        key,
        "create",
        &digest,
        &result,
        policy_id,
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    Ok(Json(result))
}

#[allow(clippy::too_many_lines)]
async fn preview_policy(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ApplicationPath>,
    Json(mut input): Json<RevisionInput>,
) -> Result<Json<PreviewResult>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    ensure_application(&state, principal, path, &request_id).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    TransactionRepository::begin_consistent_read(&mut *tx)
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    let identity =
        load_revision_identity(&mut tx, principal, path, &mut input, &request_id).await?;
    let snapshot_at: DateTime<Utc> = TransactionRepository::snapshot_time(&mut *tx)
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
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
    .map_err(|e| PolicyApiError::database(&e, &request_id))?;
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
    .map_err(|e| PolicyApiError::database(&e, &request_id))?;
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
    .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    let group_count: i64 = InventoryRepository::linked_group_count(&mut *tx, identity.id)
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    let outside = if input.outside_effect.is_some() {
        sighting_count - inside_count
    } else {
        0
    };
    let (expected_count, requires_review_count) = match input.inside_effect {
        PolicyEffect::Expected => (inside_count, outside),
        PolicyEffect::RequiresReview => (0, inside_count + outside),
    };
    tx.commit()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    Ok(Json(PreviewResult {
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
    }))
}

async fn replace_policy(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PolicyPath>,
    Json(mut input): Json<ReplacePolicyInput>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    let key = idempotency_key(&headers, &request_id)?;
    if let Some(name) = &input.name {
        input.name = Some(normalized_name(name, &request_id)?);
    }
    let digest = request_digest(&input)
        .map_err(|_| PolicyApiError::invalid("invalid request", &request_id))?;
    let app = ApplicationPath {
        project_id: path.project_id,
        application_id: path.application_id,
    };
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    if let Some(result) = begin_command(
        &mut tx,
        principal.organization_id,
        key,
        &digest,
        &request_id,
    )
    .await?
    {
        return Ok(Json(result));
    }
    let current: Option<(Uuid, i64)> = PolicyRepository::current_revision_for_update(
        &mut *tx,
        principal.organization_id,
        path.project_id,
        path.application_id,
        path.policy_id,
    )
    .await
    .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    let (prior, number) = current.ok_or_else(|| PolicyApiError::not_found(&request_id))?;
    if let Some(name) = &input.name {
        PolicyRepository::rename(&mut *tx, name, path.policy_id)
            .await
            .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    }
    let identity =
        load_revision_identity(&mut tx, principal, app, &mut input.revision, &request_id).await?;
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
        &request_id,
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
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    Ok(Json(result))
}

async fn set_policy_enabled(
    state: PolicyApiState,
    headers: HeaderMap,
    request_id: RequestId,
    path: PolicyPath,
    enabled: bool,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    let key = idempotency_key(&headers, &request_id)?;
    let digest = request_digest(&(path.policy_id, enabled)).unwrap();
    let app = ApplicationPath {
        project_id: path.project_id,
        application_id: path.application_id,
    };
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    if let Some(result) = begin_command(
        &mut tx,
        principal.organization_id,
        key,
        &digest,
        &request_id,
    )
    .await?
    {
        return Ok(Json(result));
    }
    let row: Option<PolicyRevision> = PolicyRepository::current_revision_detail_for_update(
        &mut *tx,
        principal.organization_id,
        path.project_id,
        path.application_id,
        path.policy_id,
    )
    .await
    .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    let row = row.ok_or_else(|| PolicyApiError::not_found(&request_id))?;
    let mut input = RevisionInput {
        source_inventory_item_id: row.source_inventory_item_id.ok_or_else(|| {
            PolicyApiError::conflict("policy source inventory item is unavailable", &request_id)
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
    let identity = load_revision_identity(&mut tx, principal, app, &mut input, &request_id).await?;
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
        &request_id,
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
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    Ok(Json(result))
}
async fn enable_policy(
    State(s): State<PolicyApiState>,
    h: HeaderMap,
    Extension(r): Extension<RequestId>,
    Path(p): Path<PolicyPath>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    set_policy_enabled(s, h, r, p, true).await
}
async fn disable_policy(
    State(s): State<PolicyApiState>,
    h: HeaderMap,
    Extension(r): Extension<RequestId>,
    Path(p): Path<PolicyPath>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    set_policy_enabled(s, h, r, p, false).await
}

async fn current_policy_state(
    tx: &mut Transaction<'_, Postgres>,
    principal: ProjectPrincipal,
    path: ApplicationPath,
    request_id: &RequestId,
) -> Result<i64, PolicyApiError> {
    PolicyRepository::current_state_version(
        &mut **tx,
        principal.organization_id,
        path.project_id,
        path.application_id,
    )
    .await
    .map_err(|e| PolicyApiError::database(&e, request_id))
}

#[allow(clippy::too_many_lines)]
async fn create_suppression(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ApplicationPath>,
    Json(mut input): Json<SuppressionInput>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    ensure_application(&state, principal, path, &request_id).await?;
    let normalized_reason = input.reason.trim().to_owned();
    input.reason = normalized_reason;
    input
        .placement
        .normalize()
        .map_err(|m| PolicyApiError::invalid(m, &request_id))?;
    let now = Utc::now();
    if !(1..=500).contains(&input.reason.chars().count())
        || input.expires_at <= now
        || input.expires_at > now + chrono::Duration::days(90)
    {
        return Err(PolicyApiError::invalid(
            "suppression requires a reason and an expiry within 90 days",
            &request_id,
        ));
    }
    let key = idempotency_key(&headers, &request_id)?;
    let digest = request_digest(&input).unwrap();
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    if let Some(result) = begin_command(
        &mut tx,
        principal.organization_id,
        key,
        &digest,
        &request_id,
    )
    .await?
    {
        return Ok(Json(result));
    }
    let mut seed = RevisionInput {
        source_inventory_item_id: input.source_inventory_item_id,
        source_runtime_group_id: input.source_runtime_group_id,
        placement: input.placement.clone(),
        inside_effect: PolicyEffect::Expected,
        outside_effect: None,
    };
    let identity = load_revision_identity(&mut tx, principal, path, &mut seed, &request_id).await?;
    let behavior = BehaviorIdentity::from_inventory(
        &identity.inventory_kind,
        identity.identity_version,
        &identity.identity_digest,
        &identity.semantic_summary,
    )
    .map_err(|_| PolicyApiError::invalid("invalid inventory identity", &request_id))?;
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
    .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    let version = current_policy_state(&mut tx, principal, path, &request_id).await?;
    let result = MutationResult {
        resource_id: id,
        revision_id: None,
        recomputation_id: None,
        policy_state_version: version,
    };
    record_command(
        &mut tx,
        principal,
        path,
        key,
        "suppress",
        &digest,
        &result,
        id,
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    Ok(Json(result))
}

async fn cancel_suppression(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<SuppressionPath>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let principal = principal(&headers, &state, path.project_id, &request_id).await?;
    let key = idempotency_key(&headers, &request_id)?;
    let digest = request_digest(&path.suppression_id).unwrap();
    let app = ApplicationPath {
        project_id: path.project_id,
        application_id: path.application_id,
    };
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    if let Some(result) = begin_command(
        &mut tx,
        principal.organization_id,
        key,
        &digest,
        &request_id,
    )
    .await?
    {
        return Ok(Json(result));
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
    .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    if updated.rows_affected() == 0 {
        return Err(PolicyApiError::not_found(&request_id));
    }
    let version = current_policy_state(&mut tx, principal, app, &request_id).await?;
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
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| PolicyApiError::database(&e, &request_id))?;
    Ok(Json(result))
}
