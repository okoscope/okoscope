use crate::error_code::ErrorCode;
use crate::repository::event_groups::EventGroupRepository;
use crate::repository::events::EventRepository;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use std::collections::HashMap;
use uuid::Uuid;

use crate::repository::{ApplicationRepository, ProjectRepository};
use crate::{
    access_control::resolve_project_access,
    auth::{IdentityPrincipal, UserSessionAuthenticator},
};

#[derive(Clone, Debug)]
struct ApiState {
    pool: PgPool,
    authenticator: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = ApiState {
        authenticator: UserSessionAuthenticator::new(pool.clone()),
        pool,
    };
    Router::new()
        .route("/api/v1/runtime-groups", get(list_groups))
        .route("/api/v1/runtime-groups/{group_id}", get(get_group))
        .route(
            "/api/v1/runtime-groups/{group_id}/snapshots",
            get(list_snapshots),
        )
        .route(
            "/api/v1/runtime-groups/{group_id}/occurrences",
            get(list_occurrences),
        )
        .route(
            "/api/v1/runtime-groups/{group_id}/acknowledge",
            post(acknowledge_group),
        )
        .route(
            "/api/v1/runtime-groups/{group_id}/resolve",
            post(resolve_group),
        )
        .route(
            "/api/v1/runtime-groups/{group_id}/reopen",
            post(reopen_group),
        )
        .with_state(state)
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Invalid(String),
    NotFound,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential".to_owned(),
            ),
            Self::Invalid(message) => {
                (StatusCode::BAD_REQUEST, ErrorCode::INVALID_REQUEST, message)
            }
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "runtime group not found".to_owned(),
            ),
            Self::Database(error) => {
                tracing::error!(error = %error, "runtime groups API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error".to_owned(),
                )
            }
        };
        crate::web_api::uncorrelated_error_response(status, code, message)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ListQuery {
    project_id: Uuid,
    application_id: Uuid,
    event_kind: Option<String>,
    status: Option<String>,
    namespace: Option<String>,
    workload_kind: Option<String>,
    workload_name: Option<String>,
    since: Option<DateTime<Utc>>,
    first_seen_from: Option<DateTime<Utc>>,
    first_seen_to: Option<DateTime<Utc>>,
    last_seen_to: Option<DateTime<Utc>>,
    release_id: Option<Uuid>,
    verdict: Option<String>,
    suppressed: Option<bool>,
    evaluation_pending: Option<bool>,
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct GroupSummary {
    id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
    fingerprint_version: i16,
    event_kind: String,
    semantic_summary: Value,
    #[sqlx(skip)]
    user_labels: Vec<Value>,
    status: String,
    first_seen_at: DateTime<Utc>,
    first_seen_event_id: Option<Uuid>,
    last_seen_at: DateTime<Utc>,
    occurrence_count: i64,
    representative_event_id: Option<Uuid>,
    status_changed_at: Option<DateTime<Utc>>,
    status_changed_by: Option<Uuid>,
    #[sqlx(skip)]
    policy_evaluation: Value,
    #[sqlx(skip)]
    active_suppression: Option<Value>,
    #[sqlx(skip)]
    actionable: bool,
    #[sqlx(skip)]
    coverage: crate::runtime_retention::history::Coverage,
}

#[derive(FromRow)]
struct GroupUserLabels {
    group_id: Uuid,
    user_labels: Value,
}

async fn attach_group_user_labels(
    pool: &PgPool,
    organization_id: Uuid,
    groups: &mut [GroupSummary],
) -> Result<(), sqlx::Error> {
    let ids: Vec<_> = groups.iter().map(|group| group.id).collect();
    let rows: Vec<GroupUserLabels> =
        EventGroupRepository::user_labels(pool, organization_id, ids).await?;
    let labels: HashMap<_, _> = rows
        .into_iter()
        .map(|row| (row.group_id, row.user_labels))
        .collect();
    for group in groups {
        group.user_labels = labels
            .get(&group.id)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        group.user_labels.truncate(20);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct GroupList {
    items: Vec<GroupSummary>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, FromRow, Serialize)]
struct EventOccurrence {
    id: Uuid,
    event_id: Uuid,
    observed_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    node_name: String,
    namespace: String,
    pod_name: String,
    container_name: String,
    process_command: String,
    event_kind: String,
    payload: Value,
    correlation: Value,
    #[sqlx(skip)]
    related_evidence: Vec<RelatedEvidence>,
    release_id: Option<Uuid>,
    release_version: Option<String>,
    release_display_name: String,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct RelatedEvidence {
    id: Uuid,
    event_id: Uuid,
    observed_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    event_kind: String,
    source: String,
    payload: Value,
}

#[derive(Debug, Serialize)]
struct OccurrencePage {
    items: Vec<EventOccurrence>,
    next_cursor: Option<Uuid>,
    ordering: &'static str,
}

#[derive(Debug, FromRow, Serialize)]
struct NotificationSummary {
    state: String,
    delivery_count: i64,
    succeeded_count: i64,
    failed_count: i64,
}

#[derive(Debug, Serialize)]
struct GroupDetail {
    #[serde(flatten)]
    group: GroupSummary,
    representative_event: Option<EventOccurrence>,
    notification: NotificationSummary,
}

async fn principal(headers: &HeaderMap, state: &ApiState) -> Result<IdentityPrincipal, ApiError> {
    state
        .authenticator
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)
}

async fn project_organization(
    state: &ApiState,
    principal: IdentityPrincipal,
    project_id: Uuid,
) -> Result<Uuid, ApiError> {
    let organization_id: Uuid = ProjectRepository::organization_of(&state.pool, project_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    resolve_project_access(&state.pool, principal, organization_id, project_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(organization_id)
}

async fn group_scope(
    state: &ApiState,
    principal: IdentityPrincipal,
    group_id: Uuid,
) -> Result<(Uuid, Uuid), ApiError> {
    let scope = crate::repository::EventGroupRepository::tenant_of(&state.pool, group_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    resolve_project_access(&state.pool, principal, scope.0, scope.1)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(scope)
}

async fn ensure_application(
    state: &ApiState,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(), ApiError> {
    let exists =
        ApplicationRepository::exists(&state.pool, organization_id, project_id, application_id)
            .await?;
    exists.then_some(()).ok_or(ApiError::NotFound)
}

#[derive(FromRow)]
struct GroupPolicyRow {
    group_id: Uuid,
    policy_evaluation: Value,
    active_suppression: Option<Value>,
    actionable: bool,
}

async fn attach_group_policy(
    pool: &PgPool,
    organization_id: Uuid,
    groups: &mut [GroupSummary],
) -> Result<(), sqlx::Error> {
    if groups.is_empty() {
        return Ok(());
    }
    let ids = groups.iter().map(|group| group.id).collect::<Vec<_>>();
    let rows = EventGroupRepository::policy_states::<_, GroupPolicyRow>(
        pool,
        organization_id,
        &ids,
        crate::policy::POLICY_EVALUATOR_VERSION,
    )
    .await?;
    let by_id = rows
        .into_iter()
        .map(|row| (row.group_id, row))
        .collect::<std::collections::HashMap<_, _>>();
    for group in groups {
        if let Some(row) = by_id.get(&group.id) {
            group.policy_evaluation = row.policy_evaluation.clone();
            group.active_suppression = row.active_suppression.clone();
            group.actionable = row.actionable;
        }
    }
    Ok(())
}

async fn list_groups(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<GroupList>, ApiError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let organization_id = project_organization(&state, principal, query.project_id).await?;
    ensure_application(
        &state,
        organization_id,
        query.project_id,
        query.application_id,
    )
    .await?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::Invalid("limit must be between 1 and 200".into()));
    }
    if query
        .status
        .as_deref()
        .is_some_and(|status| !matches!(status, "open" | "acknowledged" | "resolved"))
    {
        return Err(ApiError::Invalid("unsupported status".into()));
    }
    if query.verdict.as_deref().is_some_and(|verdict| {
        !matches!(
            verdict,
            "unclassified" | "expected" | "requires_review" | "policy_conflict"
        )
    }) {
        return Err(ApiError::Invalid("unsupported policy verdict".into()));
    }
    let cursor = if let Some(cursor) = query.cursor {
        let position = EventGroupRepository::list_cursor(
            &state.pool,
            cursor,
            organization_id,
            query.project_id,
            query.application_id,
        )
        .await?
        .ok_or_else(|| ApiError::Invalid("cursor does not exist in this scope".into()))?;
        Some(position)
    } else {
        None
    };
    let (cursor_time, cursor_id) = cursor.unzip();
    let mut items = EventGroupRepository::summary_page::<_, GroupSummary>(
        &state.pool,
        organization_id,
        query.project_id,
        query.application_id,
        query.event_kind,
        query.status,
        query.namespace,
        query.workload_kind,
        query.workload_name,
        query.since,
        query.first_seen_from,
        query.first_seen_to,
        query.last_seen_to,
        query.release_id,
        cursor_time,
        cursor_id,
        limit + 1,
    )
    .await?;
    attach_group_policy(&state.pool, organization_id, &mut items).await?;
    attach_group_user_labels(&state.pool, organization_id, &mut items).await?;
    items.retain(|group| {
        query.verdict.as_ref().is_none_or(|verdict| {
            group.policy_evaluation["verdict"].as_str() == Some(verdict.as_str())
        }) && query
            .suppressed
            .is_none_or(|suppressed| group.active_suppression.is_some() == suppressed)
            && query.evaluation_pending.is_none_or(|pending| {
                (group.policy_evaluation["state"] == "evaluation_pending") == pending
            })
    });
    let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
        items.pop();
        items.last().map(|group| group.id)
    } else {
        None
    };
    let coverage =
        crate::runtime_retention::history::coverage(&state.pool, organization_id, query.project_id)
            .await?;
    for item in &mut items {
        item.coverage = coverage.clone();
    }
    Ok(Json(GroupList { items, next_cursor }))
}

async fn get_group(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupDetail>, ApiError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let (organization_id, _) = group_scope(&state, principal, group_id).await?;
    let mut group =
        EventGroupRepository::summary::<_, GroupSummary>(&state.pool, organization_id, group_id)
            .await?
            .ok_or(ApiError::NotFound)?;
    attach_group_policy(
        &state.pool,
        organization_id,
        std::slice::from_mut(&mut group),
    )
    .await?;
    attach_group_user_labels(
        &state.pool,
        organization_id,
        std::slice::from_mut(&mut group),
    )
    .await?;
    group.coverage =
        crate::runtime_retention::history::coverage(&state.pool, organization_id, group.project_id)
            .await?;
    let mut representative_event = match group.representative_event_id {
        Some(id) => event_by_id(&state.pool, organization_id, id).await?,
        None => None,
    };
    if let Some(event) = &mut representative_event {
        if group.event_kind == "container.restart_loop" {
            event.event_kind.clone_from(&group.event_kind);
            event.payload =
                serde_json::json!({"type":"ContainerRestartLoop","data":group.semantic_summary});
        }
        event.related_evidence = load_related_evidence(
            &state.pool,
            organization_id,
            group_id,
            event.id,
            &event.event_kind,
        )
        .await?;
    }
    let notification = notification_summary(&state.pool, organization_id, group_id).await?;
    Ok(Json(GroupDetail {
        group,
        representative_event,
        notification,
    }))
}

#[derive(Debug, Deserialize)]
struct OccurrenceQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

async fn list_occurrences(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Query(query): Query<OccurrenceQuery>,
) -> Result<Json<OccurrencePage>, ApiError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let (organization_id, _) = group_scope(&state, principal, group_id).await?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::Invalid("limit must be between 1 and 200".into()));
    }
    let cursor = if let Some(cursor) = query.cursor {
        Some(
            EventGroupRepository::occurrence_cursor(&state.pool, organization_id, group_id, cursor)
                .await?
                .ok_or_else(|| ApiError::Invalid("cursor does not exist in this scope".into()))?,
        )
    } else {
        None
    };
    let (cursor_received_at, cursor_observed_at, cursor_id) = cursor
        .map_or((None, None, None), |(received_at, observed_at, id)| {
            (Some(received_at), Some(observed_at), Some(id))
        });
    let mut items = EventGroupRepository::occurrence_page::<_, EventOccurrence>(
        &state.pool,
        organization_id,
        group_id,
        cursor_received_at,
        cursor_observed_at,
        cursor_id,
        limit + 1,
    )
    .await?;
    for occurrence in &mut items {
        occurrence.related_evidence = load_related_evidence(
            &state.pool,
            organization_id,
            group_id,
            occurrence.id,
            &occurrence.event_kind,
        )
        .await?;
    }
    let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
        items.pop();
        items.last().map(|event| event.id)
    } else {
        None
    };
    Ok(Json(OccurrencePage {
        items,
        next_cursor,
        ordering: "received_at_desc_observed_at_desc_id_desc",
    }))
}

async fn acknowledge_group(
    state: State<ApiState>,
    headers: HeaderMap,
    path: Path<Uuid>,
) -> Result<Json<GroupSummary>, ApiError> {
    transition_group(state, headers, path, "acknowledged", &["open"]).await
}

async fn resolve_group(
    state: State<ApiState>,
    headers: HeaderMap,
    path: Path<Uuid>,
) -> Result<Json<GroupSummary>, ApiError> {
    transition_group(state, headers, path, "resolved", &["open", "acknowledged"]).await
}

async fn reopen_group(
    state: State<ApiState>,
    headers: HeaderMap,
    path: Path<Uuid>,
) -> Result<Json<GroupSummary>, ApiError> {
    transition_group(state, headers, path, "open", &["acknowledged", "resolved"]).await
}

async fn transition_group(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    target: &'static str,
    allowed: &'static [&'static str],
) -> Result<Json<GroupSummary>, ApiError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let (organization_id, _) = group_scope(&state, principal, group_id).await?;
    let group = EventGroupRepository::set_status::<_, GroupSummary>(
        &state.pool,
        organization_id,
        group_id,
        target,
        principal.user_id,
        allowed,
    )
    .await?;
    if let Some(mut group) = group {
        attach_group_policy(
            &state.pool,
            organization_id,
            std::slice::from_mut(&mut group),
        )
        .await?;
        attach_group_user_labels(
            &state.pool,
            organization_id,
            std::slice::from_mut(&mut group),
        )
        .await?;
        return Ok(Json(group));
    }
    let current: Option<String> =
        EventGroupRepository::status(&state.pool, organization_id, group_id).await?;
    match current {
        None => Err(ApiError::NotFound),
        Some(current) => Err(ApiError::Invalid(format!(
            "cannot transition runtime group from {current} to {target}"
        ))),
    }
}

async fn notification_summary(
    pool: &PgPool,
    organization_id: Uuid,
    group_id: Uuid,
) -> Result<NotificationSummary, sqlx::Error> {
    let summary = EventGroupRepository::notification_summary::<_, NotificationSummary>(
        pool,
        organization_id,
        group_id,
    )
    .await?;
    Ok(summary.unwrap_or_else(|| NotificationSummary {
        state: "not_configured".into(),
        delivery_count: 0,
        succeeded_count: 0,
        failed_count: 0,
    }))
}

async fn event_by_id(
    pool: &PgPool,
    organization_id: Uuid,
    event_id: Uuid,
) -> Result<Option<EventOccurrence>, sqlx::Error> {
    EventRepository::occurrence::<_, EventOccurrence>(pool, organization_id, event_id).await
}

const RELATED_EVIDENCE_LIMIT: i64 = 20;

async fn load_related_evidence(
    pool: &PgPool,
    organization_id: Uuid,
    group_id: Uuid,
    event_id: Uuid,
    event_kind: &str,
) -> Result<Vec<RelatedEvidence>, sqlx::Error> {
    if event_kind == "container.restart_loop" {
        return EventGroupRepository::related_evidence::<_, RelatedEvidence>(
            pool,
            organization_id,
            group_id,
            RELATED_EVIDENCE_LIMIT,
        )
        .await;
    }
    EventRepository::related_evidence::<_, RelatedEvidence>(
        pool,
        organization_id,
        event_id,
        RELATED_EVIDENCE_LIMIT,
    )
    .await
}

async fn list_snapshots(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Query(query): Query<crate::runtime_retention::history::Query>,
) -> Result<Json<crate::runtime_retention::history::Page>, ApiError> {
    let principal = principal(&headers, &state).await?;
    let (organization_id, project) = group_scope(&state, principal, group_id).await?;
    if query
        .day_from
        .zip(query.day_to)
        .is_some_and(|(from, to)| from >= to)
    {
        return Err(ApiError::Invalid("day_from must precede day_to".into()));
    }
    Ok(Json(
        crate::runtime_retention::history::page(
            &state.pool,
            organization_id,
            project,
            group_id,
            query,
        )
        .await?,
    ))
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn occurrence_contract_exposes_receive_order_and_bounded_related_evidence() {
        assert_eq!(RELATED_EVIDENCE_LIMIT, 20);
        let now = Utc::now();
        let occurrence = EventOccurrence {
            id: Uuid::from_u128(1),
            event_id: Uuid::from_u128(2),
            observed_at: now - chrono::Duration::seconds(5),
            received_at: now,
            node_name: "node".into(),
            namespace: "default".into(),
            pod_name: "pod".into(),
            container_name: "worker".into(),
            process_command: "worker".into(),
            event_kind: "container.restart_loop".into(),
            payload: serde_json::json!({
                "type": "ContainerRestartLoop",
                "data": {"evidence_source": "derived", "projection_version": 1}
            }),
            correlation: serde_json::json!({"status": "absent", "candidate_count": 0}),
            related_evidence: Vec::new(),
            release_id: None,
            release_version: None,
            release_display_name: "Unattributed".into(),
        };
        let page = OccurrencePage {
            items: vec![occurrence],
            next_cursor: None,
            ordering: "received_at_desc_observed_at_desc_id_desc",
        };
        let value = serde_json::to_value(page).unwrap();
        assert!(value["items"][0]["received_at"].is_string());
        assert_eq!(value["items"][0]["related_evidence"], serde_json::json!([]));
        assert_eq!(value["items"][0]["payload"]["type"], "ContainerRestartLoop");
        assert_eq!(
            value["ordering"],
            "received_at_desc_observed_at_desc_id_desc"
        );
    }
}
