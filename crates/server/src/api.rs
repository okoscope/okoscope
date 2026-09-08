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
use uuid::Uuid;

use crate::auth::{UserPrincipal, UserSessionAuthenticator};

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
                "unauthorized",
                "invalid or missing bearer credential".to_owned(),
            ),
            Self::Invalid(message) => (StatusCode::BAD_REQUEST, "invalid_request", message),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "runtime group not found".to_owned(),
            ),
            Self::Database(error) => {
                tracing::error!(error = %error, "runtime groups API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".to_owned(),
                )
            }
        };
        (
            status,
            Json(ErrorBody {
                error: code,
                message,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
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

async fn principal(headers: &HeaderMap, state: &ApiState) -> Result<UserPrincipal, ApiError> {
    state
        .authenticator
        .authenticate_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)
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
    let rows = sqlx::query_as::<_, GroupPolicyRow>(
        "SELECT g.id group_id,jsonb_build_object('state',CASE WHEN e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3 THEN 'evaluation_pending' ELSE 'current' END,'verdict',CASE WHEN e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3 THEN NULL ELSE e.verdict END,'reason_code',CASE WHEN e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3 THEN 'evaluation_pending' ELSE e.reason_code END,'winning_revision_id',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 THEN e.winning_revision_id END,'explanation',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 THEN e.explanation ELSE '{}'::jsonb END,'evaluated_at',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 THEN e.evaluated_at END) policy_evaluation,s.summary active_suppression,(s.summary IS NULL AND (e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3 OR e.verdict<>'expected')) actionable FROM runtime_event_groups g LEFT JOIN runtime_group_policy_evaluations e ON e.group_id=g.id LEFT JOIN runtime_policy_states ps ON ps.organization_id=g.organization_id AND ps.project_id=g.project_id AND ps.application_id=g.application_id LEFT JOIN LATERAL (SELECT jsonb_build_object('id',x.id,'reason',x.reason,'expires_at',x.expires_at,'created_at',x.created_at) summary FROM runtime_inventory_group_links gl JOIN runtime_inventory_items i ON i.id=gl.item_id JOIN runtime_policy_suppressions x ON x.organization_id=i.organization_id AND x.project_id=i.project_id AND x.application_id=i.application_id AND x.identity_version=i.identity_version AND x.identity_digest=i.identity_digest WHERE gl.group_id=g.id AND x.cancelled_at IS NULL AND x.expires_at>now() AND (cardinality(x.cluster_ids)=0 OR g.cluster_id=ANY(x.cluster_ids)) AND (cardinality(x.namespaces)=0 OR g.namespace=ANY(x.namespaces)) AND (cardinality(x.workload_kinds)=0 OR g.workload_kind=ANY(x.workload_kinds)) AND (cardinality(x.workload_names)=0 OR g.workload_name=ANY(x.workload_names)) ORDER BY (cardinality(x.cluster_ids)>0)::int+(cardinality(x.namespaces)>0)::int+(cardinality(x.workload_kinds)>0)::int+(cardinality(x.workload_names)>0)::int DESC,x.expires_at,x.id LIMIT 1) s ON true WHERE g.organization_id=$1 AND g.id=ANY($2)",
    )
    .bind(organization_id)
    .bind(&ids)
    .bind(crate::policy::POLICY_EVALUATOR_VERSION)
    .fetch_all(pool)
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
        let position = sqlx::query_as::<_, (DateTime<Utc>, Uuid)>(
            "SELECT last_seen_at,id FROM runtime_event_groups WHERE id=$1 AND organization_id=$2 AND project_id=$3 AND application_id=$4",
        )
        .bind(cursor)
        .bind(principal.organization_id)
        .bind(query.project_id)
        .bind(query.application_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| ApiError::Invalid("cursor does not exist in this scope".into()))?;
        Some(position)
    } else {
        None
    };
    let (cursor_time, cursor_id) = cursor.unzip();
    let mut items = sqlx::query_as::<_, GroupSummary>(
        "SELECT id,project_id,application_id,cluster_id,namespace,workload_kind,workload_name,fingerprint_version,event_kind,semantic_summary,status,first_seen_at,first_seen_event_id,last_seen_at,occurrence_count,representative_event_id,status_changed_at,status_changed_by_user_id AS status_changed_by FROM runtime_event_groups g WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND ($4::text IS NULL OR event_kind=$4) AND ($5::text IS NULL OR status=$5) AND ($6::text IS NULL OR namespace=$6) AND ($7::text IS NULL OR workload_kind=$7) AND ($8::text IS NULL OR workload_name=$8) AND ($9::timestamptz IS NULL OR last_seen_at >= $9) AND ($10::timestamptz IS NULL OR first_seen_at >= $10) AND ($11::timestamptz IS NULL OR first_seen_at <= $11) AND ($12::timestamptz IS NULL OR last_seen_at <= $12) AND ($13::uuid IS NULL OR EXISTS (SELECT 1 FROM runtime_event_group_releases gr WHERE gr.group_id=g.id AND gr.release_id=$13)) AND ($14::timestamptz IS NULL OR (last_seen_at,id) < ($14,$15)) ORDER BY last_seen_at DESC,id DESC LIMIT $16",
    )
    .bind(principal.organization_id).bind(query.project_id).bind(query.application_id)
    .bind(query.event_kind).bind(query.status).bind(query.namespace).bind(query.workload_kind).bind(query.workload_name)
    .bind(query.since).bind(query.first_seen_from).bind(query.first_seen_to).bind(query.last_seen_to)
    .bind(query.release_id).bind(cursor_time).bind(cursor_id).bind(limit + 1)
    .fetch_all(&state.pool).await?;
    attach_group_policy(&state.pool, principal.organization_id, &mut items).await?;
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
    let coverage = crate::runtime_retention::history::coverage(
        &state.pool,
        principal.organization_id,
        query.project_id,
    )
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
    let mut group = sqlx::query_as::<_, GroupSummary>(
        "SELECT id,project_id,application_id,cluster_id,namespace,workload_kind,workload_name,fingerprint_version,event_kind,semantic_summary,status,first_seen_at,first_seen_event_id,last_seen_at,occurrence_count,representative_event_id,status_changed_at,status_changed_by_user_id AS status_changed_by FROM runtime_event_groups WHERE organization_id=$1 AND id=$2",
    )
    .bind(principal.organization_id).bind(group_id).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    attach_group_policy(
        &state.pool,
        principal.organization_id,
        std::slice::from_mut(&mut group),
    )
    .await?;
    group.coverage = crate::runtime_retention::history::coverage(
        &state.pool,
        principal.organization_id,
        group.project_id,
    )
    .await?;
    let mut representative_event = match group.representative_event_id {
        Some(id) => event_by_id(&state.pool, principal.organization_id, id).await?,
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
            principal.organization_id,
            group_id,
            event.id,
            &event.event_kind,
        )
        .await?;
    }
    let notification =
        notification_summary(&state.pool, principal.organization_id, group_id).await?;
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
    let limit = query.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::Invalid("limit must be between 1 and 200".into()));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM runtime_event_groups WHERE organization_id=$1 AND id=$2)",
    )
    .bind(principal.organization_id)
    .bind(group_id)
    .fetch_one(&state.pool)
    .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    let cursor = if let Some(cursor) = query.cursor {
        Some(
            sqlx::query_as::<_, (DateTime<Utc>, DateTime<Utc>, Uuid)>(
                "SELECT e.received_at,e.observed_at,e.id FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.organization_id=$1 AND m.group_id=$2 AND e.id=$3",
            )
            .bind(principal.organization_id)
            .bind(group_id)
            .bind(cursor)
            .fetch_optional(&state.pool)
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
    let mut items = sqlx::query_as::<_, EventOccurrence>(
        "SELECT e.id,e.event_id,e.observed_at,e.received_at,e.node_name,e.namespace,e.pod_name,e.container_name,e.process_command,CASE WHEN g.event_kind='container.restart_loop' THEN g.event_kind ELSE e.event_kind END event_kind,CASE WHEN g.event_kind='container.restart_loop' THEN jsonb_build_object('type','ContainerRestartLoop','data',g.semantic_summary) ELSE e.payload END payload,COALESCE((SELECT jsonb_build_object('retention_incomplete',o.retention_incomplete,'status',o.status,'candidate_count',o.candidate_count,'tolerance_seconds',o.tolerance_seconds,'related_event_ids',COALESCE((SELECT jsonb_agg(c.kernel_event_id) FROM runtime_event_correlations c WHERE c.lifecycle_event_id=e.id),'[]'::jsonb)) FROM runtime_event_correlation_outcomes o WHERE o.event_id=e.id),jsonb_build_object('status','absent','candidate_count',0,'related_event_ids','[]'::jsonb)) correlation,e.release_id,r.version release_version,CASE WHEN r.id IS NULL THEN 'Unattributed' ELSE release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) END release_display_name FROM runtime_event_group_memberships m JOIN runtime_event_groups g ON g.id=m.group_id AND g.organization_id=m.organization_id JOIN runtime_events e ON e.id=m.event_id AND e.organization_id=m.organization_id LEFT JOIN releases r ON r.id=e.release_id LEFT JOIN applications a ON a.id=r.application_id WHERE m.organization_id=$1 AND m.group_id=$2 AND ($3::timestamptz IS NULL OR (e.received_at,e.observed_at,e.id)<($3,$4,$5)) ORDER BY e.received_at DESC,e.observed_at DESC,e.id DESC LIMIT $6",
    )
    .bind(principal.organization_id)
    .bind(group_id)
    .bind(cursor_received_at)
    .bind(cursor_observed_at)
    .bind(cursor_id)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;
    for occurrence in &mut items {
        occurrence.related_evidence = load_related_evidence(
            &state.pool,
            principal.organization_id,
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
    let group = sqlx::query_as::<_, GroupSummary>(
        "UPDATE runtime_event_groups SET status=$3,status_changed_at=CASE WHEN status=$3 THEN status_changed_at ELSE now() END,status_changed_by_user_id=CASE WHEN status=$3 THEN status_changed_by_user_id ELSE $4 END,status_changed_by_kind=CASE WHEN status=$3 THEN status_changed_by_kind ELSE 'user' END,updated_at=CASE WHEN status=$3 THEN updated_at ELSE now() END WHERE organization_id=$1 AND id=$2 AND (status=$3 OR status=ANY($5)) RETURNING id,project_id,application_id,cluster_id,namespace,workload_kind,workload_name,fingerprint_version,event_kind,semantic_summary,status,first_seen_at,first_seen_event_id,last_seen_at,occurrence_count,representative_event_id,status_changed_at,status_changed_by_user_id AS status_changed_by",
    )
    .bind(principal.organization_id)
    .bind(group_id)
    .bind(target)
    .bind(principal.user_id)
    .bind(allowed)
    .fetch_optional(&state.pool)
    .await?;
    if let Some(mut group) = group {
        attach_group_policy(
            &state.pool,
            principal.organization_id,
            std::slice::from_mut(&mut group),
        )
        .await?;
        return Ok(Json(group));
    }
    let current: Option<String> = sqlx::query_scalar(
        "SELECT status FROM runtime_event_groups WHERE organization_id=$1 AND id=$2",
    )
    .bind(principal.organization_id)
    .bind(group_id)
    .fetch_optional(&state.pool)
    .await?;
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
    let summary = sqlx::query_as::<_, NotificationSummary>(
        "SELECT CASE WHEN o.completion_reason='expected' THEN 'policy_expected' WHEN o.completion_reason='active_suppression' THEN 'temporary_policy_suppressed' WHEN o.completion_reason='backfill_suppressed' OR o.source='backfill' AND count(d.id) FILTER(WHERE d.status<>'suppressed')=0 THEN 'backfill_suppressed' WHEN count(d.id)=0 AND o.processed_at IS NOT NULL THEN 'not_configured' WHEN count(d.id) FILTER (WHERE d.status IN ('pending','in_flight'))>0 THEN CASE WHEN count(d.id) FILTER (WHERE d.status='in_flight')>0 THEN 'delivering' ELSE 'pending' END WHEN count(d.id) FILTER (WHERE d.status='succeeded')>0 THEN 'delivered' WHEN count(d.id) FILTER (WHERE d.status IN ('failed','cancelled','suppressed'))>0 THEN 'terminally_failed' ELSE 'pending' END state,count(d.id)::bigint delivery_count,count(d.id) FILTER (WHERE d.status='succeeded')::bigint succeeded_count,count(d.id) FILTER (WHERE d.status IN ('failed','cancelled','suppressed'))::bigint failed_count FROM outbox_messages o LEFT JOIN notification_deliveries d ON d.outbox_message_id=o.id WHERE o.organization_id=$1 AND o.aggregate_id=$2 AND o.topic='runtime_group.first_seen' GROUP BY o.id,o.source,o.processed_at,o.completion_reason",
    )
    .bind(organization_id)
    .bind(group_id)
    .fetch_optional(pool)
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
    sqlx::query_as::<_, EventOccurrence>(
        "SELECT e.id,e.event_id,e.observed_at,e.received_at,e.node_name,e.namespace,e.pod_name,e.container_name,e.process_command,e.event_kind,e.payload,COALESCE((SELECT jsonb_build_object('retention_incomplete',o.retention_incomplete,'status',o.status,'candidate_count',o.candidate_count,'tolerance_seconds',o.tolerance_seconds,'related_event_ids',COALESCE((SELECT jsonb_agg(c.kernel_event_id) FROM runtime_event_correlations c WHERE c.lifecycle_event_id=e.id),'[]'::jsonb)) FROM runtime_event_correlation_outcomes o WHERE o.event_id=e.id),jsonb_build_object('status','absent','candidate_count',0,'related_event_ids','[]'::jsonb)) correlation,e.release_id,r.version release_version,CASE WHEN r.id IS NULL THEN 'Unattributed' ELSE release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) END release_display_name FROM runtime_events e LEFT JOIN releases r ON r.id=e.release_id LEFT JOIN applications a ON a.id=r.application_id WHERE e.organization_id=$1 AND e.id=$2",
    )
    .bind(organization_id).bind(event_id).fetch_optional(pool).await
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
        return sqlx::query_as::<_, RelatedEvidence>(
            "SELECT e.id,e.event_id,e.observed_at,e.received_at,e.event_kind,COALESCE(e.payload#>>'{data,source}','unknown') source,e.payload FROM runtime_restart_loop_projections p JOIN runtime_restart_projection_memberships m ON m.organization_id=p.organization_id AND m.project_id=p.project_id AND m.projection_version=p.projection_version JOIN runtime_events e ON e.id=m.event_id AND e.organization_id=p.organization_id AND e.project_id=p.project_id AND e.application_id=p.application_id AND e.cluster_id=p.cluster_id AND e.pod_uid=p.pod_uid AND e.container_name=p.container_name AND e.container_id=p.runtime_container_id AND e.observed_at BETWEEN p.window_started_at AND p.window_ended_at WHERE p.organization_id=$1 AND p.group_id=$2 ORDER BY e.observed_at,e.received_at,e.id LIMIT $3",
        )
        .bind(organization_id)
        .bind(group_id)
        .bind(RELATED_EVIDENCE_LIMIT)
        .fetch_all(pool)
        .await;
    }
    sqlx::query_as::<_, RelatedEvidence>(
        "SELECT e.id,e.event_id,e.observed_at,e.received_at,e.event_kind,COALESCE(e.payload#>>'{data,source}','unknown') source,e.payload FROM runtime_event_correlations c JOIN runtime_events e ON e.id=CASE WHEN c.lifecycle_event_id=$2 THEN c.kernel_event_id ELSE c.lifecycle_event_id END WHERE c.organization_id=$1 AND (c.lifecycle_event_id=$2 OR c.kernel_event_id=$2) ORDER BY e.observed_at,e.received_at,e.id LIMIT $3",
    )
    .bind(organization_id)
    .bind(event_id)
    .bind(RELATED_EVIDENCE_LIMIT)
    .fetch_all(pool)
    .await
}

async fn list_snapshots(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Query(query): Query<crate::runtime_retention::history::Query>,
) -> Result<Json<crate::runtime_retention::history::Page>, ApiError> {
    let principal = principal(&headers, &state).await?;
    let project: Uuid = sqlx::query_scalar(
        "SELECT project_id FROM runtime_event_groups WHERE organization_id=$1 AND id=$2",
    )
    .bind(principal.organization_id)
    .bind(group_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
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
            principal.organization_id,
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
