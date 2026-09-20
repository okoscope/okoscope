use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    access_control::resolve_project_access,
    auth::{IdentityPrincipal, UserSessionAuthenticator},
};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;
const MAX_SCOPE_HOURS: i64 = 24 * 31;

#[derive(Clone, Debug)]
struct ApiState {
    pool: PgPool,
    auth: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = ApiState {
        auth: UserSessionAuthenticator::new(pool.clone()),
        pool,
    };
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/thread-activity",
            get(list_windows),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/thread-activity/summary",
            get(summary),
        )
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct ScopeQuery {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    process_generation: Option<i64>,
    observation_epoch: Option<Uuid>,
    limit: Option<i64>,
    cursor: Option<Uuid>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct WindowRow {
    id: Uuid,
    process_cgroup_id: i64,
    process_pid: i64,
    process_tgid: i64,
    process_command: String,
    process_generation: i64,
    observation_epoch: Uuid,
    start_observed: bool,
    window_started_at: DateTime<Utc>,
    window_ended_at: DateTime<Utc>,
    created_count: i64,
    exited_count: i64,
    active_at_start: i64,
    active_at_end: i64,
    peak_active: i64,
    baseline_provenance: String,
    baseline_complete: bool,
    name_overflow: i64,
    names: Value,
    gaps: Value,
}

#[derive(Debug, Serialize)]
struct WindowPage {
    items: Vec<WindowRow>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct ThreadSummary {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    window_count: i64,
    truncated: bool,
    created: i64,
    exited: i64,
    active: Option<i64>,
    peak_active: Option<i64>,
    baseline_complete: bool,
    baseline_provenance: Option<String>,
    name_overflow: i64,
    names: Value,
    gaps: Value,
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Invalid(&'static str),
    NotFound,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for ApiError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid or missing bearer credential",
            ),
            Self::Invalid(message) => (StatusCode::BAD_REQUEST, "invalid_request", message),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "thread activity resource not found",
            ),
            Self::Database(error) => {
                tracing::error!(%error, "thread activity API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error",
                )
            }
        };
        (status, Json(json!({"error":code,"message":message}))).into_response()
    }
}

async fn authorize(
    headers: &HeaderMap,
    state: &ApiState,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<Uuid, ApiError> {
    let identity: IdentityPrincipal = state
        .auth
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let organization_id: Uuid =
        sqlx::query_scalar("SELECT organization_id FROM projects WHERE id=$1")
            .bind(project_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    resolve_project_access(&state.pool, identity, organization_id, project_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications WHERE organization_id=$1 AND project_id=$2 AND id=$3)")
        .bind(organization_id).bind(project_id).bind(application_id).fetch_one(&state.pool).await?;
    exists.then_some(organization_id).ok_or(ApiError::NotFound)
}

fn scope(query: &ScopeQuery) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let to = query.to.unwrap_or_else(Utc::now);
    let from = query.from.unwrap_or(to - Duration::hours(1));
    if from >= to || to - from > Duration::hours(MAX_SCOPE_HOURS) {
        return Err(ApiError::Invalid(
            "time scope must be positive and no longer than 31 days",
        ));
    }
    if query.process_generation.is_some() != query.observation_epoch.is_some() {
        return Err(ApiError::Invalid(
            "process_generation and observation_epoch must be supplied together",
        ));
    }
    Ok((from, to))
}

fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

async fn list_windows(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<ScopeQuery>,
) -> Result<(HeaderMap, Json<WindowPage>), ApiError> {
    let organization_id = authorize(&headers, &state, project_id, application_id).await?;
    let (from, to) = scope(&query)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let mut items: Vec<WindowRow> = sqlx::query_as(
        "SELECT id,process_cgroup_id,process_pid,process_tgid,process_command,process_generation,observation_epoch,start_observed,window_started_at,window_ended_at,created_count,exited_count,active_at_start,active_at_end,peak_active,baseline_provenance,baseline_complete,name_overflow,names,gaps FROM thread_activity_windows WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND window_started_at >= $4 AND window_ended_at <= $5 AND ($6::bigint IS NULL OR process_generation=$6) AND ($7::uuid IS NULL OR observation_epoch=$7) AND ($8::uuid IS NULL OR (window_started_at,id) < (SELECT window_started_at,id FROM thread_activity_windows WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$8)) ORDER BY window_started_at DESC,id DESC LIMIT $9",
    ).bind(organization_id).bind(project_id).bind(application_id).bind(from).bind(to)
        .bind(query.process_generation).bind(query.observation_epoch).bind(query.cursor).bind(limit + 1)
        .fetch_all(&state.pool).await?;
    let limit = usize::try_from(limit).expect("positive bounded limit");
    let has_more = items.len() > limit;
    items.truncate(limit);
    let next_cursor = has_more.then(|| items.last().expect("non-empty page").id);
    Ok((no_store(), Json(WindowPage { items, next_cursor })))
}

async fn summary(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<ScopeQuery>,
) -> Result<(HeaderMap, Json<ThreadSummary>), ApiError> {
    let organization_id = authorize(&headers, &state, project_id, application_id).await?;
    let (from, to) = scope(&query)?;
    let mut rows: Vec<WindowRow> = sqlx::query_as(
        "SELECT id,process_cgroup_id,process_pid,process_tgid,process_command,process_generation,observation_epoch,start_observed,window_started_at,window_ended_at,created_count,exited_count,active_at_start,active_at_end,peak_active,baseline_provenance,baseline_complete,name_overflow,names,gaps FROM thread_activity_windows WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND window_started_at >= $4 AND window_ended_at <= $5 AND ($6::bigint IS NULL OR process_generation=$6) AND ($7::uuid IS NULL OR observation_epoch=$7) ORDER BY window_started_at,id LIMIT 10001",
    ).bind(organization_id).bind(project_id).bind(application_id).bind(from).bind(to)
        .bind(query.process_generation).bind(query.observation_epoch).fetch_all(&state.pool).await?;
    let truncated = rows.len() > 10_000;
    rows.truncate(10_000);
    let latest = rows.last();
    let mut gaps = rows
        .iter()
        .flat_map(|row| row.gaps.as_array().into_iter().flatten())
        .cloned()
        .collect::<Vec<_>>();
    gaps.sort_by_key(Value::to_string);
    gaps.dedup();
    let response = ThreadSummary {
        from,
        to,
        window_count: i64::try_from(rows.len()).expect("query result is bounded to 10000 rows"),
        truncated,
        created: rows.iter().map(|row| row.created_count).sum(),
        exited: rows.iter().map(|row| row.exited_count).sum(),
        active: latest.map(|row| row.active_at_end),
        peak_active: rows.iter().map(|row| row.peak_active).max(),
        baseline_complete: !truncated
            && !rows.is_empty()
            && rows
                .iter()
                .all(|row| row.baseline_complete && row.gaps == json!([])),
        baseline_provenance: latest.map(|row| row.baseline_provenance.clone()),
        name_overflow: rows.iter().map(|row| row.name_overflow).sum(),
        names: latest.map_or_else(|| json!([]), |row| row.names.clone()),
        gaps: json!(gaps),
    };
    Ok((no_store(), Json(response)))
}
