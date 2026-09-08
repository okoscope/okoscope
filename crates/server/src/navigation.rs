use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    auth::{UserPrincipal, UserSessionAuthenticator},
    web_api::{RequestId, error_response},
};

#[derive(Clone, Debug)]
struct StateData {
    pool: PgPool,
    auth: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = StateData {
        auth: UserSessionAuthenticator::new(pool.clone()),
        pool,
    };
    Router::new()
        .route("/api/v1/organization", get(organization))
        .route("/api/v1/projects", get(projects))
        .route("/api/v1/projects/{project_id}", get(project))
        .route(
            "/api/v1/projects/{project_id}/applications",
            get(applications),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}",
            get(application),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/workers",
            get(application_workers),
        )
        .layer(middleware::from_fn(track_navigation))
        .with_state(state)
}

async fn track_navigation(request: axum::extract::Request, next: Next) -> Response {
    let response = next.run(request).await;
    crate::metrics::record_navigation(response.status().is_success());
    response
}

#[derive(Debug)]
struct NavigationError {
    status: StatusCode,
    code: &'static str,
    message: String,
    request_id: RequestId,
}

impl NavigationError {
    fn unauthorized(request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "invalid or missing bearer credential".into(),
            request_id: request_id.clone(),
        }
    }
    fn invalid(message: impl Into<String>, request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: message.into(),
            request_id: request_id.clone(),
        }
    }
    fn not_found(request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "resource not found".into(),
            request_id: request_id.clone(),
        }
    }
    fn database(error: &sqlx::Error, request_id: &RequestId) -> Self {
        tracing::error!(error=%error, request_id=%request_id.0, "navigation API database error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "internal server error".into(),
            request_id: request_id.clone(),
        }
    }
}

impl IntoResponse for NavigationError {
    fn into_response(self) -> Response {
        error_response(self.status, self.code, self.message, &self.request_id)
    }
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

fn page_limit(limit: Option<i64>, request_id: &RequestId) -> Result<i64, NavigationError> {
    let limit = limit.unwrap_or(50);
    if (1..=200).contains(&limit) {
        Ok(limit)
    } else {
        Err(NavigationError::invalid(
            "limit must be between 1 and 200",
            request_id,
        ))
    }
}

#[derive(Debug, FromRow, Serialize)]
struct Organization {
    id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow, Serialize)]
struct ProjectSummary {
    id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
    archived_at: Option<DateTime<Utc>>,
    application_count: i64,
    runtime_group_count: i64,
}

#[derive(Debug, FromRow, Serialize)]
struct ApplicationSummary {
    id: Uuid,
    project_id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
    release_count: i64,
    runtime_group_count: i64,
    latest_observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct WorkerPageQuery {
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WorkerCursor {
    last_observed_at: DateTime<Utc>,
    agent_id: Uuid,
}

#[derive(Debug, FromRow, Serialize)]
struct ApplicationWorker {
    agent_id: Uuid,
    cluster_id: Uuid,
    cluster_name: String,
    node_name: String,
    agent_version: String,
    architecture: Option<String>,
    kernel_release: Option<String>,
    first_observed_at: DateTime<Utc>,
    last_observed_at: DateTime<Utc>,
    agent_last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct WorkerPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<ApplicationWorker>,
    next_cursor: Option<String>,
}

async fn principal(
    headers: &HeaderMap,
    state: &StateData,
    request_id: &RequestId,
) -> Result<UserPrincipal, NavigationError> {
    state
        .auth
        .authenticate_headers(headers)
        .await
        .map_err(|error| NavigationError::database(&error, request_id))?
        .ok_or_else(|| NavigationError::unauthorized(request_id))
}

async fn organization(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<Organization>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    let value = sqlx::query_as("SELECT id,slug,name,created_at FROM organizations WHERE id=$1")
        .bind(principal.organization_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|error| NavigationError::database(&error, &request_id))?
        .ok_or_else(|| NavigationError::not_found(&request_id))?;
    Ok(Json(value))
}

async fn projects(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<ProjectSummary>>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    let limit = page_limit(query.limit, &request_id)?;
    let cursor = cursor_position(
        &state.pool,
        "projects",
        principal.organization_id,
        None,
        query.cursor,
    )
    .await
    .map_err(|error| NavigationError::database(&error, &request_id))?;
    if query.cursor.is_some() && cursor.is_none() {
        return Err(NavigationError::invalid(
            "cursor is outside this scope",
            &request_id,
        ));
    }
    let (cursor_time, cursor_id) = cursor.unzip();
    let mut items = sqlx::query_as::<_, ProjectSummary>("SELECT p.id,p.slug,p.name,p.created_at,p.archived_at,(SELECT count(*) FROM applications a WHERE a.organization_id=p.organization_id AND a.project_id=p.id) application_count,(SELECT count(*) FROM runtime_event_groups g WHERE g.organization_id=p.organization_id AND g.project_id=p.id) runtime_group_count FROM projects p WHERE p.organization_id=$1 AND ($2::timestamptz IS NULL OR (p.created_at,p.id)>($2,$3)) ORDER BY p.created_at,p.id LIMIT $4")
        .bind(principal.organization_id).bind(cursor_time).bind(cursor_id).bind(limit+1).fetch_all(&state.pool).await.map_err(|error| NavigationError::database(&error, &request_id))?;
    Ok(Json(page(&mut items, limit, |item| item.id)))
}

async fn project(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(project_id): Path<Uuid>,
) -> Result<Json<ProjectSummary>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    let item = sqlx::query_as::<_, ProjectSummary>("SELECT p.id,p.slug,p.name,p.created_at,p.archived_at,(SELECT count(*) FROM applications a WHERE a.organization_id=p.organization_id AND a.project_id=p.id) application_count,(SELECT count(*) FROM runtime_event_groups g WHERE g.organization_id=p.organization_id AND g.project_id=p.id) runtime_group_count FROM projects p WHERE p.organization_id=$1 AND p.id=$2")
        .bind(principal.organization_id).bind(project_id).fetch_optional(&state.pool).await.map_err(|error| NavigationError::database(&error, &request_id))?.ok_or_else(|| NavigationError::not_found(&request_id))?;
    Ok(Json(item))
}

async fn applications(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(project_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<ApplicationSummary>>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    ensure_project(&state.pool, principal.organization_id, project_id)
        .await
        .map_err(|error| NavigationError::database(&error, &request_id))?
        .then_some(())
        .ok_or_else(|| NavigationError::not_found(&request_id))?;
    let limit = page_limit(query.limit, &request_id)?;
    let cursor = cursor_position(
        &state.pool,
        "applications",
        principal.organization_id,
        Some(project_id),
        query.cursor,
    )
    .await
    .map_err(|error| NavigationError::database(&error, &request_id))?;
    if query.cursor.is_some() && cursor.is_none() {
        return Err(NavigationError::invalid(
            "cursor is outside this scope",
            &request_id,
        ));
    }
    let (cursor_time, cursor_id) = cursor.unzip();
    let mut items = sqlx::query_as::<_, ApplicationSummary>("SELECT a.id,a.project_id,a.slug,a.name,a.created_at,(SELECT count(*) FROM releases r WHERE r.organization_id=a.organization_id AND r.project_id=a.project_id AND r.application_id=a.id) release_count,(SELECT count(*) FROM runtime_event_groups g WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id AND g.application_id=a.id AND g.occurrence_count>0) runtime_group_count,(SELECT max(e.last_seen_at) FROM runtime_event_groups e WHERE e.organization_id=a.organization_id AND e.project_id=a.project_id AND e.application_id=a.id AND e.occurrence_count>0) latest_observed_at FROM applications a WHERE a.organization_id=$1 AND a.project_id=$2 AND ($3::timestamptz IS NULL OR (a.created_at,a.id)>($3,$4)) ORDER BY a.created_at,a.id LIMIT $5")
        .bind(principal.organization_id).bind(project_id).bind(cursor_time).bind(cursor_id).bind(limit+1).fetch_all(&state.pool).await.map_err(|error| NavigationError::database(&error, &request_id))?;
    Ok(Json(page(&mut items, limit, |item| item.id)))
}

async fn application(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ApplicationSummary>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    let item = sqlx::query_as::<_, ApplicationSummary>("SELECT a.id,a.project_id,a.slug,a.name,a.created_at,(SELECT count(*) FROM releases r WHERE r.organization_id=a.organization_id AND r.project_id=a.project_id AND r.application_id=a.id) release_count,(SELECT count(*) FROM runtime_event_groups g WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id AND g.application_id=a.id AND g.occurrence_count>0) runtime_group_count,(SELECT max(e.last_seen_at) FROM runtime_event_groups e WHERE e.organization_id=a.organization_id AND e.project_id=a.project_id AND e.application_id=a.id AND e.occurrence_count>0) latest_observed_at FROM applications a WHERE a.organization_id=$1 AND a.project_id=$2 AND a.id=$3")
        .bind(principal.organization_id).bind(project_id).bind(application_id).fetch_optional(&state.pool).await.map_err(|error| NavigationError::database(&error, &request_id))?.ok_or_else(|| NavigationError::not_found(&request_id))?;
    Ok(Json(item))
}

async fn application_workers(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<WorkerPageQuery>,
) -> Result<Json<WorkerPage>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications WHERE organization_id=$1 AND project_id=$2 AND id=$3)")
        .bind(principal.organization_id)
        .bind(project_id)
        .bind(application_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|error| NavigationError::database(&error, &request_id))?;
    if !owned {
        return Err(NavigationError::not_found(&request_id));
    }
    let limit = page_limit(query.limit, &request_id)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(decode_worker_cursor)
        .transpose()
        .map_err(|message| NavigationError::invalid(message, &request_id))?;
    if let Some(cursor) = &cursor {
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_events WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND agent_id=$4 GROUP BY agent_id HAVING max(observed_at)=$5)")
            .bind(principal.organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cursor.agent_id)
            .bind(cursor.last_observed_at)
            .fetch_one(&state.pool)
            .await
            .map_err(|error| NavigationError::database(&error, &request_id))?;
        if !valid {
            return Err(NavigationError::invalid(
                "cursor is outside this scope",
                &request_id,
            ));
        }
    }
    let cursor_time = cursor.as_ref().map(|value| value.last_observed_at);
    let cursor_agent = cursor.as_ref().map(|value| value.agent_id);
    let mut items = sqlx::query_as::<_, ApplicationWorker>("WITH observed AS (SELECT agent_id,min(observed_at) first_observed_at,max(observed_at) last_observed_at FROM runtime_events WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 GROUP BY agent_id) SELECT a.id agent_id,a.cluster_id,c.name cluster_name,a.node_name,a.agent_version,a.architecture,a.kernel_release,o.first_observed_at,o.last_observed_at,a.last_seen_at agent_last_seen_at FROM observed o JOIN agents a ON a.organization_id=$1 AND a.id=o.agent_id JOIN clusters c ON c.organization_id=$1 AND c.id=a.cluster_id WHERE ($4::timestamptz IS NULL OR (o.last_observed_at,o.agent_id)<($4,$5)) ORDER BY o.last_observed_at DESC,o.agent_id DESC LIMIT $6")
        .bind(principal.organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(cursor_time)
        .bind(cursor_agent)
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await
        .map_err(|error| NavigationError::database(&error, &request_id))?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        items.pop();
        items
            .last()
            .map(|item| {
                encode_worker_cursor(&WorkerCursor {
                    last_observed_at: item.last_observed_at,
                    agent_id: item.agent_id,
                })
            })
            .transpose()
            .map_err(|message| NavigationError::invalid(message, &request_id))?
    } else {
        None
    };
    let coverage = crate::runtime_retention::history::coverage(
        &state.pool,
        principal.organization_id,
        project_id,
    )
    .await
    .map_err(|error| NavigationError::database(&error, &request_id))?;
    Ok(Json(WorkerPage {
        coverage,
        items,
        next_cursor,
    }))
}

fn encode_worker_cursor(cursor: &WorkerCursor) -> Result<String, &'static str> {
    serde_json::to_vec(cursor)
        .map(hex::encode)
        .map_err(|_| "cursor cannot be encoded")
}

fn decode_worker_cursor(cursor: &str) -> Result<WorkerCursor, &'static str> {
    if cursor.len() > 1024 {
        return Err("cursor is invalid");
    }
    let bytes = hex::decode(cursor).map_err(|_| "cursor is invalid")?;
    serde_json::from_slice(&bytes).map_err(|_| "cursor is invalid")
}

async fn ensure_project(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM projects WHERE organization_id=$1 AND id=$2)")
        .bind(organization_id)
        .bind(project_id)
        .fetch_one(pool)
        .await
}

async fn cursor_position(
    pool: &PgPool,
    table: &str,
    organization_id: Uuid,
    project_id: Option<Uuid>,
    cursor: Option<Uuid>,
) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    if table == "projects" {
        sqlx::query_as("SELECT created_at,id FROM projects WHERE organization_id=$1 AND id=$2")
            .bind(organization_id)
            .bind(cursor)
            .fetch_optional(pool)
            .await
    } else {
        sqlx::query_as("SELECT created_at,id FROM applications WHERE organization_id=$1 AND project_id=$2 AND id=$3").bind(organization_id).bind(project_id).bind(cursor).fetch_optional(pool).await
    }
}

fn page<T>(items: &mut Vec<T>, limit: i64, id: impl Fn(&T) -> Uuid) -> Page<T> {
    let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
        items.pop();
        items.last().map(id)
    } else {
        None
    };
    Page {
        items: std::mem::take(items),
        next_cursor,
    }
}
