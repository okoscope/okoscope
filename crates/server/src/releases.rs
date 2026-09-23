//! The release endpoints: authentication, request parsing and the mapping of
//! [`ReleaseService`] results onto responses. The use cases themselves live in
//! [`crate::service::releases`].

use crate::error_code::ErrorCode;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{IdentityPrincipal, UserSessionAuthenticator};
use crate::service::releases::{
    ApplicationPath, EpisodeList, NewRelease, Release, ReleaseList, ReleaseService,
    ReleaseServiceError, RuntimeDiff, RuntimeDiffSummary,
};

#[derive(Clone, Debug)]
struct ReleaseState {
    service: ReleaseService,
    authenticator: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = ReleaseState {
        authenticator: UserSessionAuthenticator::new(pool.clone()),
        service: ReleaseService::new(pool),
    };
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases",
            post(create_release).get(list_releases),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases/{release_id}",
            get(get_release),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases/{release_id}/episodes",
            get(list_episodes),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff",
            get(runtime_diff),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff/summary",
            get(runtime_diff_summary),
        )
        .with_state(state)
}

#[derive(Debug)]
enum ReleaseError {
    Unauthorized,
    Invalid(String),
    NotFound,
    Conflict,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for ReleaseError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<ReleaseServiceError> for ReleaseError {
    fn from(error: ReleaseServiceError) -> Self {
        match error {
            ReleaseServiceError::NotFound => Self::NotFound,
            ReleaseServiceError::Invalid(message) => Self::Invalid(message),
            ReleaseServiceError::Conflict => Self::Conflict,
            ReleaseServiceError::Database(error) => Self::Database(error),
        }
    }
}

impl IntoResponse for ReleaseError {
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
                "release or application not found".to_owned(),
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                ErrorCode::RELEASE_EXISTS,
                "release version already exists".to_owned(),
            ),
            Self::Database(error) => {
                tracing::error!(error=%error, "release API database error");
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

#[derive(Debug, Deserialize)]
struct CreateRelease {
    version: String,
    description: Option<String>,
    deployed_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct DiffQuery {
    baseline_id: Option<Uuid>,
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct DiffSummaryQuery {
    baseline_id: Option<Uuid>,
    limit: Option<i64>,
}

async fn principal(
    headers: &HeaderMap,
    state: &ReleaseState,
) -> Result<IdentityPrincipal, ReleaseError> {
    state
        .authenticator
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(ReleaseError::Unauthorized)
}

async fn create_release(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Json(input): Json<CreateRelease>,
) -> Result<(StatusCode, Json<Release>), ReleaseError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let release = state
        .service
        .create(
            principal,
            ApplicationPath {
                project_id,
                application_id,
            },
            NewRelease {
                version: input.version,
                description: input.description,
                deployed_at: input.deployed_at,
            },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(release)))
}

async fn list_releases(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ReleaseList>, ReleaseError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let path = ApplicationPath {
        project_id,
        application_id,
    };
    Ok(Json(
        state
            .service
            .list(principal, path, query.cursor, query.limit)
            .await?,
    ))
}

async fn get_release(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id, release_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<Release>, ReleaseError> {
    let principal = principal(&headers, &state).await?;
    let path = ApplicationPath {
        project_id,
        application_id,
    };
    Ok(Json(state.service.get(principal, path, release_id).await?))
}

async fn list_episodes(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id, release_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<ListQuery>,
) -> Result<Json<EpisodeList>, ReleaseError> {
    let principal = principal(&headers, &state).await?;
    let path = ApplicationPath {
        project_id,
        application_id,
    };
    Ok(Json(
        state
            .service
            .episodes(principal, path, release_id, query.cursor, query.limit)
            .await?,
    ))
}

async fn runtime_diff(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id, target_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<DiffQuery>,
) -> Result<Json<RuntimeDiff>, ReleaseError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let path = ApplicationPath {
        project_id,
        application_id,
    };
    let diff = state
        .service
        .runtime_diff(
            principal,
            path,
            target_id,
            query.baseline_id,
            query.cursor,
            query.limit,
        )
        .await?;
    crate::metrics::record_release_diff();
    Ok(Json(diff))
}

async fn runtime_diff_summary(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id, target_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<DiffSummaryQuery>,
) -> Result<Json<RuntimeDiffSummary>, ReleaseError> {
    let started = std::time::Instant::now();
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let path = ApplicationPath {
        project_id,
        application_id,
    };
    let summary = state
        .service
        .runtime_diff_summary(principal, path, target_id, query.baseline_id, query.limit)
        .await?;
    crate::metrics::record_release_diff_summary(
        u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
    );
    Ok(Json(summary))
}
