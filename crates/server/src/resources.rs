use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{IdentityPrincipal, UserSessionAuthenticator};
use crate::error_code::ErrorCode;
use crate::service::resources::{
    ComparisonQuery, ComparisonResponse, HistoryQuery, HistoryResponse, ResourceService,
    ResourceServiceError,
};

pub use crate::service::resources::{
    PersistResourceOutcome, RESOURCE_DETAIL_RETENTION_DAYS, RESOURCE_ROLLUP_RETENTION_DAYS,
    cleanup_project, persist_resource_aggregate, refresh_project_findings, render_metrics,
};

#[derive(Clone, Debug)]
struct ResourceState {
    service: ResourceService,
    authenticator: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = ResourceState {
        authenticator: UserSessionAuthenticator::new(pool.clone()),
        service: ResourceService::new(pool),
    };
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/resources",
            get(resource_history),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/resource-comparison",
            get(resource_comparison),
        )
        .with_state(state)
}

#[derive(Debug)]
enum ResourceError {
    Unauthorized,
    Service(ResourceServiceError),
}

impl From<ResourceServiceError> for ResourceError {
    fn from(error: ResourceServiceError) -> Self {
        Self::Service(error)
    }
}

impl From<sqlx::Error> for ResourceError {
    fn from(error: sqlx::Error) -> Self {
        Self::Service(ResourceServiceError::Database(error))
    }
}

impl IntoResponse for ResourceError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential".into(),
            ),
            Self::Service(ResourceServiceError::Invalid(message)) => {
                (StatusCode::BAD_REQUEST, ErrorCode::INVALID_REQUEST, message)
            }
            Self::Service(ResourceServiceError::NotFound) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "application or release not found".into(),
            ),
            Self::Service(ResourceServiceError::Database(error)) => {
                tracing::error!(%error, "resource API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error".into(),
                )
            }
        };
        crate::web_api::uncorrelated_error_response(status, code, message)
    }
}

async fn principal(
    headers: &HeaderMap,
    state: &ResourceState,
) -> Result<IdentityPrincipal, ResourceError> {
    state
        .authenticator
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(ResourceError::Unauthorized)
}

async fn resource_history(
    State(state): State<ResourceState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<HistoryResponse>, ResourceError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .history(principal, project_id, application_id, query)
            .await?,
    ))
}

async fn resource_comparison(
    State(state): State<ResourceState>,
    headers: HeaderMap,
    Path((project_id, application_id, target_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<ComparisonQuery>,
) -> Result<Json<ComparisonResponse>, ResourceError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .comparison(principal, project_id, application_id, target_id, query)
            .await?,
    ))
}
