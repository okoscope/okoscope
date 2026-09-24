use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{IdentityPrincipal, UserSessionAuthenticator};
use crate::error_code::ErrorCode;
use crate::service::runtime_groups::{
    GroupDetail, GroupList, GroupSummary, ListQuery, OccurrencePage, OccurrenceQuery,
    RuntimeGroupService, RuntimeGroupServiceError,
};

#[derive(Clone, Debug)]
struct ApiState {
    service: RuntimeGroupService,
    authenticator: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = ApiState {
        authenticator: UserSessionAuthenticator::new(pool.clone()),
        service: RuntimeGroupService::new(pool),
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
    Service(RuntimeGroupServiceError),
}

impl From<RuntimeGroupServiceError> for ApiError {
    fn from(error: RuntimeGroupServiceError) -> Self {
        Self::Service(error)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Service(RuntimeGroupServiceError::Database(error))
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
            Self::Service(RuntimeGroupServiceError::Invalid(message)) => {
                (StatusCode::BAD_REQUEST, ErrorCode::INVALID_REQUEST, message)
            }
            Self::Service(RuntimeGroupServiceError::NotFound) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "runtime group not found".to_owned(),
            ),
            Self::Service(RuntimeGroupServiceError::Database(error)) => {
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

async fn principal(headers: &HeaderMap, state: &ApiState) -> Result<IdentityPrincipal, ApiError> {
    state
        .authenticator
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)
}

async fn list_groups(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<GroupList>, ApiError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    Ok(Json(state.service.list_groups(principal, query).await?))
}

async fn get_group(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupDetail>, ApiError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    Ok(Json(state.service.get_group(principal, group_id).await?))
}

async fn list_occurrences(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Query(query): Query<OccurrenceQuery>,
) -> Result<Json<OccurrencePage>, ApiError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .list_occurrences(principal, group_id, query)
            .await?,
    ))
}

async fn acknowledge_group(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupSummary>, ApiError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state.service.acknowledge_group(principal, group_id).await?,
    ))
}

async fn resolve_group(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupSummary>, ApiError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state.service.resolve_group(principal, group_id).await?,
    ))
}

async fn reopen_group(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupSummary>, ApiError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    Ok(Json(state.service.reopen_group(principal, group_id).await?))
}

async fn list_snapshots(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Query(query): Query<crate::runtime_retention::history::Query>,
) -> Result<Json<crate::runtime_retention::history::Page>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .list_snapshots(principal, group_id, query)
            .await?,
    ))
}
