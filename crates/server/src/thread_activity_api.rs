use crate::{
    auth::UserSessionAuthenticator,
    error_code::ErrorCode,
    service::thread_activity::{
        ScopeQuery, ThreadActivityError, ThreadActivityService, ThreadSummary, WindowPage,
    },
};
use axum::{
    Json, Router,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use uuid::Uuid;
#[derive(Clone, Debug)]
struct ApiState {
    service: ThreadActivityService,
    auth: UserSessionAuthenticator,
}
pub fn router(pool: PgPool) -> Router {
    let state = ApiState {
        auth: UserSessionAuthenticator::new(pool.clone()),
        service: ThreadActivityService::new(pool),
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
#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Service(ThreadActivityError),
}
impl From<ThreadActivityError> for ApiError {
    fn from(value: ThreadActivityError) -> Self {
        Self::Service(value)
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(value: sqlx::Error) -> Self {
        Self::Service(ThreadActivityError::Database(value))
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential",
            ),
            Self::Service(ThreadActivityError::Invalid(message)) => {
                (StatusCode::BAD_REQUEST, ErrorCode::INVALID_REQUEST, message)
            }
            Self::Service(ThreadActivityError::NotFound) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "thread activity resource not found",
            ),
            Self::Service(ThreadActivityError::Database(error)) => {
                tracing::error!(%error, "thread activity API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error",
                )
            }
        };
        let mut response = crate::web_api::uncorrelated_error_response(status, code, message);
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
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
    query: Result<Query<ScopeQuery>, QueryRejection>,
) -> Result<(HeaderMap, Json<WindowPage>), ApiError> {
    let identity = state
        .auth
        .authenticate_identity_headers(&headers)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let Query(query) =
        query.map_err(|_| ThreadActivityError::Invalid("invalid query parameters"))?;
    Ok((
        no_store(),
        Json(
            state
                .service
                .list(identity, project_id, application_id, query)
                .await?,
        ),
    ))
}
async fn summary(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    query: Result<Query<ScopeQuery>, QueryRejection>,
) -> Result<(HeaderMap, Json<ThreadSummary>), ApiError> {
    let identity = state
        .auth
        .authenticate_identity_headers(&headers)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let Query(query) =
        query.map_err(|_| ThreadActivityError::Invalid("invalid query parameters"))?;
    Ok((
        no_store(),
        Json(
            state
                .service
                .summary(identity, project_id, application_id, query)
                .await?,
        ),
    ))
}
