use crate::error_code::ErrorCode;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{IdentityPrincipal, UserSessionAuthenticator};
use crate::service::notification_retention::{NotificationRetentionService, RetentionServiceError};
use crate::service::notification_retention::{ProjectRetention, RetentionPolicy};

#[derive(Clone, Debug)]
struct ApiState {
    auth: UserSessionAuthenticator,
    service: NotificationRetentionService,
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    Invalid,
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
                "user session required",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                ErrorCode::FORBIDDEN,
                "owner role is required",
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "retention settings not found",
            ),
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                ErrorCode::INVALID_REQUEST,
                "history_days must be between 1 and 3650",
            ),
            Self::Database(error) => {
                tracing::error!(%error, "retention settings database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error",
                )
            }
        };
        crate::web_api::uncorrelated_error_response(status, code, message)
    }
}

impl From<RetentionServiceError> for ApiError {
    fn from(error: RetentionServiceError) -> Self {
        match error {
            RetentionServiceError::Forbidden => Self::Forbidden,
            RetentionServiceError::NotFound => Self::NotFound,
            RetentionServiceError::Invalid => Self::Invalid,
            RetentionServiceError::Database(error) => Self::Database(error),
        }
    }
}

pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/notification-retention",
            get(get_organization).put(put_organization),
        )
        .route(
            "/api/v1/projects/{project_id}/notification-retention",
            get(get_project).put(put_project).delete(delete_project),
        )
        .with_state(ApiState {
            auth: UserSessionAuthenticator::new(pool.clone()),
            service: NotificationRetentionService::new(pool),
        })
}

async fn principal(state: &ApiState, headers: &HeaderMap) -> Result<IdentityPrincipal, ApiError> {
    state
        .auth
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)
}

async fn get_organization(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<RetentionPolicy>, ApiError> {
    let user = principal(&state, &headers).await?;
    Ok(Json(state.service.organization(user, id).await?))
}

async fn put_organization(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(policy): Json<RetentionPolicy>,
) -> Result<Json<RetentionPolicy>, ApiError> {
    let user = principal(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .set_organization(user, id, Some(policy))
            .await?,
    ))
}

async fn get_project(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ProjectRetention>, ApiError> {
    let user = principal(&state, &headers).await?;
    Ok(Json(state.service.project(user, id).await?))
}

async fn put_project(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(policy): Json<RetentionPolicy>,
) -> Result<Json<ProjectRetention>, ApiError> {
    let user = principal(&state, &headers).await?;
    Ok(Json(
        state.service.change_project(user, id, Some(policy)).await?,
    ))
}

async fn delete_project(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ProjectRetention>, ApiError> {
    let user = principal(&state, &headers).await?;
    Ok(Json(state.service.change_project(user, id, None).await?))
}
