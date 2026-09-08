use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use uuid::Uuid;

use super::retention_settings::{self as settings, ProjectRetention, RetentionPolicy};
use crate::auth::{UserPrincipal, UserSessionAuthenticator};

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
                "unauthorized",
                "user session required",
            ),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "owner role is required"),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "retention settings not found",
            ),
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "history_days must be between 1 and 3650",
            ),
            Self::Database(error) => {
                tracing::error!(%error, "retention settings database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error",
                )
            }
        };
        (
            status,
            Json(serde_json::json!({"error": code, "message": message})),
        )
            .into_response()
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
        .with_state(pool)
}

async fn principal(pool: &PgPool, headers: &HeaderMap) -> Result<UserPrincipal, ApiError> {
    UserSessionAuthenticator::new(pool.clone())
        .authenticate_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)
}

fn owner(principal: UserPrincipal) -> Result<(), ApiError> {
    if principal.role.is_owner() {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

fn validate(policy: RetentionPolicy) -> Result<(), ApiError> {
    if policy.valid() {
        Ok(())
    } else {
        Err(ApiError::Invalid)
    }
}

async fn owned_organization(
    pool: &PgPool,
    user: UserPrincipal,
    id: Uuid,
) -> Result<RetentionPolicy, ApiError> {
    if id != user.organization_id {
        return Err(ApiError::NotFound);
    }
    settings::organization(pool, id)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn owned_project(
    pool: &PgPool,
    user: UserPrincipal,
    id: Uuid,
) -> Result<ProjectRetention, ApiError> {
    settings::project(pool, user.organization_id, id)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn get_organization(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<RetentionPolicy>, ApiError> {
    let user = principal(&pool, &headers).await?;
    Ok(Json(owned_organization(&pool, user, id).await?))
}

async fn put_organization(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(policy): Json<RetentionPolicy>,
) -> Result<Json<RetentionPolicy>, ApiError> {
    let user = principal(&pool, &headers).await?;
    owned_organization(&pool, user, id).await?;
    owner(user)?;
    validate(policy)?;
    settings::set_organization(&pool, id, user.user_id, policy).await?;
    Ok(Json(policy))
}

async fn get_project(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ProjectRetention>, ApiError> {
    let user = principal(&pool, &headers).await?;
    Ok(Json(owned_project(&pool, user, id).await?))
}

async fn change_project(
    pool: &PgPool,
    headers: &HeaderMap,
    id: Uuid,
    policy: Option<RetentionPolicy>,
) -> Result<Json<ProjectRetention>, ApiError> {
    let user = principal(pool, headers).await?;
    owned_project(pool, user, id).await?;
    owner(user)?;
    if let Some(policy) = policy {
        validate(policy)?;
    }
    settings::set_project(pool, user.organization_id, id, user.user_id, policy).await?;
    Ok(Json(owned_project(pool, user, id).await?))
}

async fn put_project(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(policy): Json<RetentionPolicy>,
) -> Result<Json<ProjectRetention>, ApiError> {
    change_project(&pool, &headers, id, Some(policy)).await
}

async fn delete_project(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ProjectRetention>, ApiError> {
    change_project(&pool, &headers, id, None).await
}
