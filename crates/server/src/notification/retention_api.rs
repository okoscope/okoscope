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
use crate::{
    access_control::{EffectiveProjectAccess, resolve_project_access},
    auth::{IdentityPrincipal, OrganizationRole, UserSessionAuthenticator},
};

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

async fn principal(pool: &PgPool, headers: &HeaderMap) -> Result<IdentityPrincipal, ApiError> {
    UserSessionAuthenticator::new(pool.clone())
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)
}

fn owner(principal: IdentityPrincipal, organization_id: Uuid) -> Result<(), ApiError> {
    if principal.is_super_admin
        || principal.active_organization_id == Some(organization_id)
            && principal.organization_role == Some(OrganizationRole::Owner)
    {
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
    user: IdentityPrincipal,
    id: Uuid,
) -> Result<RetentionPolicy, ApiError> {
    let can_read = user.is_super_admin
        || user.active_organization_id == Some(id)
            && user
                .organization_role
                .is_some_and(OrganizationRole::inherits_project_access);
    if !can_read {
        return Err(ApiError::NotFound);
    }
    settings::organization(pool, id)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn owned_project(
    pool: &PgPool,
    user: IdentityPrincipal,
    id: Uuid,
) -> Result<(Uuid, EffectiveProjectAccess, ProjectRetention), ApiError> {
    let organization_id: Uuid =
        sqlx::query_scalar("SELECT organization_id FROM projects WHERE id=$1")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    let access = resolve_project_access(pool, user, organization_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let retention = settings::project(pool, organization_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok((organization_id, access, retention))
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
    if !user.is_super_admin && user.active_organization_id != Some(id) {
        return Err(ApiError::NotFound);
    }
    owner(user, id)?;
    owned_organization(&pool, user, id).await?;
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
    let (_, _, retention) = owned_project(&pool, user, id).await?;
    Ok(Json(retention))
}

async fn change_project(
    pool: &PgPool,
    headers: &HeaderMap,
    id: Uuid,
    policy: Option<RetentionPolicy>,
) -> Result<Json<ProjectRetention>, ApiError> {
    let user = principal(pool, headers).await?;
    let (organization_id, access, _) = owned_project(pool, user, id).await?;
    if !access.can_manage_members() {
        return Err(ApiError::Forbidden);
    }
    if let Some(policy) = policy {
        validate(policy)?;
    }
    settings::set_project(pool, organization_id, id, user.user_id, policy).await?;
    let (_, _, retention) = owned_project(pool, user, id).await?;
    Ok(Json(retention))
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
