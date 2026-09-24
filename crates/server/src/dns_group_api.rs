use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::UserSessionAuthenticator;
use crate::error_code::ErrorCode;
use crate::service::dns_groups::{
    DistributionQuery, DnsDistribution, DnsGroupService, DnsGroupServiceError, GroupPage,
    GroupQuery, VariantPage, VariantQuery,
};

#[derive(Clone, Debug)]
struct DnsGroupState {
    service: DnsGroupService,
    auth: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = DnsGroupState {
        auth: UserSessionAuthenticator::new(pool.clone()),
        service: DnsGroupService::new(pool),
    };
    Router::new()
        .route("/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups", get(list_groups))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups/distribution", get(distribution))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups/{group_token}/variants", get(variants))
        .with_state(state)
}

#[derive(Debug)]
enum DnsGroupError {
    Unauthorized,
    Service(DnsGroupServiceError),
}

impl From<DnsGroupServiceError> for DnsGroupError {
    fn from(error: DnsGroupServiceError) -> Self {
        Self::Service(error)
    }
}

impl From<sqlx::Error> for DnsGroupError {
    fn from(error: sqlx::Error) -> Self {
        Self::Service(DnsGroupServiceError::Database(error))
    }
}

impl IntoResponse for DnsGroupError {
    fn into_response(self) -> Response {
        let (status, error, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential".into(),
            ),
            Self::Service(DnsGroupServiceError::Invalid(message)) => {
                (StatusCode::BAD_REQUEST, ErrorCode::INVALID_REQUEST, message)
            }
            Self::Service(DnsGroupServiceError::NotFound) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "logical DNS group not found".into(),
            ),
            Self::Service(DnsGroupServiceError::Database(error)) => {
                tracing::error!(%error, "logical DNS group API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error".into(),
                )
            }
        };
        crate::web_api::uncorrelated_error_response(status, error, message)
    }
}

async fn principal(
    headers: &HeaderMap,
    state: &DnsGroupState,
) -> Result<crate::auth::IdentityPrincipal, DnsGroupError> {
    state
        .auth
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(DnsGroupError::Unauthorized)
}

async fn list_groups(
    State(state): State<DnsGroupState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<GroupQuery>,
) -> Result<Json<GroupPage>, DnsGroupError> {
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .list_groups(identity, project_id, application_id, query)
            .await?,
    ))
}

async fn distribution(
    State(state): State<DnsGroupState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<DistributionQuery>,
) -> Result<Json<DnsDistribution>, DnsGroupError> {
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .distribution(identity, project_id, application_id, query)
            .await?,
    ))
}

async fn variants(
    State(state): State<DnsGroupState>,
    headers: HeaderMap,
    Path((project_id, application_id, group_token)): Path<(Uuid, Uuid, String)>,
    Query(query): Query<VariantQuery>,
) -> Result<Json<VariantPage>, DnsGroupError> {
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .variants(identity, project_id, application_id, &group_token, query)
            .await?,
    ))
}
