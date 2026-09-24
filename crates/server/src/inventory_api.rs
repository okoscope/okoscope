use std::time::Instant;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{IdentityPrincipal, UserSessionAuthenticator};
use crate::error_code::ErrorCode;
use crate::service::inventory::{
    DeleteUserLabel, DistributionQuery, FacetPage, FacetQuery, GroupPage, IdentityTokenProblem,
    InventoryDistribution, InventoryItemDetail, InventoryItemPage, InventoryQuery,
    InventoryService, InventoryServiceError, InventorySummary, OccurrencePage, PageQuery,
    PutUserLabel, ReleasePresencePage, SightingPage, StringCursorPageQuery, SummaryQuery,
    UserLabel,
};

#[derive(Clone, Debug)]
struct InventoryApiState {
    service: InventoryService,
    auth: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = InventoryApiState {
        auth: UserSessionAuthenticator::new(pool.clone()),
        service: InventoryService::new(pool),
    };
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory",
            get(list_items),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/summary",
            get(summary),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/distribution",
            get(distribution),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/facets/{facet}",
            get(facets),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}",
            get(item_detail),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/user-label",
            put(put_user_label).delete(delete_user_label),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/releases",
            get(item_releases),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/sightings",
            get(item_sightings),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/groups",
            get(item_groups),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/occurrences",
            get(item_occurrences),
        )
        .with_state(state)
}

#[derive(Debug)]
enum InventoryApiError {
    Unauthorized,
    Service(InventoryServiceError),
}

impl From<InventoryServiceError> for InventoryApiError {
    fn from(error: InventoryServiceError) -> Self {
        Self::Service(error)
    }
}

impl From<sqlx::Error> for InventoryApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Service(InventoryServiceError::Database(error))
    }
}

impl IntoResponse for InventoryApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential".to_owned(),
            ),
            Self::Service(InventoryServiceError::Invalid(message)) => {
                (StatusCode::BAD_REQUEST, ErrorCode::INVALID_REQUEST, message)
            }
            Self::Service(InventoryServiceError::IdentityToken(problem)) => (
                StatusCode::BAD_REQUEST,
                match problem {
                    IdentityTokenProblem::Invalid => ErrorCode::INVALID_IDENTITY_TOKEN,
                    IdentityTokenProblem::Expired => ErrorCode::EXPIRED_IDENTITY_TOKEN,
                    IdentityTokenProblem::ScopeMismatch => ErrorCode::IDENTITY_TOKEN_SCOPE_MISMATCH,
                },
                "identity token is invalid for this request".to_owned(),
            ),
            Self::Service(InventoryServiceError::NotFound) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "runtime inventory resource not found".to_owned(),
            ),
            Self::Service(InventoryServiceError::Conflict) => (
                StatusCode::CONFLICT,
                ErrorCode::LABEL_CONFLICT,
                "the runtime behavior label was changed by another request".to_owned(),
            ),
            Self::Service(InventoryServiceError::Database(error)) => {
                tracing::error!(error=%error, "runtime inventory API database error");
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

async fn principal(
    headers: &HeaderMap,
    state: &InventoryApiState,
) -> Result<IdentityPrincipal, InventoryApiError> {
    state
        .auth
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(InventoryApiError::Unauthorized)
}

async fn put_user_label(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
    Json(input): Json<PutUserLabel>,
) -> Result<Json<UserLabel>, InventoryApiError> {
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .put_user_label(identity, project_id, application_id, item_id, input)
            .await?,
    ))
}

async fn delete_user_label(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(input): Query<DeleteUserLabel>,
) -> Result<StatusCode, InventoryApiError> {
    let identity = principal(&headers, &state).await?;
    state
        .service
        .delete_user_label(identity, project_id, application_id, item_id, input)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn summary(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<SummaryQuery>,
) -> Result<Json<InventorySummary>, InventoryApiError> {
    let started = Instant::now();
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .summary(identity, project_id, application_id, query, started)
            .await?,
    ))
}

async fn distribution(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<DistributionQuery>,
) -> Result<Json<InventoryDistribution>, InventoryApiError> {
    let started = Instant::now();
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .distribution(identity, project_id, application_id, query, started)
            .await?,
    ))
}

async fn facets(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, facet_name)): Path<(Uuid, Uuid, String)>,
    Query(query): Query<FacetQuery>,
) -> Result<Json<FacetPage>, InventoryApiError> {
    let started = Instant::now();
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .facets(
                identity,
                project_id,
                application_id,
                &facet_name,
                query,
                started,
            )
            .await?,
    ))
}

async fn list_items(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<InventoryQuery>,
) -> Result<Json<InventoryItemPage>, InventoryApiError> {
    let started = Instant::now();
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .list_items(identity, project_id, application_id, query, started)
            .await?,
    ))
}

async fn item_detail(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<InventoryItemDetail>, InventoryApiError> {
    let started = Instant::now();
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .item_detail(identity, project_id, application_id, item_id, started)
            .await?,
    ))
}

async fn item_releases(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<PageQuery>,
) -> Result<Json<ReleasePresencePage>, InventoryApiError> {
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .item_releases(identity, project_id, application_id, item_id, query)
            .await?,
    ))
}

async fn item_sightings(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<StringCursorPageQuery>,
) -> Result<Json<SightingPage>, InventoryApiError> {
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .item_sightings(identity, project_id, application_id, item_id, query)
            .await?,
    ))
}

async fn item_groups(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<PageQuery>,
) -> Result<Json<GroupPage>, InventoryApiError> {
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .item_groups(identity, project_id, application_id, item_id, query)
            .await?,
    ))
}

async fn item_occurrences(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<PageQuery>,
) -> Result<Json<OccurrencePage>, InventoryApiError> {
    let identity = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .item_occurrences(identity, project_id, application_id, item_id, query)
            .await?,
    ))
}
