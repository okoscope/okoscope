use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use sqlx::PgPool;

use crate::auth::{IdentityPrincipal, UserSessionAuthenticator};
use crate::error_code::ErrorCode;
use crate::service::policies::{
    ApplicationPath, CreatePolicyInput, GroupPath, ItemPath, MutationResult, Page, PageQuery,
    PolicyPath, PolicyRevision, PolicyService, PolicyServiceError, PolicySummary, PreviewResult,
    RecomputePath, RecomputeSummary, ReplacePolicyInput, RevisionInput, SeedResponse,
    SuppressionInput, SuppressionPath, SuppressionQuery, SuppressionSummary,
};
use crate::web_api::{RequestId, error_response};

#[derive(Clone)]
struct PolicyApiState {
    service: PolicyService,
    auth: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = PolicyApiState {
        auth: UserSessionAuthenticator::new(pool.clone()),
        service: PolicyService::new(pool),
    };
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies",
            get(list_policies).post(create_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/preview",
            post(preview_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}",
            get(get_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/revisions",
            get(list_revisions),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/replace",
            post(replace_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/enable",
            post(enable_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/disable",
            post(disable_policy),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/policy-seed",
            get(inventory_seed),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-groups/{group_id}/policy-seed",
            get(group_seed),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policy-suppressions",
            get(list_suppressions).post(create_suppression),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policy-suppressions/{suppression_id}/cancel",
            post(cancel_suppression),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/policy-recomputations/{recomputation_id}",
            get(get_recomputation),
        )
        .with_state(state)
}

#[derive(Debug)]
struct PolicyApiError {
    status: StatusCode,
    code: ErrorCode,
    message: String,
    request_id: RequestId,
}

impl PolicyApiError {
    fn new(status: StatusCode, code: ErrorCode, message: String, request_id: &RequestId) -> Self {
        Self {
            status,
            code,
            message,
            request_id: request_id.clone(),
        }
    }

    fn unauthorized(request_id: &RequestId) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::UNAUTHORIZED,
            "invalid or missing bearer credential".into(),
            request_id,
        )
    }

    /// The response for a failed policy use case.
    fn from_service(error: PolicyServiceError, request_id: &RequestId) -> Self {
        match error {
            PolicyServiceError::Invalid(message) => Self::new(
                StatusCode::BAD_REQUEST,
                ErrorCode::INVALID_REQUEST,
                message,
                request_id,
            ),
            PolicyServiceError::NotFound => Self::new(
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "resource not found".into(),
                request_id,
            ),
            PolicyServiceError::Conflict(message) => Self::new(
                StatusCode::CONFLICT,
                ErrorCode::CONFLICT,
                message,
                request_id,
            ),
            PolicyServiceError::Database(error) => {
                tracing::error!(%error, request_id=%request_id.0, "policy API database error");
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error".into(),
                    request_id,
                )
            }
        }
    }
}

impl IntoResponse for PolicyApiError {
    fn into_response(self) -> Response {
        error_response(self.status, self.code, self.message, &self.request_id)
    }
}

/// Maps a service error onto this request's response.
fn failed(request_id: &RequestId) -> impl Fn(PolicyServiceError) -> PolicyApiError + '_ {
    move |error| PolicyApiError::from_service(error, request_id)
}

async fn principal(
    headers: &HeaderMap,
    state: &PolicyApiState,
    request_id: &RequestId,
) -> Result<IdentityPrincipal, PolicyApiError> {
    state
        .auth
        .authenticate_identity_headers(headers)
        .await
        .map_err(|error| {
            PolicyApiError::from_service(PolicyServiceError::Database(error), request_id)
        })?
        .ok_or_else(|| PolicyApiError::unauthorized(request_id))
}

/// The raw `Idempotency-Key` header; the service parses it.
fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
}

async fn get_recomputation(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RecomputePath>,
) -> Result<Json<RecomputeSummary>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .get_recomputation(identity, path)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn list_policies(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ApplicationPath>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<PolicySummary>>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .list_policies(identity, path, query)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn get_policy(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PolicyPath>,
) -> Result<Json<PolicySummary>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .get_policy(identity, path)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn list_revisions(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PolicyPath>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<PolicyRevision>>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .list_revisions(identity, path, query)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn inventory_seed(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ItemPath>,
) -> Result<Json<SeedResponse>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .inventory_seed(identity, path)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn group_seed(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<GroupPath>,
) -> Result<Json<SeedResponse>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .group_seed(identity, path)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn list_suppressions(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ApplicationPath>,
    Query(query): Query<SuppressionQuery>,
) -> Result<Json<Page<SuppressionSummary>>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .list_suppressions(identity, path, query)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn create_policy(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ApplicationPath>,
    Json(input): Json<CreatePolicyInput>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .create_policy(identity, path, idempotency_key(&headers), input)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn preview_policy(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ApplicationPath>,
    Json(input): Json<RevisionInput>,
) -> Result<Json<PreviewResult>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .preview_policy(identity, path, input)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn replace_policy(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PolicyPath>,
    Json(input): Json<ReplacePolicyInput>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .replace_policy(identity, path, idempotency_key(&headers), input)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn enable_policy(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PolicyPath>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .enable_policy(identity, path, idempotency_key(&headers))
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn disable_policy(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PolicyPath>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .disable_policy(identity, path, idempotency_key(&headers))
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn create_suppression(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ApplicationPath>,
    Json(input): Json<SuppressionInput>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .create_suppression(identity, path, idempotency_key(&headers), input)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn cancel_suppression(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<SuppressionPath>,
) -> Result<Json<MutationResult>, PolicyApiError> {
    let identity = principal(&headers, &state, &request_id).await?;
    state
        .service
        .cancel_suppression(identity, path, idempotency_key(&headers))
        .await
        .map(Json)
        .map_err(failed(&request_id))
}
