use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{UserPrincipal, UserSessionAuthenticator},
    web_api::RequestId,
};

use super::{
    NotificationService,
    health::{NotificationHealthResponse, load_project_snapshot},
    recovery::{
        BulkRecoveryResult, BulkRetryFilter, DeliveryRecoveryResult, RecoveryActor,
        RecoveryConflictCode, RecoveryError, RecoveryOperationDetail, RecoveryOperationFilter,
        RecoveryOperationSummary,
    },
    repository::{DestinationError, DestinationRepository, DestinationUpdate, WebhookDestination},
    webhook::{WebhookPolicy, parse_url, resolve_target},
    worker::{
        DeliveryDetail, DeliveryFilter, DeliverySummary, delivery_detail, list_deliveries,
        test_destination,
    },
};

#[derive(Clone, Debug)]
struct NotificationApiState {
    authenticator: UserSessionAuthenticator,
    destinations: DestinationRepository,
    policy: WebhookPolicy,
    service: NotificationService,
}

pub fn router(pool: PgPool, service: NotificationService) -> Router {
    let state = NotificationApiState {
        authenticator: UserSessionAuthenticator::new(pool),
        destinations: service.destinations.clone(),
        policy: service.policy.clone(),
        service,
    };
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/webhook-destinations",
            get(list).post(create),
        )
        .route(
            "/api/v1/projects/{project_id}/webhook-destinations/{destination_id}",
            get(get_destination).patch(update),
        )
        .route(
            "/api/v1/projects/{project_id}/webhook-destinations/{destination_id}/disable",
            post(disable),
        )
        .route(
            "/api/v1/projects/{project_id}/webhook-destinations/{destination_id}/rotate-secret",
            post(rotate_secret),
        )
        .route(
            "/api/v1/projects/{project_id}/webhook-destinations/{destination_id}/test",
            post(test),
        )
        .route(
            "/api/v1/projects/{project_id}/notification-deliveries",
            get(list_delivery_history),
        )
        .route(
            "/api/v1/projects/{project_id}/notification-deliveries/bulk-retry",
            post(bulk_retry_deliveries),
        )
        .route(
            "/api/v1/projects/{project_id}/notification-health",
            get(notification_health),
        )
        .route(
            "/api/v1/projects/{project_id}/notification-deliveries/{delivery_id}",
            get(get_delivery_history),
        )
        .route(
            "/api/v1/projects/{project_id}/notification-deliveries/{delivery_id}/retry",
            post(retry_delivery),
        )
        .route(
            "/api/v1/projects/{project_id}/notification-deliveries/{delivery_id}/cancel",
            post(cancel_delivery),
        )
        .route(
            "/api/v1/projects/{project_id}/notification-recovery-operations",
            get(list_recovery_operations),
        )
        .route(
            "/api/v1/projects/{project_id}/notification-recovery-operations/{operation_id}",
            get(get_recovery_operation),
        )
        .with_state(state)
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Invalid(String),
    NotFound,
    Conflict,
    RecoveryConflict(RecoveryConflictCode),
    Database(sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid or missing bearer credential".into(),
            ),
            Self::Invalid(message) => (StatusCode::BAD_REQUEST, "invalid_request", message),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "destination not found".into(),
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "revision_conflict",
                "destination revision conflict".into(),
            ),
            Self::RecoveryConflict(conflict) => (
                StatusCode::CONFLICT,
                match conflict {
                    RecoveryConflictCode::InvalidState => "delivery_invalid_state",
                    RecoveryConflictCode::ActiveLease => "delivery_active_lease",
                    RecoveryConflictCode::DestinationDisabled => "destination_disabled",
                    RecoveryConflictCode::IdempotencyKeyReused => "idempotency_key_reused",
                    RecoveryConflictCode::BulkLimitExceeded => "bulk_limit_exceeded",
                },
                "notification recovery command conflicts with current state".into(),
            ),
            Self::Database(error) => {
                tracing::error!(error=%error, "notification API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".into(),
                )
            }
        };
        (
            status,
            Json(ErrorBody {
                error: code,
                message,
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<DestinationError> for ApiError {
    fn from(error: DestinationError) -> Self {
        match error {
            DestinationError::NotFound => Self::NotFound,
            DestinationError::RevisionConflict => Self::Conflict,
            DestinationError::InvalidName => Self::Invalid(error.to_string()),
            DestinationError::Database(error) => Self::Database(error),
            DestinationError::Vault(error) => {
                tracing::error!(error=%error, "destination secret operation failed");
                Self::Invalid("destination secret operation failed".into())
            }
        }
    }
}

impl From<RecoveryError> for ApiError {
    fn from(error: RecoveryError) -> Self {
        match error {
            RecoveryError::NotFound => Self::NotFound,
            RecoveryError::Conflict(conflict) => Self::RecoveryConflict(conflict),
            RecoveryError::InvalidIdempotencyKey => Self::Invalid(error.to_string()),
            RecoveryError::Serialization(error) => {
                tracing::error!(error=%error, "notification recovery serialization failed");
                Self::Invalid("notification recovery command is invalid".into())
            }
            RecoveryError::Database(error) => Self::Database(error),
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CreateDestination {
    name: String,
    url: String,
    #[serde(default)]
    deliver_backfill: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateDestination {
    name: Option<String>,
    url: Option<String>,
    deliver_backfill: Option<bool>,
    enabled: Option<bool>,
    revision: i64,
}

#[derive(Debug, Serialize)]
struct DestinationWithSecret {
    #[serde(flatten)]
    destination: WebhookDestination,
    secret: String,
}

#[derive(Debug, Serialize)]
struct DeliveryList {
    items: Vec<DeliverySummary>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct RecoveryOperationList {
    items: Vec<RecoveryOperationSummary>,
    next_cursor: Option<Uuid>,
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::Invalid("missing or invalid Idempotency-Key header".into()))
}

async fn principal(
    headers: &HeaderMap,
    state: &NotificationApiState,
) -> Result<UserPrincipal, ApiError> {
    state
        .authenticator
        .authenticate_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)
}

async fn validate_target(value: &str, policy: &WebhookPolicy) -> Result<(), ApiError> {
    let url = parse_url(value, policy).map_err(|error| ApiError::Invalid(error.to_string()))?;
    resolve_target(&url, policy)
        .await
        .map_err(|error| ApiError::Invalid(error.to_string()))?;
    Ok(())
}

async fn list(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
) -> Result<Json<Vec<WebhookDestination>>, ApiError> {
    let principal = principal(&headers, &state).await?;
    if !state
        .destinations
        .project_owned(principal.organization_id, project_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    Ok(Json(
        state
            .destinations
            .list(principal.organization_id, project_id)
            .await?,
    ))
}

async fn get_destination(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, destination_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<WebhookDestination>, ApiError> {
    let principal = principal(&headers, &state).await?;
    state
        .destinations
        .get(principal.organization_id, project_id, destination_id)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

async fn create(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Json(input): Json<CreateDestination>,
) -> Result<(StatusCode, Json<DestinationWithSecret>), ApiError> {
    let principal = principal(&headers, &state).await?;
    validate_target(&input.url, &state.policy).await?;
    let (destination, secret) = state
        .destinations
        .create(
            principal.organization_id,
            project_id,
            &input.name,
            &input.url,
            input.deliver_backfill,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(DestinationWithSecret {
            destination,
            secret: secret.to_string(),
        }),
    ))
}

async fn update(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, destination_id)): Path<(Uuid, Uuid)>,
    Json(input): Json<UpdateDestination>,
) -> Result<Json<WebhookDestination>, ApiError> {
    let principal = principal(&headers, &state).await?;
    if let Some(url) = &input.url {
        validate_target(url, &state.policy).await?;
    }
    let destination = state
        .destinations
        .update(
            principal.organization_id,
            project_id,
            destination_id,
            DestinationUpdate {
                name: input.name.as_deref(),
                url: input.url.as_deref(),
                deliver_backfill: input.deliver_backfill,
                enabled: input.enabled,
                expected_revision: input.revision,
            },
        )
        .await?;
    Ok(Json(destination))
}

async fn disable(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, destination_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<WebhookDestination>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .destinations
            .disable(principal.organization_id, project_id, destination_id)
            .await?,
    ))
}

async fn rotate_secret(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, destination_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DestinationWithSecret>, ApiError> {
    let principal = principal(&headers, &state).await?;
    let (destination, secret) = state
        .destinations
        .rotate_secret(principal.organization_id, project_id, destination_id)
        .await?;
    Ok(Json(DestinationWithSecret {
        destination,
        secret: secret.to_string(),
    }))
}

async fn test(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, destination_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeliverySummary>, ApiError> {
    let principal = principal(&headers, &state).await?;
    test_destination(
        &state.service,
        principal.organization_id,
        project_id,
        destination_id,
    )
    .await
    .map(Json)
    .map_err(|error| {
        tracing::warn!(error=%error, "test webhook delivery failed");
        ApiError::Invalid("test delivery could not be completed".into())
    })
}

async fn list_delivery_history(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    axum::extract::Query(filter): axum::extract::Query<DeliveryFilter>,
) -> Result<Json<DeliveryList>, ApiError> {
    let principal = principal(&headers, &state).await?;
    if !state
        .destinations
        .project_owned(principal.organization_id, project_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    let (items, next_cursor) = list_deliveries(
        &state.service.pool,
        principal.organization_id,
        project_id,
        &filter,
    )
    .await?;
    Ok(Json(DeliveryList { items, next_cursor }))
}

async fn notification_health(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
) -> Result<Json<NotificationHealthResponse>, ApiError> {
    let principal = principal(&headers, &state).await?;
    if !state
        .destinations
        .project_owned(principal.organization_id, project_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    let snapshot =
        load_project_snapshot(&state.service.pool, principal.organization_id, project_id).await?;
    Ok(Json(NotificationHealthResponse::from_snapshot(
        state.service.config.enabled,
        crate::metrics::notification_worker_is_draining(),
        &snapshot,
    )))
}

async fn get_delivery_history(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, delivery_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeliveryDetail>, ApiError> {
    let principal = principal(&headers, &state).await?;
    delivery_detail(
        &state.service.pool,
        principal.organization_id,
        project_id,
        delivery_id,
    )
    .await?
    .map(Json)
    .ok_or(ApiError::NotFound)
}

async fn retry_delivery(
    State(state): State<NotificationApiState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((project_id, delivery_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeliveryRecoveryResult>, ApiError> {
    let principal = principal(&headers, &state).await?;
    if !state
        .destinations
        .project_owned(principal.organization_id, project_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    let key = idempotency_key(&headers)?;
    state
        .service
        .recovery
        .retry_delivery(
            principal.organization_id,
            project_id,
            delivery_id,
            RecoveryActor {
                id: principal.user_id,
                request_id: &request_id.0,
            },
            key,
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn cancel_delivery(
    State(state): State<NotificationApiState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((project_id, delivery_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeliveryRecoveryResult>, ApiError> {
    let principal = principal(&headers, &state).await?;
    if !state
        .destinations
        .project_owned(principal.organization_id, project_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    let key = idempotency_key(&headers)?;
    state
        .service
        .recovery
        .cancel_delivery(
            principal.organization_id,
            project_id,
            delivery_id,
            RecoveryActor {
                id: principal.user_id,
                request_id: &request_id.0,
            },
            key,
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn bulk_retry_deliveries(
    State(state): State<NotificationApiState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Json(filter): Json<BulkRetryFilter>,
) -> Result<Json<BulkRecoveryResult>, ApiError> {
    let principal = principal(&headers, &state).await?;
    if !state
        .destinations
        .project_owned(principal.organization_id, project_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    let key = idempotency_key(&headers)?;
    state
        .service
        .recovery
        .bulk_retry(
            principal.organization_id,
            project_id,
            &filter,
            RecoveryActor {
                id: principal.user_id,
                request_id: &request_id.0,
            },
            key,
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn list_recovery_operations(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    axum::extract::Query(filter): axum::extract::Query<RecoveryOperationFilter>,
) -> Result<Json<RecoveryOperationList>, ApiError> {
    let principal = principal(&headers, &state).await?;
    if !state
        .destinations
        .project_owned(principal.organization_id, project_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    let (items, next_cursor) = state
        .service
        .recovery
        .list_operations(principal.organization_id, project_id, &filter)
        .await?;
    Ok(Json(RecoveryOperationList { items, next_cursor }))
}

async fn get_recovery_operation(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, operation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RecoveryOperationDetail>, ApiError> {
    let principal = principal(&headers, &state).await?;
    if !state
        .destinations
        .project_owned(principal.organization_id, project_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    state
        .service
        .recovery
        .operation_detail(principal.organization_id, project_id, operation_id)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}
