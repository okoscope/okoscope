use crate::error_code::ErrorCode;
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::service::notifications::{
    DeliveryList, DestinationChange, DestinationWithSecret, NewDestination,
    ProjectNotificationError, ProjectNotificationService, RecoveryOperationList,
};
use crate::{
    auth::{IdentityPrincipal, UserSessionAuthenticator},
    web_api::RequestId,
};

use super::{
    NotificationService,
    health::NotificationHealthResponse,
    worker::{DeliveryDetail, DeliveryFilter, DeliverySummary},
};
use crate::service::notification_destinations::{DestinationError, WebhookDestination};
use crate::service::notification_recovery::{
    BulkRecoveryResult, BulkRetryFilter, DeliveryRecoveryResult, RecoveryConflictCode,
    RecoveryError, RecoveryOperationDetail, RecoveryOperationFilter,
};

#[derive(Clone, Debug)]
struct NotificationApiState {
    authenticator: UserSessionAuthenticator,
    service: ProjectNotificationService,
}

pub fn router(pool: PgPool, service: NotificationService) -> Router {
    let state = NotificationApiState {
        authenticator: UserSessionAuthenticator::new(pool),
        service: ProjectNotificationService::new(service),
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
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential".into(),
            ),
            Self::Invalid(message) => {
                (StatusCode::BAD_REQUEST, ErrorCode::INVALID_REQUEST, message)
            }
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "destination not found".into(),
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                ErrorCode::REVISION_CONFLICT,
                "destination revision conflict".into(),
            ),
            Self::RecoveryConflict(conflict) => (
                StatusCode::CONFLICT,
                match conflict {
                    RecoveryConflictCode::InvalidState => ErrorCode::DELIVERY_INVALID_STATE,
                    RecoveryConflictCode::ActiveLease => ErrorCode::DELIVERY_ACTIVE_LEASE,
                    RecoveryConflictCode::DestinationDisabled => ErrorCode::DESTINATION_DISABLED,
                    RecoveryConflictCode::IdempotencyKeyReused => ErrorCode::IDEMPOTENCY_KEY_REUSED,
                    RecoveryConflictCode::BulkLimitExceeded => ErrorCode::BULK_LIMIT_EXCEEDED,
                },
                "notification recovery command conflicts with current state".into(),
            ),
            Self::Database(error) => {
                tracing::error!(error=%error, "notification API database error");
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

impl From<ProjectNotificationError> for ApiError {
    fn from(error: ProjectNotificationError) -> Self {
        match error {
            ProjectNotificationError::NotFound => Self::NotFound,
            ProjectNotificationError::Invalid(message) => Self::Invalid(message),
            ProjectNotificationError::Destination(error) => error.into(),
            ProjectNotificationError::Recovery(error) => error.into(),
            ProjectNotificationError::Database(error) => Self::Database(error),
        }
    }
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

/// The raw `Idempotency-Key` header; the service requires it.
fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
}

async fn principal(
    headers: &HeaderMap,
    state: &NotificationApiState,
) -> Result<IdentityPrincipal, ApiError> {
    state
        .authenticator
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)
}

async fn list(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
) -> Result<Json<Vec<WebhookDestination>>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .list_destinations(principal, project_id)
            .await?,
    ))
}

async fn get_destination(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, destination_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<WebhookDestination>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .get_destination(principal, project_id, destination_id)
            .await?,
    ))
}

async fn create(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Json(input): Json<CreateDestination>,
) -> Result<(StatusCode, Json<DestinationWithSecret>), ApiError> {
    let principal = principal(&headers, &state).await?;
    let created = state
        .service
        .create_destination(
            principal,
            project_id,
            NewDestination {
                name: input.name,
                url: input.url,
                deliver_backfill: input.deliver_backfill,
            },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn update(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, destination_id)): Path<(Uuid, Uuid)>,
    Json(input): Json<UpdateDestination>,
) -> Result<Json<WebhookDestination>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .update_destination(
                principal,
                project_id,
                destination_id,
                DestinationChange {
                    name: input.name,
                    url: input.url,
                    deliver_backfill: input.deliver_backfill,
                    enabled: input.enabled,
                    revision: input.revision,
                },
            )
            .await?,
    ))
}

async fn disable(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, destination_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<WebhookDestination>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .disable_destination(principal, project_id, destination_id)
            .await?,
    ))
}

async fn rotate_secret(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, destination_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DestinationWithSecret>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .rotate_secret(principal, project_id, destination_id)
            .await?,
    ))
}

async fn test(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, destination_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeliverySummary>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .test_destination(principal, project_id, destination_id)
            .await?,
    ))
}

async fn list_delivery_history(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    axum::extract::Query(filter): axum::extract::Query<DeliveryFilter>,
) -> Result<Json<DeliveryList>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .list_deliveries(principal, project_id, filter)
            .await?,
    ))
}

async fn notification_health(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
) -> Result<Json<NotificationHealthResponse>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(state.service.health(principal, project_id).await?))
}

async fn get_delivery_history(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, delivery_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeliveryDetail>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .get_delivery(principal, project_id, delivery_id)
            .await?,
    ))
}

async fn retry_delivery(
    State(state): State<NotificationApiState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((project_id, delivery_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeliveryRecoveryResult>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .retry_delivery(
                principal,
                project_id,
                delivery_id,
                idempotency_key(&headers),
                &request_id.0,
            )
            .await?,
    ))
}

async fn cancel_delivery(
    State(state): State<NotificationApiState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((project_id, delivery_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeliveryRecoveryResult>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .cancel_delivery(
                principal,
                project_id,
                delivery_id,
                idempotency_key(&headers),
                &request_id.0,
            )
            .await?,
    ))
}

async fn bulk_retry_deliveries(
    State(state): State<NotificationApiState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Json(filter): Json<BulkRetryFilter>,
) -> Result<Json<BulkRecoveryResult>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .bulk_retry(
                principal,
                project_id,
                filter,
                idempotency_key(&headers),
                &request_id.0,
            )
            .await?,
    ))
}

async fn list_recovery_operations(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    axum::extract::Query(filter): axum::extract::Query<RecoveryOperationFilter>,
) -> Result<Json<RecoveryOperationList>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .list_recovery_operations(principal, project_id, filter)
            .await?,
    ))
}

async fn get_recovery_operation(
    State(state): State<NotificationApiState>,
    headers: HeaderMap,
    Path((project_id, operation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RecoveryOperationDetail>, ApiError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .get_recovery_operation(principal, project_id, operation_id)
            .await?,
    ))
}
