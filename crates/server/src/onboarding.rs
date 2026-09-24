use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::error_code::ErrorCode;
use crate::service::onboarding::{
    FirstAdministrator, Installation, InstallationIssue, InstallationPage, InstallationRequest,
    IssuedCredential, OnboardingService, OnboardingServiceError, Readiness, SetupStatus,
};
use crate::{
    auth::{UserPrincipal, UserSessionAuthenticator},
    transactional_mail::Locale,
    user_auth::session_cookie,
    web_api::{RequestId, WebApiConfig},
};

pub use crate::service::onboarding::AgentInstallationMetadata;

#[derive(Clone)]
struct OnboardingState {
    service: OnboardingService,
    auth: UserSessionAuthenticator,
    secure_cookie: bool,
    session_lifetime: Duration,
    setup_attempts: Arc<Semaphore>,
    recent_setup_attempts: Arc<tokio::sync::Mutex<VecDeque<Instant>>>,
}

pub fn router(pool: PgPool, config: &WebApiConfig) -> Router {
    let state = OnboardingState {
        service: OnboardingService::new(pool.clone(), config),
        auth: UserSessionAuthenticator::new(pool),
        secure_cookie: config.secure_session_cookie,
        session_lifetime: config.session_lifetime,
        setup_attempts: Arc::new(Semaphore::new(4)),
        recent_setup_attempts: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
    };
    Router::new()
        .route("/api/v1/setup/status", get(setup_status))
        .route("/api/v1/setup/complete", post(complete_setup))
        .route("/api/v1/agent-installation-metadata", get(installation_metadata))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/installations", get(list_installations).post(create_installation))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/installations/{installation_id}", get(get_installation).patch(update_installation))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/installations/{installation_id}/replace-credential", post(replace_credential))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/connection-readiness", get(connection_readiness))
        .with_state(state)
}

async fn setup_status(State(state): State<OnboardingState>) -> Result<Json<SetupStatus>, ApiError> {
    state
        .service
        .setup_status()
        .await
        .map(Json)
        .map_err(ApiError::from)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupRequest {
    setup_token: String,
    email: String,
    password: String,
    display_name: String,
    locale: Locale,
}

async fn complete_setup(
    State(state): State<OnboardingState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<SetupRequest>,
) -> Result<Response, ApiError> {
    enforce_setup_rate(&state).await?;
    let _permit = state.setup_attempts.try_acquire().map_err(|_| {
        ApiError::unavailable(ErrorCode::SETUP_RATE_LIMITED, "too many setup attempts")
    })?;
    let completed = state
        .service
        .complete_setup(
            FirstAdministrator {
                setup_token: input.setup_token,
                email: input.email,
                password: input.password,
                display_name: input.display_name,
                locale: input.locale,
            },
            &request_id.0,
        )
        .await?;
    tracing::info!(request_id=%request_id.0, "first super administrator setup completed");
    let mut response = (StatusCode::CREATED, Json(completed.result)).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(
            completed.session.expose(),
            state.secure_cookie,
            state.session_lifetime,
        ),
    );
    Ok(response)
}

async fn enforce_setup_rate(state: &OnboardingState) -> Result<(), ApiError> {
    const WINDOW: Duration = Duration::from_secs(60);
    const MAX_ATTEMPTS: usize = 10;
    let now = Instant::now();
    let mut attempts = state.recent_setup_attempts.lock().await;
    while attempts
        .front()
        .is_some_and(|attempt| now.duration_since(*attempt) >= WINDOW)
    {
        attempts.pop_front();
    }
    if attempts.len() >= MAX_ATTEMPTS {
        return Err(ApiError::unavailable(
            ErrorCode::SETUP_RATE_LIMITED,
            "too many setup attempts",
        ));
    }
    attempts.push_back(now);
    Ok(())
}

async fn principal(
    headers: &HeaderMap,
    state: &OnboardingState,
) -> Result<UserPrincipal, ApiError> {
    state
        .auth
        .authenticate_headers(headers)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| {
            ApiError::unauthorized(ErrorCode::INVALID_CREDENTIAL, "authentication required")
        })
}

async fn installation_metadata(
    State(state): State<OnboardingState>,
    headers: HeaderMap,
) -> Result<Json<AgentInstallationMetadata>, ApiError> {
    principal(&headers, &state).await?;
    Ok(Json(state.service.installation_metadata()?))
}

async fn create_installation(
    State(state): State<OnboardingState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<InstallationRequest>,
) -> Result<Response, ApiError> {
    let user = principal(&headers, &state).await?;
    let key = headers.get("idempotency-key").and_then(|v| v.to_str().ok());
    let issued = state
        .service
        .create_installation(user, project_id, application_id, key, input)
        .await?;
    Ok(match issued {
        InstallationIssue::Replayed(installation) => (
            StatusCode::OK,
            Json(serde_json::json!({"installation": installation, "credential": null, "command": null})),
        )
            .into_response(),
        InstallationIssue::Issued(body) => (StatusCode::CREATED, Json(body)).into_response(),
    })
}

async fn list_installations(
    State(state): State<OnboardingState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<InstallationPage>, ApiError> {
    let user = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .list_installations(user, project_id, application_id)
            .await?,
    ))
}

async fn get_installation(
    State(state): State<OnboardingState>,
    Path((project_id, application_id, installation_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Installation>, ApiError> {
    let user = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .get_installation(user, project_id, application_id, installation_id)
            .await?,
    ))
}

async fn update_installation(
    State(state): State<OnboardingState>,
    Path((project_id, application_id, installation_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<InstallationRequest>,
) -> Result<Json<Installation>, ApiError> {
    let user = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .update_installation(user, project_id, application_id, installation_id, input)
            .await?,
    ))
}

async fn replace_credential(
    State(state): State<OnboardingState>,
    Path((project_id, application_id, installation_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<IssuedCredential>, ApiError> {
    let user = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .replace_credential(user, project_id, application_id, installation_id)
            .await?,
    ))
}

async fn connection_readiness(
    State(state): State<OnboardingState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Readiness>, ApiError> {
    let user = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .connection_readiness(user, project_id, application_id)
            .await?,
    ))
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: ErrorCode,
    message: &'static str,
}
impl ApiError {
    fn unauthorized(code: ErrorCode, message: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
            message,
        }
    }
    fn validation(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: ErrorCode::VALIDATION_FAILED,
            message,
        }
    }
    fn conflict(code: ErrorCode, message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message,
        }
    }
    fn unavailable(code: ErrorCode, message: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
            message,
        }
    }
    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: ErrorCode::NOT_FOUND,
            message: "resource not found",
        }
    }
    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ErrorCode::INTERNAL_ERROR,
            message: "internal server error",
        }
    }
    fn database(_error: impl std::fmt::Display) -> Self {
        tracing::error!("onboarding database error");
        Self::internal()
    }
}
impl From<OnboardingServiceError> for ApiError {
    fn from(error: OnboardingServiceError) -> Self {
        match error {
            OnboardingServiceError::Invalid(message) => Self::validation(message),
            OnboardingServiceError::InvalidSetupToken => Self::unauthorized(
                ErrorCode::INVALID_SETUP_TOKEN,
                "setup authorization is invalid",
            ),
            OnboardingServiceError::SetupAlreadyCompleted => Self::conflict(
                ErrorCode::SETUP_ALREADY_COMPLETED,
                "setup is already complete",
            ),
            OnboardingServiceError::MetadataUnavailable(message) => {
                Self::unavailable(ErrorCode::INSTALLATION_METADATA_UNAVAILABLE, message)
            }
            OnboardingServiceError::NotFound => Self::not_found(),
            OnboardingServiceError::IdempotencyKeyReused => Self::conflict(
                ErrorCode::IDEMPOTENCY_KEY_REUSED,
                "idempotency key was used for another request",
            ),
            OnboardingServiceError::Internal => Self::internal(),
            OnboardingServiceError::Database(error) => Self::database(error),
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({"error":self.code,"message":self.message})),
        )
            .into_response()
    }
}
