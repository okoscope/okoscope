use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::UserSessionAuthenticator;
use crate::error_code::ErrorCode;
use crate::service::agent_health::{
    AgentHealthService, AgentHealthServiceError, HealthPage, HealthQuery,
};
use crate::web_api::{RequestId, error_response};

pub use crate::service::agent_health::{
    FRESHNESS_SECONDS, HEALTH_RETENTION_HOURS, MAX_CAPABILITIES, MAX_CAPABILITY_CHARS, end_session,
    record_heartbeat, register_application_agent, validate_capabilities,
};

#[derive(Clone, Debug)]
struct HealthState {
    service: AgentHealthService,
    auth: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/agent-health",
            get(application_agent_health),
        )
        .with_state(HealthState {
            auth: UserSessionAuthenticator::new(pool.clone()),
            service: AgentHealthService::new(pool),
        })
}

#[derive(Debug)]
struct HealthError {
    status: StatusCode,
    code: ErrorCode,
    message: &'static str,
    request_id: RequestId,
}

impl HealthError {
    fn new(status: StatusCode, code: ErrorCode, message: &'static str, id: &RequestId) -> Self {
        Self {
            status,
            code,
            message,
            request_id: id.clone(),
        }
    }

    fn database(_error: &sqlx::Error, id: &RequestId) -> Self {
        tracing::error!(request_id=%id.0, "agent health database error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::INTERNAL_ERROR,
            "internal server error",
            id,
        )
    }

    /// The response for a failed agent health read.
    fn from_service(error: AgentHealthServiceError, id: &RequestId) -> Self {
        match error {
            AgentHealthServiceError::Invalid(message) => Self::new(
                StatusCode::BAD_REQUEST,
                ErrorCode::INVALID_REQUEST,
                message,
                id,
            ),
            AgentHealthServiceError::NotFound => Self::new(
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "resource not found",
                id,
            ),
            AgentHealthServiceError::Database(error) => Self::database(&error, id),
        }
    }
}

impl IntoResponse for HealthError {
    fn into_response(self) -> Response {
        error_response(self.status, self.code, self.message, &self.request_id)
    }
}

async fn application_agent_health(
    State(state): State<HealthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<HealthQuery>,
) -> Result<Json<HealthPage>, HealthError> {
    let principal = state
        .auth
        .authenticate_headers(&headers)
        .await
        .map_err(|e| HealthError::database(&e, &request_id))?
        .ok_or_else(|| {
            HealthError::new(
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential",
                &request_id,
            )
        })?;
    state
        .service
        .application_health(principal, project_id, application_id, query)
        .await
        .map(Json)
        .map_err(|error| HealthError::from_service(error, &request_id))
}
