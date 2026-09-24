use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{IdentityPrincipal, UserSessionAuthenticator};
use crate::error_code::ErrorCode;
use crate::service::attention::{
    ApplicationQuery, ApplicationSummary, AttentionService, AttentionServiceError,
    OrganizationQuery, OrganizationSummary,
};
use crate::web_api::RequestId;

pub use crate::service::attention::{
    APPLICATION_ATTENTION_QUERY_BUDGET, ORGANIZATION_ATTENTION_QUERY_BUDGET,
};

#[derive(Clone)]
struct AttentionState {
    service: AttentionService,
    auth: UserSessionAuthenticator,
}

pub fn router(pool: PgPool, delivery_enabled: bool) -> Router {
    let state = AttentionState {
        auth: UserSessionAuthenticator::new(pool.clone()),
        service: AttentionService::new(pool, delivery_enabled),
    };
    Router::new()
        .route("/api/v1/attention-summary", get(organization_summary))
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/attention-summary",
            get(application_summary),
        )
        .with_state(state)
}

#[derive(Debug)]
enum AttentionError {
    Unauthorized,
    Service(AttentionServiceError),
}
impl IntoResponse for AttentionError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized => crate::web_api::uncorrelated_error_response(
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential",
            ),
            Self::Service(AttentionServiceError::Invalid(message)) => {
                crate::web_api::uncorrelated_error_response(
                    StatusCode::BAD_REQUEST,
                    ErrorCode::INVALID_REQUEST,
                    message,
                )
            }
            Self::Service(AttentionServiceError::NotFound) => {
                crate::web_api::uncorrelated_error_response(
                    StatusCode::NOT_FOUND,
                    ErrorCode::NOT_FOUND,
                    "resource not found",
                )
            }
            Self::Service(AttentionServiceError::Database(error)) => {
                tracing::error!(%error, "attention API database error");
                crate::web_api::uncorrelated_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error",
                )
            }
        }
    }
}
impl From<AttentionServiceError> for AttentionError {
    fn from(value: AttentionServiceError) -> Self {
        Self::Service(value)
    }
}
impl From<sqlx::Error> for AttentionError {
    fn from(value: sqlx::Error) -> Self {
        Self::Service(AttentionServiceError::Database(value))
    }
}

async fn principal(
    headers: &HeaderMap,
    state: &AttentionState,
) -> Result<IdentityPrincipal, AttentionError> {
    state
        .auth
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(AttentionError::Unauthorized)
}

async fn organization_summary(
    State(state): State<AttentionState>,
    headers: HeaderMap,
    Extension(_request_id): Extension<RequestId>,
    Query(q): Query<OrganizationQuery>,
) -> Result<Json<OrganizationSummary>, AttentionError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state.service.organization_summary(principal, q).await?,
    ))
}

async fn application_summary(
    State(state): State<AttentionState>,
    headers: HeaderMap,
    Extension(_request_id): Extension<RequestId>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(q): Query<ApplicationQuery>,
) -> Result<Json<ApplicationSummary>, AttentionError> {
    let principal = principal(&headers, &state).await?;
    Ok(Json(
        state
            .service
            .application_summary(principal, project_id, application_id, q)
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    #[tokio::test]
    async fn routes_reject_missing_credentials_with_correlated_no_store_error() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
            .unwrap();
        let app = crate::web_api::router(
            router(pool, false),
            &crate::web_api::WebApiConfig::default(),
        );
        for path in [
            "/api/v1/attention-summary",
            "/api/v1/projects/00000000-0000-0000-0000-000000000001/applications/00000000-0000-0000-0000-000000000002/attention-summary",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(response.headers().contains_key("x-request-id"));
        }
    }
}
