use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{UserPrincipal, UserSessionAuthenticator};
use crate::error_code::ErrorCode;
use crate::service::navigation::{
    ApplicationSummary, NavigationService, NavigationServiceError, Organization, Page, PageQuery,
    ProjectSummary, WorkerPage, WorkerPageQuery,
};
use crate::web_api::{RequestId, error_response};

#[derive(Clone, Debug)]
struct StateData {
    service: NavigationService,
    auth: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = StateData {
        auth: UserSessionAuthenticator::new(pool.clone()),
        service: NavigationService::new(pool),
    };
    Router::new()
        .route("/api/v1/organization", get(organization))
        .route("/api/v1/projects", get(projects))
        .route("/api/v1/projects/{project_id}", get(project))
        .route(
            "/api/v1/projects/{project_id}/applications",
            get(applications),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}",
            get(application),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/workers",
            get(application_workers),
        )
        .layer(middleware::from_fn(track_navigation))
        .with_state(state)
}

async fn track_navigation(request: axum::extract::Request, next: Next) -> Response {
    let response = next.run(request).await;
    crate::metrics::record_navigation(response.status().is_success());
    response
}

#[derive(Debug)]
struct NavigationError {
    status: StatusCode,
    code: ErrorCode,
    message: String,
    request_id: RequestId,
}

impl NavigationError {
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

    /// The response for a failed navigation read.
    fn from_service(error: NavigationServiceError, request_id: &RequestId) -> Self {
        match error {
            NavigationServiceError::Invalid(message) => Self::new(
                StatusCode::BAD_REQUEST,
                ErrorCode::INVALID_REQUEST,
                message,
                request_id,
            ),
            NavigationServiceError::NotFound => Self::new(
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "resource not found".into(),
                request_id,
            ),
            NavigationServiceError::Database(_error) => {
                tracing::error!(request_id=%request_id.0, "navigation API database error");
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

impl IntoResponse for NavigationError {
    fn into_response(self) -> Response {
        error_response(self.status, self.code, self.message, &self.request_id)
    }
}

/// Maps a service error onto this request's response.
fn failed(request_id: &RequestId) -> impl Fn(NavigationServiceError) -> NavigationError + '_ {
    move |error| NavigationError::from_service(error, request_id)
}

async fn principal(
    headers: &HeaderMap,
    state: &StateData,
    request_id: &RequestId,
) -> Result<UserPrincipal, NavigationError> {
    state
        .auth
        .authenticate_headers(headers)
        .await
        .map_err(|error| {
            NavigationError::from_service(NavigationServiceError::Database(error), request_id)
        })?
        .ok_or_else(|| NavigationError::unauthorized(request_id))
}

async fn organization(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<Organization>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    state
        .service
        .organization(principal)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn projects(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<ProjectSummary>>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    state
        .service
        .projects(principal, query)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn project(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(project_id): Path<Uuid>,
) -> Result<Json<ProjectSummary>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    state
        .service
        .project(principal, project_id)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn applications(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(project_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<ApplicationSummary>>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    state
        .service
        .applications(principal, project_id, query)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn application(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ApplicationSummary>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    state
        .service
        .application(principal, project_id, application_id)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn application_workers(
    State(state): State<StateData>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<WorkerPageQuery>,
) -> Result<Json<WorkerPage>, NavigationError> {
    let principal = principal(&headers, &state, &request_id).await?;
    state
        .service
        .application_workers(principal, project_id, application_id, query)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}
