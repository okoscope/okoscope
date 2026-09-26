use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error_code::ErrorCode;
use crate::service::invitations::{
    InvitationConflict, InvitationService, InvitationServiceError, InvitationTarget, NewInvitation,
    NewUserAcceptance,
};
use crate::{
    auth::{IdentityPrincipal, UserSessionAuthenticator, session_token},
    transactional_mail::Locale,
    user_auth::session_cookie,
    web_api::{RequestId, WebApiConfig},
};

#[derive(Clone, Debug)]
struct InvitationState {
    service: InvitationService,
    auth: UserSessionAuthenticator,
    secure_cookie: bool,
    session_lifetime: std::time::Duration,
}

pub fn router(pool: PgPool, config: &WebApiConfig) -> Router {
    Router::new()
        .route("/api/v1/platform/invitations", get(list_platform))
        .route(
            "/api/v1/platform/organizations/{organization_id}/invitations",
            get(list_platform_organization).post(create_platform_organization),
        )
        .route(
            "/api/v1/platform/organizations/{organization_id}/invitations/{invitation_id}",
            delete(revoke_platform_organization),
        )
        .route(
            "/api/v1/platform/organizations/{organization_id}/invitations/{invitation_id}/resend",
            post(resend_platform_organization),
        )
        .route(
            "/api/v1/platform/projects/{project_id}/invitations",
            get(list_platform_project).post(create_platform_project),
        )
        .route(
            "/api/v1/platform/projects/{project_id}/invitations/{invitation_id}",
            delete(revoke_platform_project),
        )
        .route(
            "/api/v1/platform/projects/{project_id}/invitations/{invitation_id}/resend",
            post(resend_platform_project),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations",
            get(list_organization).post(create_organization),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations/{invitation_id}",
            delete(revoke_organization),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations/{invitation_id}/resend",
            post(resend_organization),
        )
        .route(
            "/api/v1/projects/{project_id}/invitations",
            get(list_project).post(create_project),
        )
        .route(
            "/api/v1/projects/{project_id}/invitations/{invitation_id}",
            delete(revoke_project),
        )
        .route(
            "/api/v1/projects/{project_id}/invitations/{invitation_id}/resend",
            post(resend_project),
        )
        .route("/api/v1/invitations/inspections", post(inspect))
        .route(
            "/api/v1/invitations/acceptances/new-user",
            post(accept_new_user),
        )
        .route(
            "/api/v1/invitations/acceptances/existing-user",
            post(accept_existing_user),
        )
        .with_state(InvitationState {
            service: InvitationService::new(pool.clone(), config),
            auth: UserSessionAuthenticator::new(pool),
            secure_cookie: config.secure_session_cookie,
            session_lifetime: config.session_lifetime,
        })
}

#[derive(Debug)]
pub(crate) struct InvitationError {
    status: StatusCode,
    code: ErrorCode,
    message: &'static str,
    request_id: RequestId,
}

impl InvitationError {
    fn new(
        status: StatusCode,
        code: ErrorCode,
        message: &'static str,
        request_id: &RequestId,
    ) -> Self {
        Self {
            status,
            code,
            message,
            request_id: request_id.clone(),
        }
    }

    fn database(_error: &sqlx::Error, request_id: &RequestId) -> Self {
        tracing::error!(request_id=%request_id.0, "invitation database operation failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::INTERNAL_ERROR,
            "internal server error",
            request_id,
        )
    }

    /// The response for a failed invitation use case.
    pub(crate) fn from_service(error: InvitationServiceError, request_id: &RequestId) -> Self {
        let (status, code, message) = match error {
            InvitationServiceError::SuperAdminRequired => (
                StatusCode::FORBIDDEN,
                ErrorCode::FORBIDDEN,
                "super administrator role is required",
            ),
            InvitationServiceError::NotFound(target) => (
                StatusCode::NOT_FOUND,
                match target {
                    InvitationTarget::Organization => ErrorCode::ORGANIZATION_NOT_FOUND,
                    InvitationTarget::Project => ErrorCode::PROJECT_NOT_FOUND,
                    InvitationTarget::Scope => ErrorCode::INVITATION_SCOPE_NOT_FOUND,
                    InvitationTarget::Invitation => ErrorCode::INVITATION_NOT_FOUND,
                },
                "resource not found",
            ),
            InvitationServiceError::Forbidden => (
                StatusCode::FORBIDDEN,
                ErrorCode::FORBIDDEN,
                "insufficient permission",
            ),
            InvitationServiceError::Invalid(message) => (
                StatusCode::BAD_REQUEST,
                ErrorCode::VALIDATION_FAILED,
                message,
            ),
            InvitationServiceError::InvalidLimit => (
                StatusCode::BAD_REQUEST,
                ErrorCode::INVALID_REQUEST,
                "limit must be between 1 and 100",
            ),
            InvitationServiceError::Conflict(conflict) => (
                StatusCode::CONFLICT,
                match conflict {
                    InvitationConflict::MembershipExists => ErrorCode::MEMBERSHIP_EXISTS,
                    InvitationConflict::InvitationExists => ErrorCode::INVITATION_EXISTS,
                    InvitationConflict::NotPending => ErrorCode::INVITATION_NOT_PENDING,
                    InvitationConflict::RequiresSignIn => ErrorCode::INVITATION_REQUIRES_SIGN_IN,
                    InvitationConflict::AccountMismatch => ErrorCode::INVITATION_ACCOUNT_MISMATCH,
                    InvitationConflict::IdentityConflict => ErrorCode::INVITATION_IDENTITY_CONFLICT,
                },
                "invitation conflicts with current state",
            ),
            InvitationServiceError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::RATE_LIMITED,
                "invitation rate limit exceeded",
            ),
            InvitationServiceError::MailUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::MAIL_UNAVAILABLE,
                "invitation mail is unavailable",
            ),
            InvitationServiceError::MailIntent(_error) => {
                tracing::error!(request_id=%request_id.0, "invitation mail intent failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::MAIL_UNAVAILABLE,
                    "invitation mail is unavailable",
                )
            }
            InvitationServiceError::Unusable => (
                StatusCode::GONE,
                ErrorCode::INVITATION_UNUSABLE,
                "invitation is unavailable",
            ),
            InvitationServiceError::PasswordHashing => {
                tracing::error!(request_id=%request_id.0, "invitation password hashing failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error",
                )
            }
            InvitationServiceError::Database(error) => return Self::database(&error, request_id),
        };
        Self::new(status, code, message, request_id)
    }
}

impl IntoResponse for InvitationError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body {
            error: ErrorCode,
            message: &'static str,
            request_id: String,
        }
        crate::metrics::record_invitation_lifecycle(false);
        tracing::warn!(
            status = self.status.as_u16(),
            error = %self.code,
            "invitation operation rejected"
        );
        let mut response = (
            self.status,
            Json(Body {
                error: self.code,
                message: self.message,
                request_id: self.request_id.0,
            }),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// Maps a service error onto this request's response.
fn failed(request_id: &RequestId) -> impl Fn(InvitationServiceError) -> InvitationError + '_ {
    move |error| InvitationError::from_service(error, request_id)
}

#[derive(Debug, Deserialize)]
struct CreateInvitationRequest {
    email: String,
    role: String,
    locale: Locale,
}

impl From<CreateInvitationRequest> for NewInvitation {
    fn from(input: CreateInvitationRequest) -> Self {
        Self {
            email: input.email,
            role: input.role,
            locale: input.locale,
        }
    }
}

#[derive(Debug, Deserialize)]
struct InvitationTokenRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
struct NewUserAcceptanceRequest {
    token: String,
    password: String,
    display_name: String,
    locale: Locale,
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

async fn identity(
    state: &InvitationState,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> Result<IdentityPrincipal, InvitationError> {
    state
        .auth
        .authenticate_identity(session_token(headers).unwrap_or_default())
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?
        .ok_or_else(|| {
            InvitationError::new(
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "authentication required",
                request_id,
            )
        })
}

fn no_store<T: Serialize>(status: StatusCode, value: T) -> Response {
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn list_platform(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let page = state
        .service
        .list_platform(principal, query.cursor, query.limit)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::OK, page))
}

async fn list_platform_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let page = state
        .service
        .list_platform_organization(principal, organization_id, query.cursor, query.limit)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::OK, page))
}

async fn list_platform_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let page = state
        .service
        .list_platform_project(principal, project_id, query.cursor, query.limit)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::OK, page))
}

async fn list_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let page = state
        .service
        .list_organization(principal, organization_id, query.cursor, query.limit)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::OK, page))
}

async fn list_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let page = state
        .service
        .list_project(principal, project_id, query.cursor, query.limit)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::OK, page))
}

async fn create_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(input): Json<CreateInvitationRequest>,
) -> Result<Response, InvitationError> {
    // Unavailable mail is reported before authentication.
    state.service.require_mail().map_err(failed(&request_id))?;
    let principal = identity(&state, &headers, &request_id).await?;
    let invitation = state
        .service
        .create_organization(principal, organization_id, input.into(), &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::CREATED, invitation))
}

async fn create_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Json(input): Json<CreateInvitationRequest>,
) -> Result<Response, InvitationError> {
    // Unavailable mail is reported before authentication.
    state.service.require_mail().map_err(failed(&request_id))?;
    let principal = identity(&state, &headers, &request_id).await?;
    let invitation = state
        .service
        .create_project(principal, project_id, input.into(), &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::CREATED, invitation))
}

async fn create_platform_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(input): Json<CreateInvitationRequest>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let invitation = state
        .service
        .create_platform_organization(principal, organization_id, input.into(), &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::CREATED, invitation))
}

async fn create_platform_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Json(input): Json<CreateInvitationRequest>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let invitation = state
        .service
        .create_platform_project(principal, project_id, input.into(), &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::CREATED, invitation))
}

async fn resend_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((organization_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    // Unavailable mail is reported before authentication.
    state.service.require_mail().map_err(failed(&request_id))?;
    let principal = identity(&state, &headers, &request_id).await?;
    let replacement = state
        .service
        .resend_organization(principal, organization_id, invitation_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::CREATED, replacement))
}

async fn resend_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((project_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    // Unavailable mail is reported before authentication.
    state.service.require_mail().map_err(failed(&request_id))?;
    let principal = identity(&state, &headers, &request_id).await?;
    let replacement = state
        .service
        .resend_project(principal, project_id, invitation_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::CREATED, replacement))
}

async fn resend_platform_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((organization_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let replacement = state
        .service
        .resend_platform_organization(principal, organization_id, invitation_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::CREATED, replacement))
}

async fn resend_platform_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((project_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let replacement = state
        .service
        .resend_platform_project(principal, project_id, invitation_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::CREATED, replacement))
}

async fn revoke_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((organization_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .revoke_organization(principal, organization_id, invitation_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::NO_CONTENT, ()))
}

async fn revoke_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((project_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .revoke_project(principal, project_id, invitation_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::NO_CONTENT, ()))
}

async fn revoke_platform_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((organization_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .revoke_platform_organization(principal, organization_id, invitation_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::NO_CONTENT, ()))
}

async fn revoke_platform_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((project_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .revoke_platform_project(principal, project_id, invitation_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::NO_CONTENT, ()))
}

async fn inspect(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<InvitationTokenRequest>,
) -> Result<Response, InvitationError> {
    let inspection = state
        .service
        .inspect(&input.token)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::OK, inspection))
}

async fn accept_new_user(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<NewUserAcceptanceRequest>,
) -> Result<Response, InvitationError> {
    let accepted = state
        .service
        .accept_new_user(
            NewUserAcceptance {
                token: input.token,
                password: input.password,
                display_name: input.display_name,
                locale: input.locale,
            },
            &request_id.0,
        )
        .await
        .map_err(failed(&request_id))?;
    let mut response = no_store(StatusCode::CREATED, accepted.acceptance);
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(
            accepted.session.expose(),
            state.secure_cookie,
            state.session_lifetime,
        ),
    );
    Ok(response)
}

async fn accept_existing_user(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(input): Json<InvitationTokenRequest>,
) -> Result<Response, InvitationError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let acceptance = state
        .service
        .accept_existing_user(principal, &input.token, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(no_store(StatusCode::OK, acceptance))
}
