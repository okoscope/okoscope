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

use crate::error_code::ErrorCode;
use crate::service::provisioning::{
    ApplicationPage, ApplicationResponse, Created, CreatedApplicationResponse, CredentialPage,
    IssuedCredentialResponse, NamedResource, OrganizationPage, OrganizationResponse, ProjectPage,
    ProjectResponse, ProvisioningConflict, ProvisioningService, ProvisioningServiceError,
    ProvisioningTarget, store_error,
};
use crate::{
    admin_auth::AdminAuthenticator,
    auth::{IdentityPrincipal, UserSessionAuthenticator, session_token},
    transactional_mail::MailConfig,
    web_api::RequestId,
};

#[derive(Clone, Debug)]
struct ProvisioningState {
    service: ProvisioningService,
    tenant: UserSessionAuthenticator,
}

pub fn router(pool: PgPool, _admin: Option<AdminAuthenticator>, mail: MailConfig) -> Router {
    Router::new()
        .route("/api/v1/organizations", post(create_organization))
        .route("/api/v1/admin/organizations", get(list_organizations))
        .route(
            "/api/v1/admin/organizations/{organization_id}/projects",
            get(list_projects),
        )
        .route(
            "/api/v1/admin/projects/{project_id}/applications",
            get(list_applications),
        )
        .route(
            "/api/v1/admin/projects/{project_id}/applications/{application_id}",
            get(get_application),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects",
            post(create_project),
        )
        .route(
            "/api/v1/projects/{project_id}/applications",
            post(create_application),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/credentials",
            axum::routing::get(list_application_credentials).post(issue_application_credential),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/credentials/{credential_id}",
            axum::routing::delete(revoke_application_credential),
        )
        .route(
            "/api/v1/platform/projects/{project_id}/applications/{application_id}/credentials",
            axum::routing::get(list_application_credentials).post(issue_application_credential),
        )
        .route(
            "/api/v1/platform/projects/{project_id}/applications/{application_id}/credentials/{credential_id}",
            axum::routing::delete(revoke_application_credential),
        )
        .with_state(ProvisioningState {
            service: ProvisioningService::new(pool.clone(), mail),
            tenant: UserSessionAuthenticator::new(pool),
        })
}

#[derive(Debug)]
struct ProvisioningError {
    status: StatusCode,
    code: ErrorCode,
    message: String,
    request_id: RequestId,
    fields: Option<std::collections::BTreeMap<&'static str, String>>,
}

impl ProvisioningError {
    fn new(status: StatusCode, code: ErrorCode, message: &str, request_id: &RequestId) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            request_id: request_id.clone(),
            fields: None,
        }
    }

    /// The response for a failed provisioning use case.
    fn from_service(error: ProvisioningServiceError, request_id: &RequestId) -> Self {
        match error {
            ProvisioningServiceError::InvalidCredential => Self::new(
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential",
                request_id,
            ),
            ProvisioningServiceError::SuperAdminRequired => Self::new(
                StatusCode::FORBIDDEN,
                ErrorCode::FORBIDDEN,
                "super administrator role is required",
                request_id,
            ),
            ProvisioningServiceError::OwnerRequired => Self::new(
                StatusCode::FORBIDDEN,
                ErrorCode::FORBIDDEN,
                "owner role is required",
                request_id,
            ),
            ProvisioningServiceError::Invalid { field, detail } => Self {
                fields: Some(std::collections::BTreeMap::from([(field, detail.into())])),
                ..Self::new(
                    StatusCode::BAD_REQUEST,
                    ErrorCode::VALIDATION_FAILED,
                    "the request contains invalid fields",
                    request_id,
                )
            },
            ProvisioningServiceError::NotFound(target) => Self::new(
                StatusCode::NOT_FOUND,
                match target {
                    ProvisioningTarget::Organization => ErrorCode::ORGANIZATION_NOT_FOUND,
                    ProvisioningTarget::Project => ErrorCode::PROJECT_NOT_FOUND,
                    ProvisioningTarget::Application => ErrorCode::APPLICATION_NOT_FOUND,
                    ProvisioningTarget::Credential => ErrorCode::CREDENTIAL_NOT_FOUND,
                },
                "resource not found",
                request_id,
            ),
            ProvisioningServiceError::Conflict(conflict) => Self::new(
                StatusCode::CONFLICT,
                match conflict {
                    ProvisioningConflict::OrganizationSlug => ErrorCode::ORGANIZATION_SLUG_CONFLICT,
                    ProvisioningConflict::ProjectSlug => ErrorCode::PROJECT_SLUG_CONFLICT,
                    ProvisioningConflict::ApplicationSlug => ErrorCode::APPLICATION_SLUG_CONFLICT,
                    ProvisioningConflict::CredentialName => ErrorCode::CREDENTIAL_NAME_CONFLICT,
                    ProvisioningConflict::Credential => ErrorCode::CREDENTIAL_CONFLICT,
                    ProvisioningConflict::IdempotencyKeyReused => ErrorCode::IDEMPOTENCY_KEY_REUSED,
                    ProvisioningConflict::OperationAlreadyCompleted => {
                        ErrorCode::OPERATION_ALREADY_COMPLETED
                    }
                },
                "resource already exists",
                request_id,
            ),
            ProvisioningServiceError::MailPayloadRejected => {
                tracing::error!(request_id=%request_id.0, "application mail payload rejected");
                Self::internal(request_id)
            }
            ProvisioningServiceError::Database(error) => {
                tracing::error!(error=%error, request_id=%request_id.0, "provisioning database error");
                Self::internal(request_id)
            }
        }
    }

    fn internal(request_id: &RequestId) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::INTERNAL_ERROR,
            "internal server error",
            request_id,
        )
    }
}

impl IntoResponse for ProvisioningError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body {
            error: ErrorCode,
            message: String,
            request_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            fields: Option<std::collections::BTreeMap<&'static str, String>>,
        }
        (
            self.status,
            Json(Body {
                error: self.code,
                message: self.message,
                request_id: self.request_id.0,
                fields: self.fields,
            }),
        )
            .into_response()
    }
}

/// Maps a service error onto this request's response.
fn failed(request_id: &RequestId) -> impl Fn(ProvisioningServiceError) -> ProvisioningError + '_ {
    move |error| ProvisioningError::from_service(error, request_id)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateNamedResource {
    slug: String,
    name: String,
}

impl From<CreateNamedResource> for NamedResource {
    fn from(input: CreateNamedResource) -> Self {
        Self {
            slug: input.slug,
            name: input.name,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueCredentialRequest {
    name: String,
}

async fn authenticate(
    state: &ProvisioningState,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> Result<IdentityPrincipal, ProvisioningError> {
    let invalid =
        || ProvisioningError::from_service(ProvisioningServiceError::InvalidCredential, request_id);
    let presented = session_token(headers).ok_or_else(invalid)?;
    state
        .tenant
        .authenticate_identity(presented)
        .await
        .map_err(|error| {
            ProvisioningError::from_service(
                store_error(error, ProvisioningConflict::Credential),
                request_id,
            )
        })?
        .ok_or_else(invalid)
}

fn idempotency_key(headers: &HeaderMap) -> Option<&[u8]> {
    headers
        .get("idempotency-key")
        .map(axum::http::HeaderValue::as_bytes)
}

fn created<T: Serialize>(created: Created<T>) -> (StatusCode, Json<T>) {
    match created {
        Created::New(value) => (StatusCode::CREATED, Json(value)),
        Created::Replayed(value) => (StatusCode::OK, Json(value)),
    }
}

async fn list_organizations(
    State(state): State<ProvisioningState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<OrganizationPage>, ProvisioningError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    state
        .service
        .list_organizations(principal)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn list_projects(
    State(state): State<ProvisioningState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<ProjectPage>, ProvisioningError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    state
        .service
        .list_projects(principal, organization_id)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn list_applications(
    State(state): State<ProvisioningState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<ApplicationPage>, ProvisioningError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    state
        .service
        .list_applications(principal, project_id)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn get_application(
    State(state): State<ProvisioningState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<ApplicationResponse>, ProvisioningError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    state
        .service
        .get_application(principal, project_id, application_id)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn create_organization(
    State(state): State<ProvisioningState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreateNamedResource>,
) -> Result<(StatusCode, Json<OrganizationResponse>), ProvisioningError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    state
        .service
        .create_organization(principal, input.into(), idempotency_key(&headers))
        .await
        .map(created)
        .map_err(failed(&request_id))
}

async fn create_project(
    State(state): State<ProvisioningState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreateNamedResource>,
) -> Result<(StatusCode, Json<ProjectResponse>), ProvisioningError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    state
        .service
        .create_project(
            principal,
            organization_id,
            input.into(),
            idempotency_key(&headers),
        )
        .await
        .map(created)
        .map_err(failed(&request_id))
}

async fn create_application(
    State(state): State<ProvisioningState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreateNamedResource>,
) -> Result<(StatusCode, Json<CreatedApplicationResponse>), ProvisioningError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    let response = state
        .service
        .create_application(
            principal,
            project_id,
            input.into(),
            idempotency_key(&headers),
        )
        .await
        .map_err(failed(&request_id))?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn list_application_credentials(
    State(state): State<ProvisioningState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<CredentialPage>, ProvisioningError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    state
        .service
        .list_credentials(principal, project_id, application_id)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn issue_application_credential(
    State(state): State<ProvisioningState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<IssueCredentialRequest>,
) -> Result<(StatusCode, Json<IssuedCredentialResponse>), ProvisioningError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    let response = state
        .service
        .issue_credential(
            principal,
            project_id,
            application_id,
            &input.name,
            idempotency_key(&headers),
        )
        .await
        .map_err(failed(&request_id))?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn revoke_application_credential(
    State(state): State<ProvisioningState>,
    Path((project_id, application_id, credential_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, ProvisioningError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    state
        .service
        .revoke_credential(principal, project_id, application_id, credential_id)
        .await
        .map_err(failed(&request_id))?;
    Ok(StatusCode::NO_CONTENT)
}
