use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch, post, put},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error_code::ErrorCode;
use crate::invitation_api::InvitationError;
use crate::service::access::{
    AccessConflict, AccessService, AccessServiceError, AccessTarget, AuditPage,
    AuthenticationPolicy, CreatedPlatformApplication, Denial, NamedResource,
    NewPlatformOrganization, OrganizationMember, OrganizationMemberPage, Ownership, PageRequest,
    PlatformApplicationPage, PlatformOrganization, PlatformOrganizationPage, PlatformProject,
    PlatformProjectPage, ProjectMember, ProjectMemberPage, UserPage, UserSummary,
};
use crate::{
    access_control::ProjectRole,
    auth::{IdentityPrincipal, OrganizationRole, UserSessionAuthenticator, session_token},
    transactional_mail::Locale,
    user_auth::session_cookie,
    web_api::{RequestId, WebApiConfig},
};

#[derive(Clone, Debug)]
struct AccessState {
    service: AccessService,
    auth: UserSessionAuthenticator,
    secure_cookie: bool,
    session_lifetime: std::time::Duration,
}

pub fn router(pool: PgPool, config: &WebApiConfig) -> Router {
    Router::new()
        .route(
            "/api/v1/auth/organization-selections",
            post(select_organization),
        )
        .route("/api/v1/auth/policy", get(authentication_policy))
        .route(
            "/api/v1/auth/privilege-confirmations",
            post(confirm_privilege),
        )
        .route("/api/v1/platform/users", get(list_platform_users))
        .route(
            "/api/v1/platform/organizations",
            get(list_platform_organizations).post(create_platform_organization),
        )
        .route(
            "/api/v1/platform/organizations/{organization_id}",
            get(get_platform_organization).delete(delete_platform_organization),
        )
        .route(
            "/api/v1/platform/organizations/{organization_id}/projects",
            get(list_platform_projects).post(create_platform_project),
        )
        .route(
            "/api/v1/platform/projects/{project_id}/applications",
            get(list_platform_applications).post(create_platform_application),
        )
        .route(
            "/api/v1/platform/users/{user_id}/status",
            patch(set_user_status),
        )
        .route(
            "/api/v1/platform/users/{user_id}/roles/super-admin",
            put(grant_super_admin).delete(revoke_super_admin),
        )
        .route("/api/v1/platform/audit", get(list_platform_audit))
        .route(
            "/api/v1/organizations/{organization_id}/members",
            get(list_organization_members),
        )
        .route(
            "/api/v1/organizations/{organization_id}/members/{user_id}",
            patch(update_organization_member).delete(remove_organization_member),
        )
        .route(
            "/api/v1/platform/organizations/{organization_id}/members",
            get(list_organization_members),
        )
        .route(
            "/api/v1/platform/organizations/{organization_id}/members/{user_id}",
            patch(update_organization_member).delete(remove_organization_member),
        )
        .route(
            "/api/v1/organizations/{organization_id}/audit",
            get(list_audit),
        )
        .route(
            "/api/v1/projects/{project_id}/members",
            get(list_project_members).post(add_project_member),
        )
        .route(
            "/api/v1/projects/{project_id}/members/{user_id}",
            patch(update_project_member).delete(remove_project_member),
        )
        .route(
            "/api/v1/projects/{project_id}/eligible-organization-members",
            get(list_eligible_project_members),
        )
        .route(
            "/api/v1/platform/projects/{project_id}/members",
            get(list_project_members).post(add_project_member),
        )
        .route(
            "/api/v1/platform/projects/{project_id}/eligible-organization-members",
            get(list_eligible_project_members),
        )
        .route(
            "/api/v1/platform/projects/{project_id}/members/{user_id}",
            patch(update_project_member).delete(remove_project_member),
        )
        .with_state(AccessState {
            service: AccessService::new(pool.clone(), config),
            auth: UserSessionAuthenticator::new(pool),
            secure_cookie: config.secure_session_cookie,
            session_lifetime: config.session_lifetime,
        })
}

async fn authentication_policy(State(state): State<AccessState>) -> Json<AuthenticationPolicy> {
    Json(state.service.authentication_policy())
}

#[derive(Debug)]
enum AccessError {
    Rejected {
        status: StatusCode,
        code: ErrorCode,
        message: &'static str,
        request_id: RequestId,
    },
    /// Inviting a new organization's first owner failed; the invitation API's
    /// response is sent as it is.
    Invitation(InvitationError),
}

impl AccessError {
    fn new(status: StatusCode, code: ErrorCode, message: &'static str, id: &RequestId) -> Self {
        Self::Rejected {
            status,
            code,
            message,
            request_id: id.clone(),
        }
    }

    fn database(_error: &sqlx::Error, request_id: &RequestId) -> Self {
        tracing::error!(request_id=%request_id.0, "access control database operation failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::INTERNAL_ERROR,
            "internal server error",
            request_id,
        )
    }

    /// The response for a failed access use case.
    fn from_service(error: AccessServiceError, request_id: &RequestId) -> Self {
        let (status, code, message) = match error {
            AccessServiceError::SuperAdminRequired => (
                StatusCode::FORBIDDEN,
                ErrorCode::FORBIDDEN,
                "super administrator role is required",
            ),
            AccessServiceError::PrivilegeConfirmationRequired => (
                StatusCode::FORBIDDEN,
                ErrorCode::PRIVILEGE_CONFIRMATION_REQUIRED,
                "recent password confirmation is required",
            ),
            AccessServiceError::NotFound(target) => (
                StatusCode::NOT_FOUND,
                match target {
                    AccessTarget::Organization => ErrorCode::ORGANIZATION_NOT_FOUND,
                    AccessTarget::Project => ErrorCode::PROJECT_NOT_FOUND,
                    AccessTarget::User => ErrorCode::USER_NOT_FOUND,
                },
                "resource not found",
            ),
            AccessServiceError::Denied(denial) => (
                StatusCode::FORBIDDEN,
                ErrorCode::FORBIDDEN,
                match denial {
                    Denial::OrganizationAdministration => "Organization administration is required",
                    Denial::OwnerRequired => "owner role is required",
                    Denial::RoleTransition => "role transition is forbidden",
                    Denial::MembershipRemoval => "membership removal is forbidden",
                    Denial::ProjectAdministration => "Project administration is required",
                    Denial::ProjectRoleGrant => "Project role grant is forbidden",
                    Denial::ProjectRoleTransition => "Project role transition is forbidden",
                    Denial::ProjectMembershipRemoval => "Project membership removal is forbidden",
                },
            ),
            AccessServiceError::SelfPromotion => (
                StatusCode::FORBIDDEN,
                ErrorCode::SELF_PROMOTION_FORBIDDEN,
                "self promotion is forbidden",
            ),
            AccessServiceError::CurrentPasswordInvalid => (
                StatusCode::BAD_REQUEST,
                ErrorCode::CURRENT_PASSWORD_INVALID,
                "current password is incorrect",
            ),
            AccessServiceError::Invalid(message) => (
                StatusCode::BAD_REQUEST,
                ErrorCode::VALIDATION_FAILED,
                message,
            ),
            AccessServiceError::UserNotEligible => (
                StatusCode::CONFLICT,
                ErrorCode::USER_NOT_ELIGIBLE,
                "user is not eligible",
            ),
            AccessServiceError::Conflict(conflict) => (
                StatusCode::CONFLICT,
                match conflict {
                    AccessConflict::OrganizationLimitReached => {
                        ErrorCode::ORGANIZATION_LIMIT_REACHED
                    }
                    AccessConflict::OrganizationNotDeletable => {
                        ErrorCode::ORGANIZATION_NOT_DELETABLE
                    }
                    AccessConflict::LastSuperAdminRequired => ErrorCode::LAST_SUPER_ADMIN_REQUIRED,
                    AccessConflict::MembershipExists => ErrorCode::MEMBERSHIP_EXISTS,
                    AccessConflict::LastOrganizationOwnerRequired => {
                        ErrorCode::LAST_ORGANIZATION_OWNER_REQUIRED
                    }
                },
                "access mutation conflicts with current authority",
            ),
            AccessServiceError::UnreadableMember => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::INTERNAL_ERROR,
                "internal server error",
            ),
            AccessServiceError::Invitation(error) => {
                return Self::Invitation(InvitationError::from_service(error, request_id));
            }
            AccessServiceError::Database(error) => return Self::database(&error, request_id),
        };
        Self::new(status, code, message, request_id)
    }
}

impl IntoResponse for AccessError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body {
            error: ErrorCode,
            message: &'static str,
            request_id: String,
        }
        let (status, code, message, request_id) = match self {
            Self::Rejected {
                status,
                code,
                message,
                request_id,
            } => (status, code, message, request_id),
            Self::Invitation(error) => return error.into_response(),
        };
        if matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND) {
            crate::metrics::record_access_denial();
            tracing::warn!(
                status = status.as_u16(),
                error = %code,
                "access denied"
            );
        }
        (
            status,
            Json(Body {
                error: code,
                message,
                request_id: request_id.0,
            }),
        )
            .into_response()
    }
}

/// Maps a service error onto this request's response.
fn failed(request_id: &RequestId) -> impl Fn(AccessServiceError) -> AccessError + '_ {
    move |error| AccessError::from_service(error, request_id)
}

async fn identity(
    state: &AccessState,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> Result<IdentityPrincipal, AccessError> {
    state
        .auth
        .authenticate_identity(session_token(headers).unwrap_or_default())
        .await
        .map_err(|error| AccessError::database(&error, request_id))?
        .ok_or_else(|| {
            AccessError::new(
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "authentication required",
                request_id,
            )
        })
}

fn with_session<T: Serialize>(
    state: &AccessState,
    body: T,
    session: &crate::auth::SessionToken,
) -> Response {
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(
            session.expose(),
            state.secure_cookie,
            state.session_lifetime,
        ),
    );
    response
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrganizationSelection {
    organization_id: Uuid,
}

async fn select_organization(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<OrganizationSelection>,
) -> Result<Response, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let change = state
        .service
        .select_organization(principal, input.organization_id)
        .await
        .map_err(failed(&request_id))?;
    Ok(with_session(&state, change.result, &change.session))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegeConfirmation {
    current_password: String,
}

async fn confirm_privilege(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<PrivilegeConfirmation>,
) -> Result<Response, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let change = state
        .service
        .confirm_privilege(principal, &input.current_password, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    crate::metrics::record_privilege_confirmation();
    Ok(with_session(&state, change.result, &change.session))
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

impl From<PageQuery> for PageRequest {
    fn from(query: PageQuery) -> Self {
        Self {
            cursor: query.cursor,
            limit: query.limit,
        }
    }
}

async fn list_platform_users(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<UserPage>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .list_platform_users(principal, page.into())
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PlatformOwnership {
    InvitedOwner { email: String, locale: Locale },
    SelfOwner,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePlatformOrganization {
    slug: String,
    name: String,
    ownership: PlatformOwnership,
}

async fn list_platform_organizations(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<PlatformOrganizationPage>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .list_platform_organizations(principal, page.into())
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn get_platform_organization(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<PlatformOrganization>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .get_platform_organization(principal, organization_id)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn create_platform_organization(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreatePlatformOrganization>,
) -> Result<Response, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let ownership = match input.ownership {
        PlatformOwnership::InvitedOwner { email, locale } => {
            Ownership::InvitedOwner { email, locale }
        }
        PlatformOwnership::SelfOwner => Ownership::SelfOwner,
    };
    let provisioned = state
        .service
        .create_platform_organization(
            principal,
            NewPlatformOrganization {
                slug: input.slug,
                name: input.name,
                ownership,
            },
            &request_id.0,
        )
        .await
        .map_err(failed(&request_id))?;
    Ok((StatusCode::CREATED, Json(provisioned)).into_response())
}

async fn delete_platform_organization(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .delete_platform_organization(principal, organization_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(StatusCode::NO_CONTENT)
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

async fn list_platform_projects(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<PlatformProjectPage>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .list_platform_projects(principal, organization_id, page.into())
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn create_platform_project(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreateNamedResource>,
) -> Result<(StatusCode, Json<PlatformProject>), AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let project = state
        .service
        .create_platform_project(principal, organization_id, input.into(), &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok((StatusCode::CREATED, Json(project)))
}

async fn list_platform_applications(
    State(state): State<AccessState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<PlatformApplicationPage>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .list_platform_applications(principal, project_id, page.into())
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn create_platform_application(
    State(state): State<AccessState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreateNamedResource>,
) -> Result<(StatusCode, Json<CreatedPlatformApplication>), AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let created = state
        .service
        .create_platform_application(principal, project_id, input.into(), &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UserStatus {
    Enabled,
    Disabled,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserStatusChange {
    status: UserStatus,
}

async fn set_user_status(
    State(state): State<AccessState>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<UserStatusChange>,
) -> Result<Json<UserSummary>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let disabled = matches!(input.status, UserStatus::Disabled);
    state
        .service
        .set_user_status(principal, user_id, disabled, &request_id.0)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn grant_super_admin(
    State(state): State<AccessState>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .grant_super_admin(principal, user_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_super_admin(
    State(state): State<AccessState>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .revoke_super_admin(principal, user_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_organization_members(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OrganizationMemberPage>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .list_organization_members(principal, organization_id, page.into())
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrganizationRoleChange {
    role: OrganizationRole,
}

async fn update_organization_member(
    State(state): State<AccessState>,
    Path((organization_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<OrganizationRoleChange>,
) -> Result<Json<OrganizationMember>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .update_organization_member(
            principal,
            organization_id,
            user_id,
            input.role,
            &request_id.0,
        )
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn remove_organization_member(
    State(state): State<AccessState>,
    Path((organization_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .remove_organization_member(principal, organization_id, user_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_project_members(
    State(state): State<AccessState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<ProjectMemberPage>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .list_project_members(principal, project_id, page.into())
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn list_eligible_project_members(
    State(state): State<AccessState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OrganizationMemberPage>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .list_eligible_project_members(principal, project_id, page.into())
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddProjectMember {
    user_id: Uuid,
    role: ProjectRole,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRoleChange {
    role: ProjectRole,
}

async fn add_project_member(
    State(state): State<AccessState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<AddProjectMember>,
) -> Result<(StatusCode, Json<ProjectMember>), AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let member = state
        .service
        .add_project_member(
            principal,
            project_id,
            input.user_id,
            input.role,
            &request_id.0,
        )
        .await
        .map_err(failed(&request_id))?;
    Ok((StatusCode::CREATED, Json(member)))
}

async fn update_project_member(
    State(state): State<AccessState>,
    Path((project_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<ProjectRoleChange>,
) -> Result<Json<ProjectMember>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .update_project_member(principal, project_id, user_id, input.role, &request_id.0)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn remove_project_member(
    State(state): State<AccessState>,
    Path((project_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .remove_project_member(principal, project_id, user_id, &request_id.0)
        .await
        .map_err(failed(&request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_audit(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<AuditPage>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .list_audit(principal, organization_id, page.into())
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn list_platform_audit(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<AuditPage>, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    state
        .service
        .list_platform_audit(principal, page.into())
        .await
        .map(Json)
        .map_err(failed(&request_id))
}
