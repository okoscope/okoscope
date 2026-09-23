use crate::error_code::ErrorCode;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch, post, put},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::repository::ApplicationRepository;
use crate::repository::MembershipRepository;
use crate::repository::ProjectRepository;
use crate::repository::SessionRepository;
use crate::repository::event_groups::aggregates;
use crate::repository::{OrganizationRepository, OrganizationStatus};
use crate::{
    access_audit::{AccessAuditActor, AccessAuditEvent, write_access_audit},
    access_control::{
        EffectiveAccessSource, ProjectRole, can_manage_organization_role, can_manage_project_role,
        resolve_project_access,
    },
    application_credentials::issue as issue_application_credential,
    auth::{IdentityPrincipal, OrganizationRole, UserSessionAuthenticator, session_token},
    invitation_api::{
        InvitationView, current_organization_owner_invitation, issue_organization_invitation,
    },
    transactional_mail::Locale,
    user_auth::{insert_session_with_context, session_cookie},
    web_api::{OrganizationMode, RequestId, WebApiConfig},
};

#[derive(Clone, Debug)]
struct AccessState {
    pool: PgPool,
    auth: UserSessionAuthenticator,
    secure_cookie: bool,
    session_lifetime: std::time::Duration,
    config: WebApiConfig,
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
            auth: UserSessionAuthenticator::new(pool.clone()),
            pool,
            secure_cookie: config.secure_session_cookie,
            session_lifetime: config.session_lifetime,
            config: config.clone(),
        })
}

#[derive(Debug, Serialize)]
struct AuthenticationPolicy {
    public_signup_enabled: bool,
    invitation_registration_enabled: bool,
    organization_mode: &'static str,
}

async fn authentication_policy(State(state): State<AccessState>) -> Json<AuthenticationPolicy> {
    let organization_mode = match state.config.organization_mode {
        OrganizationMode::Single => "single",
        OrganizationMode::Multiple => "multiple",
    };
    Json(AuthenticationPolicy {
        public_signup_enabled: state.config.public_signup_enabled,
        invitation_registration_enabled: true,
        organization_mode,
    })
}

#[derive(Debug)]
struct AccessError {
    status: StatusCode,
    code: ErrorCode,
    message: &'static str,
    request_id: RequestId,
}

impl AccessError {
    fn new(status: StatusCode, code: ErrorCode, message: &'static str, id: &RequestId) -> Self {
        Self {
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

    fn conflict(code: ErrorCode, request_id: &RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            code,
            "access mutation conflicts with current authority",
            request_id,
        )
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
        if matches!(self.status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND) {
            crate::metrics::record_access_denial();
            tracing::warn!(
                status = self.status.as_u16(),
                error = %self.code,
                "access denied"
            );
        }
        (
            self.status,
            Json(Body {
                error: self.code,
                message: self.message,
                request_id: self.request_id.0,
            }),
        )
            .into_response()
    }
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

async fn platform(
    state: &AccessState,
    headers: &HeaderMap,
    request_id: &RequestId,
    privileged: bool,
) -> Result<IdentityPrincipal, AccessError> {
    let principal = identity(state, headers, request_id).await?;
    if !principal.is_super_admin {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::FORBIDDEN,
            "super administrator role is required",
            request_id,
        ));
    }
    if privileged && !principal.has_recent_privilege() {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::PRIVILEGE_CONFIRMATION_REQUIRED,
            "recent password confirmation is required",
            request_id,
        ));
    }
    Ok(principal)
}

async fn organization_admin(
    state: &AccessState,
    headers: &HeaderMap,
    organization_id: Uuid,
    request_id: &RequestId,
) -> Result<IdentityPrincipal, AccessError> {
    let principal = identity(state, headers, request_id).await?;
    if principal.is_super_admin {
        return Ok(principal);
    }
    if principal.active_organization_id != Some(organization_id) {
        return Err(AccessError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::ORGANIZATION_NOT_FOUND,
            "resource not found",
            request_id,
        ));
    }
    if !principal
        .organization_role
        .is_some_and(OrganizationRole::inherits_project_access)
    {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::FORBIDDEN,
            "Organization administration is required",
            request_id,
        ));
    }
    Ok(principal)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrganizationSelection {
    organization_id: Uuid,
}

#[derive(Debug, Serialize)]
struct SessionSelection {
    active_organization_id: Uuid,
    role: OrganizationRole,
}

async fn select_organization(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<OrganizationSelection>,
) -> Result<Response, AccessError> {
    let principal = identity(&state, &headers, &request_id).await?;
    let role = MembershipRepository::organization_role_when_active(
        &state.pool,
        principal.user_id,
        input.organization_id,
    )
    .await
    .map_err(|error| AccessError::database(&error, &request_id))?;
    let role: OrganizationRole = role.and_then(|value| value.parse().ok()).ok_or_else(|| {
        AccessError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::ORGANIZATION_NOT_FOUND,
            "resource not found",
            &request_id,
        )
    })?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    SessionRepository::revoke(&mut *tx, principal.session_id)
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    let (_, token) = insert_session_with_context(
        &mut tx,
        principal.user_id,
        Some(input.organization_id),
        principal.privileged_until,
        state.session_lifetime,
    )
    .await
    .map_err(|error| AccessError::database(&error, &request_id))?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    let mut response = Json(SessionSelection {
        active_organization_id: input.organization_id,
        role,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(token.expose(), state.secure_cookie, state.session_lifetime),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegeConfirmation {
    current_password: String,
}

#[derive(Debug, Serialize)]
struct PrivilegeState {
    privileged_until: DateTime<Utc>,
}

async fn confirm_privilege(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<PrivilegeConfirmation>,
) -> Result<Response, AccessError> {
    let principal = platform(&state, &headers, &request_id, false).await?;
    let password_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1")
        .bind(principal.user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    if !crate::auth::verify_password(&input.current_password, &password_hash) {
        return Err(AccessError::new(
            StatusCode::BAD_REQUEST,
            ErrorCode::CURRENT_PASSWORD_INVALID,
            "current password is incorrect",
            &request_id,
        ));
    }
    let until = Utc::now() + Duration::minutes(15);
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    SessionRepository::revoke(&mut *tx, principal.session_id)
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    let (_, token) = insert_session_with_context(
        &mut tx,
        principal.user_id,
        principal.active_organization_id,
        Some(until),
        state.session_lifetime,
    )
    .await
    .map_err(|error| AccessError::database(&error, &request_id))?;
    audit(
        &mut tx,
        principal.user_id,
        "privilege.confirmed",
        None,
        None,
        Some(principal.user_id),
        None,
        None,
        None,
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    crate::metrics::record_privilege_confirmation();
    let mut response = Json(PrivilegeState {
        privileged_until: until,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(token.expose(), state.secure_cookie, state.session_lifetime),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

impl PageQuery {
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }
}

#[derive(Debug, Serialize, FromRow)]
struct UserSummary {
    id: Uuid,
    email: String,
    display_name: String,
    email_verified: bool,
    enabled: bool,
    is_super_admin: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct UserPage {
    items: Vec<UserSummary>,
    next_cursor: Option<Uuid>,
}

async fn list_platform_users(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<UserPage>, AccessError> {
    platform(&state, &headers, &request_id, false).await?;
    let limit = page.limit();
    let mut items: Vec<UserSummary> = sqlx::query_as("SELECT u.id,u.email,u.display_name,(u.email_verified_at IS NOT NULL) email_verified,(u.disabled_at IS NULL) enabled,EXISTS(SELECT 1 FROM platform_role_assignments p WHERE p.user_id=u.id AND p.revoked_at IS NULL) is_super_admin,u.created_at FROM users u WHERE ($1::uuid IS NULL OR u.id>$1) ORDER BY u.id LIMIT $2")
        .bind(page.cursor).bind(limit + 1).fetch_all(&state.pool).await.map_err(|error| AccessError::database(&error, &request_id))?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(100) {
        items.pop();
        items.last().map(|item| item.id)
    } else {
        None
    };
    Ok(Json(UserPage { items, next_cursor }))
}

#[derive(Debug, Serialize, FromRow)]
struct PlatformOrganization {
    id: Uuid,
    slug: String,
    name: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    #[sqlx(skip)]
    current_owner_invitation: Option<InvitationView>,
}

#[derive(Debug, Serialize)]
struct PlatformOrganizationPage {
    items: Vec<PlatformOrganization>,
    next_cursor: Option<Uuid>,
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

#[derive(Debug, Serialize)]
struct ProvisionedOrganization {
    organization: PlatformOrganization,
    invitation: Option<InvitationView>,
}

async fn list_platform_organizations(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<PlatformOrganizationPage>, AccessError> {
    platform(&state, &headers, &request_id, false).await?;
    let limit = page.limit();
    let mut items: Vec<PlatformOrganization> = sqlx::query_as("SELECT id,slug,name,status,created_at,updated_at FROM organizations WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT $2")
        .bind(page.cursor).bind(limit + 1).fetch_all(&state.pool).await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    let next_cursor = trim_page(&mut items, limit, |item| item.id);
    Ok(Json(PlatformOrganizationPage { items, next_cursor }))
}

async fn get_platform_organization(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<PlatformOrganization>, AccessError> {
    platform(&state, &headers, &request_id, false).await?;
    let mut organization =
        platform_organization_by_id(&state.pool, organization_id, &request_id).await?;
    organization.current_owner_invitation =
        current_organization_owner_invitation(&state.pool, organization_id)
            .await
            .map_err(|error| AccessError::database(&error, &request_id))?;
    Ok(Json(organization))
}

async fn platform_organization_by_id(
    pool: &PgPool,
    organization_id: Uuid,
    request_id: &RequestId,
) -> Result<PlatformOrganization, AccessError> {
    sqlx::query_as(
        "SELECT id,slug,name,status,created_at,updated_at FROM organizations WHERE id=$1",
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| AccessError::database(&error, request_id))?
    .ok_or_else(|| {
        AccessError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::ORGANIZATION_NOT_FOUND,
            "resource not found",
            request_id,
        )
    })
}

async fn create_platform_organization(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreatePlatformOrganization>,
) -> Result<Response, Response> {
    let actor = platform(&state, &headers, &request_id, true)
        .await
        .map_err(IntoResponse::into_response)?;
    validate_platform_organization(&input, &request_id).map_err(IntoResponse::into_response)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id).into_response())?;
    ensure_organization_capacity(&mut tx, state.config.organization_mode, &request_id)
        .await
        .map_err(IntoResponse::into_response)?;
    let organization_id = Uuid::new_v4();
    let status = if matches!(input.ownership, PlatformOwnership::SelfOwner) {
        OrganizationStatus::Active
    } else {
        OrganizationStatus::PendingOwner
    };
    let stored =
        OrganizationRepository::insert(&mut *tx, organization_id, &input.slug, &input.name, status)
            .await
            .map_err(|error| AccessError::database(&error, &request_id).into_response())?;
    let organization = PlatformOrganization {
        id: stored.id,
        slug: stored.slug,
        name: stored.name,
        status: stored.status,
        created_at: stored.created_at,
        updated_at: stored.updated_at,
        current_owner_invitation: None,
    };
    let invitation = match input.ownership {
        PlatformOwnership::SelfOwner => {
            MembershipRepository::insert_organization_role(
                &mut *tx,
                organization_id,
                actor.user_id,
                "owner",
            )
            .await
            .map_err(|error| AccessError::database(&error, &request_id).into_response())?;
            None
        }
        PlatformOwnership::InvitedOwner { email, locale } => Some(
            issue_organization_invitation(
                &mut tx,
                &state.config,
                actor.user_id,
                organization_id,
                &email,
                OrganizationRole::Owner,
                locale,
                &request_id,
            )
            .await
            .map_err(IntoResponse::into_response)?,
        ),
    };
    audit(
        &mut tx,
        actor.user_id,
        "organization.created",
        Some(organization_id),
        None,
        None,
        None,
        None,
        None,
        &request_id,
    )
    .await
    .map_err(IntoResponse::into_response)?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id).into_response())?;
    Ok((
        StatusCode::CREATED,
        Json(ProvisionedOrganization {
            organization,
            invitation,
        }),
    )
        .into_response())
}

fn validate_platform_organization(
    input: &CreatePlatformOrganization,
    request_id: &RequestId,
) -> Result<(), AccessError> {
    if !crate::user_auth::valid_slug(&input.slug) || !crate::user_auth::valid_name(&input.name) {
        return Err(AccessError::new(
            StatusCode::BAD_REQUEST,
            ErrorCode::VALIDATION_FAILED,
            "organization is invalid",
            request_id,
        ));
    }
    Ok(())
}

/// Refuses to create a second organization in single-organization mode.
///
/// Must run inside the transaction that creates the organization. The check
/// used to run on the pool before that transaction began, so two concurrent
/// requests could both find no organization and both insert one; nothing in
/// the schema limits the table to a single row. Holding the authority lock
/// across the check and the insert means a second request waits for the first
/// to commit and then sees its organization.
async fn ensure_organization_capacity(
    tx: &mut Transaction<'_, Postgres>,
    mode: OrganizationMode,
    request_id: &RequestId,
) -> Result<(), AccessError> {
    if mode != OrganizationMode::Single {
        return Ok(());
    }
    lock_authority(tx, request_id).await?;
    let exists = OrganizationRepository::any_exists(&mut **tx)
        .await
        .map_err(|error| AccessError::database(&error, request_id))?;
    if exists {
        return Err(AccessError::conflict(
            ErrorCode::ORGANIZATION_LIMIT_REACHED,
            request_id,
        ));
    }
    Ok(())
}

async fn delete_platform_organization(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, AccessError> {
    let actor = platform(&state, &headers, &request_id, true).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    let deleted = OrganizationRepository::discard_unclaimed(&mut *tx, organization_id)
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    if !deleted {
        return Err(AccessError::conflict(
            ErrorCode::ORGANIZATION_NOT_DELETABLE,
            &request_id,
        ));
    }
    audit(
        &mut tx,
        actor.user_id,
        "organization.deleted",
        None,
        None,
        None,
        None,
        None,
        None,
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

fn platform_capabilities() -> serde_json::Value {
    serde_json::json!({
        "manage_platform": true,
        "manage_organization": true,
        "create_project": true,
        "manage_project_members": true,
        "create_application": true,
        "manage_credentials": true,
        "organization_roles_grantable": ["owner", "admin", "member"],
        "project_roles_grantable": ["admin", "member"],
    })
}

#[derive(Debug, Serialize, FromRow)]
struct PlatformProject {
    id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
    archived_at: Option<DateTime<Utc>>,
    application_count: i64,
    runtime_group_count: i64,
    #[sqlx(skip)]
    effective_project_role: Option<ProjectRole>,
    #[sqlx(skip)]
    effective_access_source: Option<EffectiveAccessSource>,
    #[sqlx(skip)]
    capabilities: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct PlatformProjectPage {
    items: Vec<PlatformProject>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateNamedResource {
    slug: String,
    name: String,
}

async fn list_platform_projects(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<PlatformProjectPage>, AccessError> {
    platform(&state, &headers, &request_id, false).await?;
    let limit = page.limit();
    let mut items: Vec<PlatformProject> = sqlx::query_as(&format!("SELECT p.id,p.slug,p.name,p.created_at,p.archived_at,{} application_count,{} runtime_group_count FROM projects p WHERE p.organization_id=$1 AND ($2::uuid IS NULL OR p.id>$2) ORDER BY p.id LIMIT $3", crate::repository::applications::aggregates::COUNT_FOR_PROJECT, aggregates::COUNT_ALL_FOR_PROJECT))
        .bind(organization_id).bind(page.cursor).bind(limit + 1).fetch_all(&state.pool).await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    for item in &mut items {
        item.effective_project_role = Some(ProjectRole::Admin);
        item.effective_access_source = Some(EffectiveAccessSource::Platform);
        item.capabilities = platform_capabilities();
    }
    let next_cursor = trim_page(&mut items, limit, |item| item.id);
    Ok(Json(PlatformProjectPage { items, next_cursor }))
}

async fn create_platform_project(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreateNamedResource>,
) -> Result<(StatusCode, Json<PlatformProject>), AccessError> {
    let actor = platform(&state, &headers, &request_id, false).await?;
    validate_named_resource(&input, &request_id)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    let stored = ProjectRepository::insert(
        &mut *tx,
        Uuid::new_v4(),
        organization_id,
        &input.slug,
        &input.name,
    )
    .await
    .map_err(|error| AccessError::database(&error, &request_id))?
    .ok_or_else(|| {
        AccessError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::ORGANIZATION_NOT_FOUND,
            "resource not found",
            &request_id,
        )
    })?;
    // A project that was just created has no applications and no runtime
    // groups yet, so the counts are known without a query.
    let mut project = PlatformProject {
        id: stored.id,
        slug: stored.slug,
        name: stored.name,
        created_at: stored.created_at,
        archived_at: stored.archived_at,
        application_count: 0,
        runtime_group_count: 0,
        effective_project_role: None,
        effective_access_source: None,
        capabilities: platform_capabilities(),
    };
    project.effective_project_role = Some(ProjectRole::Admin);
    project.effective_access_source = Some(EffectiveAccessSource::Platform);
    project.capabilities = platform_capabilities();
    audit(
        &mut tx,
        actor.user_id,
        "project.created",
        Some(organization_id),
        Some(project.id),
        None,
        None,
        None,
        None,
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    Ok((StatusCode::CREATED, Json(project)))
}

#[derive(Debug, Serialize, FromRow)]
struct PlatformApplication {
    id: Uuid,
    project_id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
    release_count: i64,
    runtime_group_count: i64,
    latest_observed_at: Option<DateTime<Utc>>,
    #[sqlx(skip)]
    effective_project_role: Option<ProjectRole>,
    #[sqlx(skip)]
    effective_access_source: Option<EffectiveAccessSource>,
    #[sqlx(skip)]
    capabilities: serde_json::Value,
}

#[derive(Debug, Serialize, FromRow)]
struct ProvisionedApplication {
    id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct PlatformApplicationPage {
    items: Vec<PlatformApplication>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct IssuedCredential {
    id: Uuid,
    name: String,
    token: String,
    token_hint: String,
    created_at: DateTime<Utc>,
    shown_once: bool,
}

#[derive(Debug, Serialize)]
struct CreatedPlatformApplication {
    application: ProvisionedApplication,
    credential: IssuedCredential,
}

async fn list_platform_applications(
    State(state): State<AccessState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<PlatformApplicationPage>, AccessError> {
    platform(&state, &headers, &request_id, false).await?;
    let limit = page.limit();
    let mut items: Vec<PlatformApplication> = sqlx::query_as(&format!("SELECT a.id,a.project_id,a.slug,a.name,a.created_at,{} release_count,{} runtime_group_count,{} latest_observed_at FROM applications a WHERE a.project_id=$1 AND ($2::uuid IS NULL OR a.id>$2) ORDER BY a.id LIMIT $3", crate::repository::releases::aggregates::COUNT_FOR_APPLICATION, aggregates::COUNT_ALL_FOR_APPLICATION,aggregates::LATEST_SEEN_ALL_FOR_APPLICATION))
        .bind(project_id).bind(page.cursor).bind(limit + 1).fetch_all(&state.pool).await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    for item in &mut items {
        item.effective_project_role = Some(ProjectRole::Admin);
        item.effective_access_source = Some(EffectiveAccessSource::Platform);
        item.capabilities = platform_capabilities();
    }
    let next_cursor = trim_page(&mut items, limit, |item| item.id);
    Ok(Json(PlatformApplicationPage { items, next_cursor }))
}

async fn create_platform_application(
    State(state): State<AccessState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreateNamedResource>,
) -> Result<(StatusCode, Json<CreatedPlatformApplication>), AccessError> {
    let actor = platform(&state, &headers, &request_id, false).await?;
    validate_named_resource(&input, &request_id)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    let stored = ApplicationRepository::insert(
        &mut *tx,
        Uuid::new_v4(),
        project_id,
        &input.slug,
        &input.name,
    )
    .await
    .map_err(|error| AccessError::database(&error, &request_id))?
    .ok_or_else(|| {
        AccessError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::PROJECT_NOT_FOUND,
            "resource not found",
            &request_id,
        )
    })?;
    let application = ProvisionedApplication {
        id: stored.id,
        organization_id: stored.organization_id,
        project_id: stored.project_id,
        slug: stored.slug,
        name: stored.name,
        created_at: stored.created_at,
    };
    let issued = issue_application_credential(
        &mut tx,
        application.organization_id,
        project_id,
        application.id,
        "default",
    )
    .await
    .map_err(|error| AccessError::database(&error, &request_id))?;
    let token = issued.token().to_owned();
    let credential = IssuedCredential {
        id: issued.summary.id,
        name: issued.summary.name,
        token,
        token_hint: issued.summary.token_hint,
        created_at: issued.summary.created_at,
        shown_once: true,
    };
    audit(
        &mut tx,
        actor.user_id,
        "credential.issued",
        Some(application.organization_id),
        Some(project_id),
        None,
        None,
        None,
        None,
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedPlatformApplication {
            application,
            credential,
        }),
    ))
}

fn validate_named_resource(
    input: &CreateNamedResource,
    request_id: &RequestId,
) -> Result<(), AccessError> {
    if crate::user_auth::valid_slug(&input.slug) && crate::user_auth::valid_name(&input.name) {
        Ok(())
    } else {
        Err(AccessError::new(
            StatusCode::BAD_REQUEST,
            ErrorCode::VALIDATION_FAILED,
            "resource is invalid",
            request_id,
        ))
    }
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
    let actor = platform(&state, &headers, &request_id, true).await?;
    let disabled = matches!(input.status, UserStatus::Disabled);
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    lock_authority(&mut tx, &request_id).await?;
    let item: UserSummary = sqlx::query_as("UPDATE users SET disabled_at=CASE WHEN $2 THEN coalesce(disabled_at,now()) ELSE NULL END,updated_at=now() WHERE id=$1 RETURNING id,email,display_name,(email_verified_at IS NOT NULL) email_verified,(disabled_at IS NULL) enabled,EXISTS(SELECT 1 FROM platform_role_assignments p WHERE p.user_id=users.id AND p.revoked_at IS NULL) is_super_admin,created_at")
        .bind(user_id).bind(disabled).fetch_optional(&mut *tx).await.map_err(|error| AccessError::database(&error, &request_id))?
        .ok_or_else(|| AccessError::new(StatusCode::NOT_FOUND, ErrorCode::USER_NOT_FOUND, "resource not found", &request_id))?;
    SessionRepository::revoke_all_for_user(&mut *tx, user_id, None)
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    audit(
        &mut tx,
        actor.user_id,
        if disabled {
            "user.disabled"
        } else {
            "user.enabled"
        },
        None,
        None,
        Some(user_id),
        None,
        None,
        None,
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    Ok(Json(item))
}

async fn grant_super_admin(
    State(state): State<AccessState>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, AccessError> {
    let actor = platform(&state, &headers, &request_id, true).await?;
    if actor.user_id == user_id {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::SELF_PROMOTION_FORBIDDEN,
            "self promotion is forbidden",
            &request_id,
        ));
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    lock_authority(&mut tx, &request_id).await?;
    let eligible: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND disabled_at IS NULL AND email_verified_at IS NOT NULL)")
        .bind(user_id).fetch_one(&mut *tx).await.map_err(|error| AccessError::database(&error, &request_id))?;
    if !eligible {
        return Err(AccessError::new(
            StatusCode::CONFLICT,
            ErrorCode::USER_NOT_ELIGIBLE,
            "user is not eligible",
            &request_id,
        ));
    }
    sqlx::query("INSERT INTO platform_role_assignments(user_id,role,granted_by_user_id) VALUES($1,'super_admin',$2) ON CONFLICT(user_id) DO UPDATE SET revoked_at=NULL,granted_at=now(),granted_by_user_id=$2")
        .bind(user_id).bind(actor.user_id).execute(&mut *tx).await.map_err(|error| AccessError::database(&error, &request_id))?;
    audit(
        &mut tx,
        actor.user_id,
        "platform_role.granted",
        None,
        None,
        Some(user_id),
        None,
        None,
        Some("super_admin"),
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_super_admin(
    State(state): State<AccessState>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, AccessError> {
    let actor = platform(&state, &headers, &request_id, true).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    lock_authority(&mut tx, &request_id).await?;
    let result = sqlx::query("UPDATE platform_role_assignments SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL")
        .bind(user_id).execute(&mut *tx).await;
    if let Err(error) = result {
        return if error
            .as_database_error()
            .is_some_and(|item| item.code().as_deref() == Some("23514"))
        {
            Err(AccessError::conflict(
                ErrorCode::LAST_SUPER_ADMIN_REQUIRED,
                &request_id,
            ))
        } else {
            Err(AccessError::database(&error, &request_id))
        };
    }
    SessionRepository::revoke_all_for_user(&mut *tx, user_id, None)
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    audit(
        &mut tx,
        actor.user_id,
        "platform_role.revoked",
        None,
        None,
        Some(user_id),
        None,
        Some("super_admin"),
        None,
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
struct OrganizationMember {
    user_id: Uuid,
    email: String,
    display_name: String,
    role: OrganizationRole,
    enabled: bool,
    email_verified: bool,
    created_at: DateTime<Utc>,
    can_change_role: serde_json::Value,
    can_remove: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct OrganizationMemberPage {
    items: Vec<OrganizationMember>,
    next_cursor: Option<Uuid>,
}

type OrganizationMemberRow = (Uuid, String, String, String, bool, bool, DateTime<Utc>);

async fn list_organization_members(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OrganizationMemberPage>, AccessError> {
    let actor = organization_admin(&state, &headers, organization_id, &request_id).await?;
    let limit = page.limit();
    let rows: Vec<OrganizationMemberRow> = sqlx::query_as(
        "SELECT u.id,u.email,u.display_name,m.role,(u.disabled_at IS NULL),(u.email_verified_at IS NOT NULL),m.created_at FROM organization_memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND ($2::uuid IS NULL OR u.id>$2) ORDER BY u.id LIMIT $3",
    )
    .bind(organization_id).bind(page.cursor).bind(limit + 1).fetch_all(&state.pool).await
    .map_err(|error| AccessError::database(&error, &request_id))?;
    let mut items = rows
        .into_iter()
        .filter_map(organization_member)
        .collect::<Vec<_>>();
    let owner_count = MembershipRepository::organization_owner_count(&state.pool, organization_id)
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    for item in &mut items {
        let allowed = actor.is_super_admin
            || can_manage_organization_role(
                actor.organization_role.unwrap_or(OrganizationRole::Member),
                item.role,
                None,
            );
        item.can_change_role = serde_json::json!(allowed);
        item.can_remove = serde_json::json!(
            allowed && !(item.role == OrganizationRole::Owner && owner_count == 1)
        );
    }
    let next_cursor = trim_page(&mut items, limit, |item| item.user_id);
    Ok(Json(OrganizationMemberPage { items, next_cursor }))
}

fn organization_member(row: OrganizationMemberRow) -> Option<OrganizationMember> {
    Some(OrganizationMember {
        user_id: row.0,
        email: row.1,
        display_name: row.2,
        role: row.3.parse().ok()?,
        enabled: row.4,
        email_verified: row.5,
        created_at: row.6,
        can_change_role: serde_json::json!(false),
        can_remove: serde_json::json!(false),
    })
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
    let actor = organization_admin(&state, &headers, organization_id, &request_id).await?;
    let current =
        organization_member_by_id(&state.pool, organization_id, user_id, &request_id).await?;
    if !actor.is_super_admin
        && !can_manage_organization_role(
            actor.organization_role.unwrap_or(OrganizationRole::Member),
            current.role,
            Some(input.role),
        )
    {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::FORBIDDEN,
            "role transition is forbidden",
            &request_id,
        ));
    }
    if actor.user_id == user_id && role_promotes(current.role, input.role) {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::SELF_PROMOTION_FORBIDDEN,
            "self promotion is forbidden",
            &request_id,
        ));
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    lock_authority(&mut tx, &request_id).await?;
    let result = sqlx::query(
        "UPDATE organization_memberships SET role=$3 WHERE organization_id=$1 AND user_id=$2",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(role_name(input.role))
    .execute(&mut *tx)
    .await;
    map_authority_result(
        result,
        ErrorCode::LAST_ORGANIZATION_OWNER_REQUIRED,
        &request_id,
    )?;
    audit(
        &mut tx,
        actor.user_id,
        "organization_member.role_changed",
        Some(organization_id),
        None,
        Some(user_id),
        None,
        Some(role_name(current.role)),
        Some(role_name(input.role)),
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    organization_member_by_id(&state.pool, organization_id, user_id, &request_id)
        .await
        .map(Json)
}

async fn remove_organization_member(
    State(state): State<AccessState>,
    Path((organization_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, AccessError> {
    let actor = organization_admin(&state, &headers, organization_id, &request_id).await?;
    let current =
        organization_member_by_id(&state.pool, organization_id, user_id, &request_id).await?;
    if !actor.is_super_admin
        && !can_manage_organization_role(
            actor.organization_role.unwrap_or(OrganizationRole::Member),
            current.role,
            None,
        )
    {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::FORBIDDEN,
            "membership removal is forbidden",
            &request_id,
        ));
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    lock_authority(&mut tx, &request_id).await?;
    let result =
        MembershipRepository::remove_organization_role(&mut *tx, organization_id, user_id).await;
    map_authority_result(
        result,
        ErrorCode::LAST_ORGANIZATION_OWNER_REQUIRED,
        &request_id,
    )?;
    SessionRepository::revoke_for_user_in_organization(&mut *tx, user_id, organization_id)
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    audit(
        &mut tx,
        actor.user_id,
        "organization_member.removed",
        Some(organization_id),
        None,
        Some(user_id),
        None,
        Some(role_name(current.role)),
        None,
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn organization_member_by_id(
    pool: &PgPool,
    organization_id: Uuid,
    user_id: Uuid,
    request_id: &RequestId,
) -> Result<OrganizationMember, AccessError> {
    let row = sqlx::query_as("SELECT u.id,u.email,u.display_name,m.role,(u.disabled_at IS NULL),(u.email_verified_at IS NOT NULL),m.created_at FROM organization_memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.user_id=$2")
        .bind(organization_id).bind(user_id).fetch_optional(pool).await
        .map_err(|error| AccessError::database(&error, request_id))?
        .ok_or_else(|| AccessError::new(StatusCode::NOT_FOUND, ErrorCode::USER_NOT_FOUND, "resource not found", request_id))?;
    organization_member(row).ok_or_else(|| {
        AccessError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::INTERNAL_ERROR,
            "internal server error",
            request_id,
        )
    })
}

#[derive(Debug, Serialize)]
struct ProjectMember {
    user_id: Uuid,
    email: String,
    display_name: String,
    role: ProjectRole,
    access_source: EffectiveAccessSource,
    created_at: DateTime<Utc>,
    can_change_role: serde_json::Value,
    can_remove: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ProjectMemberPage {
    items: Vec<ProjectMember>,
    next_cursor: Option<Uuid>,
}

async fn project_actor(
    state: &AccessState,
    headers: &HeaderMap,
    project_id: Uuid,
    request_id: &RequestId,
) -> Result<(IdentityPrincipal, Uuid, ProjectRole), AccessError> {
    let principal = identity(state, headers, request_id).await?;
    let organization_id: Uuid = ProjectRepository::organization_of(&state.pool, project_id)
        .await
        .map_err(|error| AccessError::database(&error, request_id))?
        .ok_or_else(|| {
            AccessError::new(
                StatusCode::NOT_FOUND,
                ErrorCode::PROJECT_NOT_FOUND,
                "resource not found",
                request_id,
            )
        })?;
    let access = resolve_project_access(&state.pool, principal, organization_id, project_id)
        .await
        .map_err(|error| AccessError::database(&error, request_id))?
        .ok_or_else(|| {
            AccessError::new(
                StatusCode::NOT_FOUND,
                ErrorCode::PROJECT_NOT_FOUND,
                "resource not found",
                request_id,
            )
        })?;
    if !access.can_manage_members() {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::FORBIDDEN,
            "Project administration is required",
            request_id,
        ));
    }
    Ok((principal, organization_id, access.role))
}

async fn list_project_members(
    State(state): State<AccessState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<ProjectMemberPage>, AccessError> {
    let (actor, _, actor_role) = project_actor(&state, &headers, project_id, &request_id).await?;
    let limit = page.limit();
    let rows: Vec<(Uuid, String, String, String, DateTime<Utc>)> = sqlx::query_as("SELECT u.id,u.email,u.display_name,m.role,m.created_at FROM project_memberships m JOIN users u ON u.id=m.user_id WHERE m.project_id=$1 AND ($2::uuid IS NULL OR u.id>$2) ORDER BY u.id LIMIT $3")
        .bind(project_id).bind(page.cursor).bind(limit + 1).fetch_all(&state.pool).await.map_err(|error| AccessError::database(&error, &request_id))?;
    let mut items = rows
        .into_iter()
        .filter_map(project_member)
        .collect::<Vec<_>>();
    for item in &mut items {
        let allowed = can_manage_project_role(
            actor.is_super_admin,
            actor.organization_role,
            Some(actor_role),
            Some(item.role),
        );
        item.can_change_role = serde_json::json!(allowed);
        item.can_remove = serde_json::json!(allowed);
    }
    let next_cursor = trim_page(&mut items, limit, |item| item.user_id);
    Ok(Json(ProjectMemberPage { items, next_cursor }))
}

async fn list_eligible_project_members(
    State(state): State<AccessState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OrganizationMemberPage>, AccessError> {
    let (_, organization_id, _) = project_actor(&state, &headers, project_id, &request_id).await?;
    let limit = page.limit();
    let rows: Vec<OrganizationMemberRow> = sqlx::query_as("SELECT u.id,u.email,u.display_name,m.role,(u.disabled_at IS NULL),(u.email_verified_at IS NOT NULL),m.created_at FROM organization_memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND u.disabled_at IS NULL AND NOT EXISTS(SELECT 1 FROM project_memberships pm WHERE pm.project_id=$2 AND pm.user_id=u.id) AND ($3::uuid IS NULL OR u.id>$3) ORDER BY u.id LIMIT $4")
        .bind(organization_id).bind(project_id).bind(page.cursor).bind(limit + 1)
        .fetch_all(&state.pool).await.map_err(|error| AccessError::database(&error, &request_id))?;
    let mut items = rows.into_iter().filter_map(organization_member).collect();
    let next_cursor = trim_page(&mut items, limit, |item| item.user_id);
    Ok(Json(OrganizationMemberPage { items, next_cursor }))
}

fn project_member(row: (Uuid, String, String, String, DateTime<Utc>)) -> Option<ProjectMember> {
    Some(ProjectMember {
        user_id: row.0,
        email: row.1,
        display_name: row.2,
        role: row.3.parse().ok()?,
        access_source: EffectiveAccessSource::Project,
        created_at: row.4,
        can_change_role: serde_json::json!(false),
        can_remove: serde_json::json!(false),
    })
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
    let (actor, organization_id, actor_role) =
        project_actor(&state, &headers, project_id, &request_id).await?;
    if !can_manage_project_role(
        actor.is_super_admin,
        actor.organization_role,
        Some(actor_role),
        Some(input.role),
    ) {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::FORBIDDEN,
            "Project role grant is forbidden",
            &request_id,
        ));
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    let created = MembershipRepository::insert_project_role(
        &mut *tx,
        organization_id,
        project_id,
        input.user_id,
        project_role_name(input.role),
    )
    .await;
    created.map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
        {
            AccessError::conflict(ErrorCode::MEMBERSHIP_EXISTS, &request_id)
        } else {
            AccessError::database(&error, &request_id)
        }
    })?;
    audit(
        &mut tx,
        actor.user_id,
        "project_member.added",
        Some(organization_id),
        Some(project_id),
        Some(input.user_id),
        None,
        None,
        Some(project_role_name(input.role)),
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    project_member_by_id(&state.pool, project_id, input.user_id, &request_id)
        .await
        .map(|item| (StatusCode::CREATED, Json(item)))
}

async fn update_project_member(
    State(state): State<AccessState>,
    Path((project_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<ProjectRoleChange>,
) -> Result<Json<ProjectMember>, AccessError> {
    let (actor, organization_id, actor_role) =
        project_actor(&state, &headers, project_id, &request_id).await?;
    if !can_manage_project_role(
        actor.is_super_admin,
        actor.organization_role,
        Some(actor_role),
        Some(input.role),
    ) {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::FORBIDDEN,
            "Project role transition is forbidden",
            &request_id,
        ));
    }
    let current = project_member_by_id(&state.pool, project_id, user_id, &request_id).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    sqlx::query("UPDATE project_memberships SET role=$3,updated_at=now() WHERE project_id=$1 AND user_id=$2")
        .bind(project_id).bind(user_id).bind(project_role_name(input.role)).execute(&mut *tx).await.map_err(|error| AccessError::database(&error, &request_id))?;
    audit(
        &mut tx,
        actor.user_id,
        "project_member.role_changed",
        Some(organization_id),
        Some(project_id),
        Some(user_id),
        None,
        Some(project_role_name(current.role)),
        Some(project_role_name(input.role)),
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    project_member_by_id(&state.pool, project_id, user_id, &request_id)
        .await
        .map(Json)
}

async fn remove_project_member(
    State(state): State<AccessState>,
    Path((project_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, AccessError> {
    let (actor, organization_id, actor_role) =
        project_actor(&state, &headers, project_id, &request_id).await?;
    let current = project_member_by_id(&state.pool, project_id, user_id, &request_id).await?;
    if !can_manage_project_role(
        actor.is_super_admin,
        actor.organization_role,
        Some(actor_role),
        None,
    ) {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::FORBIDDEN,
            "Project membership removal is forbidden",
            &request_id,
        ));
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    MembershipRepository::remove_project_role(&mut *tx, project_id, user_id)
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    audit(
        &mut tx,
        actor.user_id,
        "project_member.removed",
        Some(organization_id),
        Some(project_id),
        Some(user_id),
        None,
        Some(project_role_name(current.role)),
        None,
        &request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| AccessError::database(&error, &request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn project_member_by_id(
    pool: &PgPool,
    project_id: Uuid,
    user_id: Uuid,
    request_id: &RequestId,
) -> Result<ProjectMember, AccessError> {
    let row = sqlx::query_as("SELECT u.id,u.email,u.display_name,m.role,m.created_at FROM project_memberships m JOIN users u ON u.id=m.user_id WHERE m.project_id=$1 AND m.user_id=$2")
        .bind(project_id).bind(user_id).fetch_optional(pool).await.map_err(|error| AccessError::database(&error, request_id))?
        .ok_or_else(|| AccessError::new(StatusCode::NOT_FOUND, ErrorCode::USER_NOT_FOUND, "resource not found", request_id))?;
    project_member(row).ok_or_else(|| {
        AccessError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::INTERNAL_ERROR,
            "internal server error",
            request_id,
        )
    })
}

fn trim_page<T>(
    items: &mut Vec<T>,
    limit: i64,
    id: impl FnOnce(&T) -> Uuid + Copy,
) -> Option<Uuid> {
    if items.len() > usize::try_from(limit).unwrap_or(100) {
        items.pop();
        items.last().map(id)
    } else {
        None
    }
}

fn role_name(role: OrganizationRole) -> &'static str {
    match role {
        OrganizationRole::Owner => "owner",
        OrganizationRole::Admin => "admin",
        OrganizationRole::Member => "member",
    }
}
fn project_role_name(role: ProjectRole) -> &'static str {
    match role {
        ProjectRole::Admin => "admin",
        ProjectRole::Member => "member",
    }
}
fn role_promotes(current: OrganizationRole, next: OrganizationRole) -> bool {
    matches!(
        (current, next),
        (
            OrganizationRole::Member,
            OrganizationRole::Admin | OrganizationRole::Owner
        ) | (OrganizationRole::Admin, OrganizationRole::Owner)
    )
}

fn map_authority_result<T>(
    result: Result<T, sqlx::Error>,
    code: ErrorCode,
    request_id: &RequestId,
) -> Result<(), AccessError> {
    result.map(|_| ()).map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|item| item.code().as_deref() == Some("23514"))
        {
            AccessError::conflict(code, request_id)
        } else {
            AccessError::database(&error, request_id)
        }
    })
}

async fn lock_authority(
    tx: &mut Transaction<'_, Postgres>,
    request_id: &RequestId,
) -> Result<(), AccessError> {
    sqlx::query("SELECT pg_advisory_xact_lock(1869373292)")
        .execute(&mut **tx)
        .await
        .map(|_| ())
        .map_err(|error| AccessError::database(&error, request_id))
}

#[derive(Debug, Serialize, FromRow)]
struct AuditRecord {
    id: Uuid,
    actor_kind: String,
    actor_user_id: Option<Uuid>,
    action: String,
    organization_id: Option<Uuid>,
    project_id: Option<Uuid>,
    target_user_id: Option<Uuid>,
    invitation_id: Option<Uuid>,
    previous_role: Option<String>,
    new_role: Option<String>,
    outcome: String,
    request_id: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct AuditPage {
    items: Vec<AuditRecord>,
    next_cursor: Option<Uuid>,
}

async fn list_audit(
    State(state): State<AccessState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<AuditPage>, AccessError> {
    let actor = organization_admin(&state, &headers, organization_id, &request_id).await?;
    if !actor.is_super_admin && actor.organization_role != Some(OrganizationRole::Owner) {
        return Err(AccessError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::FORBIDDEN,
            "owner role is required",
            &request_id,
        ));
    }
    query_audit(&state.pool, Some(organization_id), page, &request_id)
        .await
        .map(Json)
}

async fn list_platform_audit(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(page): Query<PageQuery>,
) -> Result<Json<AuditPage>, AccessError> {
    platform(&state, &headers, &request_id, false).await?;
    query_audit(&state.pool, None, page, &request_id)
        .await
        .map(Json)
}

async fn query_audit(
    pool: &PgPool,
    organization_id: Option<Uuid>,
    page: PageQuery,
    request_id: &RequestId,
) -> Result<AuditPage, AccessError> {
    let limit = page.limit();
    let mut items: Vec<AuditRecord> = sqlx::query_as("SELECT id,actor_kind,actor_user_id,action,organization_id,project_id,target_user_id,invitation_id,previous_role,new_role,outcome,request_id,created_at FROM access_audit_records WHERE ($1::uuid IS NULL OR organization_id=$1) AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT $3")
        .bind(organization_id).bind(page.cursor).bind(limit + 1).fetch_all(pool).await.map_err(|error| AccessError::database(&error, request_id))?;
    let next_cursor = trim_page(&mut items, limit, |item| item.id);
    Ok(AuditPage { items, next_cursor })
}

#[allow(clippy::too_many_arguments)]
async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    actor_user_id: Uuid,
    action: &str,
    organization_id: Option<Uuid>,
    project_id: Option<Uuid>,
    target_user_id: Option<Uuid>,
    invitation_id: Option<Uuid>,
    previous_role: Option<&str>,
    new_role: Option<&str>,
    request_id: &RequestId,
) -> Result<(), AccessError> {
    write_access_audit(
        tx,
        AccessAuditEvent {
            actor: AccessAuditActor::User(actor_user_id),
            action,
            organization_id,
            project_id,
            target_user_id,
            invitation_id,
            previous_role,
            new_role,
            request_id: Some(&request_id.0),
        },
    )
    .await
    .map_err(|error| AccessError::database(&error, request_id))?;
    if matches!(
        action,
        "platform_role.granted"
            | "platform_role.revoked"
            | "user.disabled"
            | "user.enabled"
            | "organization.created"
            | "organization.deleted"
            | "project.created"
            | "credential.issued"
            | "credential.revoked"
    ) {
        crate::metrics::record_platform_mutation();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two creations racing in single-organization mode must leave exactly one
    /// organization. The first has passed the capacity check and inserted but
    /// not committed when the second arrives, which is the window the check
    /// used to leave open: under read committed the second could not see the
    /// first's row, found the table empty, and inserted its own.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn single_mode_admits_one_organization_under_concurrency(pool: PgPool) {
        let request_id = RequestId("first".into());
        let mut first = pool.begin().await.unwrap();
        ensure_organization_capacity(&mut first, OrganizationMode::Single, &request_id)
            .await
            .unwrap();
        OrganizationRepository::insert(
            &mut *first,
            Uuid::new_v4(),
            "first",
            "First",
            OrganizationStatus::Active,
        )
        .await
        .unwrap();

        let second_pool = pool.clone();
        let second = tokio::spawn(async move {
            let request_id = RequestId("second".into());
            let mut tx = second_pool.begin().await.unwrap();
            let admitted =
                ensure_organization_capacity(&mut tx, OrganizationMode::Single, &request_id)
                    .await
                    .is_ok();
            if admitted {
                OrganizationRepository::insert(
                    &mut *tx,
                    Uuid::new_v4(),
                    "second",
                    "Second",
                    OrganizationStatus::Active,
                )
                .await
                .unwrap();
                tx.commit().await.unwrap();
            }
            admitted
        });
        // Let the second request reach its check while the first is open.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        first.commit().await.unwrap();

        assert!(
            !second.await.unwrap(),
            "the second creation must be refused once the first commits"
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "single mode must never hold two organizations");
    }

    /// Multiple-organization mode has no limit and takes no lock.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn multiple_mode_is_not_limited(pool: PgPool) {
        let request_id = RequestId("multiple".into());
        for slug in ["one", "two"] {
            let mut tx = pool.begin().await.unwrap();
            ensure_organization_capacity(&mut tx, OrganizationMode::Multiple, &request_id)
                .await
                .unwrap();
            OrganizationRepository::insert(
                &mut *tx,
                Uuid::new_v4(),
                slug,
                slug,
                OrganizationStatus::Active,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
    }
}
