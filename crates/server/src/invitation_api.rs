use crate::error_code::ErrorCode;
use crate::repository::MembershipRepository;
use crate::repository::UserRepository;
use std::{fmt, str::FromStr};

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::repository::{OrganizationRepository, ProjectRepository};
use crate::{
    access_audit::{AccessAuditActor, AccessAuditEvent, write_access_audit},
    access_control::{ProjectRole, can_manage_project_role, resolve_project_access},
    auth::{
        IdentityPrincipal, OrganizationRole, UserSessionAuthenticator, hash_password,
        normalize_email, session_token, validate_password,
    },
    transactional_mail::{Locale, MailConfig, MailError, TemplateData, enqueue_invitation},
    user_auth::{insert_session_with_context, session_cookie, valid_name},
    web_api::{InvitationConfig, RequestId, WebApiConfig},
};

const TOKEN_PREFIX: &str = "oko_invitation_v1_";
const TOKEN_BYTES: usize = 32;
const DEFAULT_PAGE_LIMIT: i64 = 50;
const MAX_PAGE_LIMIT: i64 = 100;

#[derive(Clone, Debug)]
struct InvitationState {
    pool: PgPool,
    auth: UserSessionAuthenticator,
    invitations: InvitationConfig,
    mail: MailConfig,
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
            auth: UserSessionAuthenticator::new(pool.clone()),
            pool,
            invitations: config.invitations,
            mail: config.mail.clone(),
            secure_cookie: config.secure_session_cookie,
            session_lifetime: config.session_lifetime,
        })
}

struct InvitationToken {
    plaintext: Zeroizing<String>,
    digest: [u8; 32],
}

impl InvitationToken {
    fn generate() -> Self {
        let mut bytes = [0_u8; TOKEN_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        let plaintext = Zeroizing::new(format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)));
        let digest = Sha256::digest(plaintext.as_bytes()).into();
        Self { plaintext, digest }
    }
}

impl fmt::Debug for InvitationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvitationToken")
            .finish_non_exhaustive()
    }
}

fn invitation_digest(token: &str) -> Option<[u8; 32]> {
    let encoded = token.strip_prefix(TOKEN_PREFIX)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    if bytes.len() != TOKEN_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return None;
    }
    Some(Sha256::digest(token.as_bytes()).into())
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

    fn unusable(request_id: &RequestId) -> Self {
        Self::new(
            StatusCode::GONE,
            ErrorCode::INVITATION_UNUSABLE,
            "invitation is unavailable",
            request_id,
        )
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

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum InvitationScope {
    Organization,
    Project,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum InvitationStatus {
    Pending,
    Accepted,
    Revoked,
    Expired,
    Replaced,
}

#[derive(Debug, Deserialize)]
struct CreateInvitationRequest {
    email: String,
    role: String,
    locale: Locale,
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

#[derive(Debug, FromRow)]
struct InvitationRow {
    id: Uuid,
    organization_id: Uuid,
    organization_name: String,
    project_id: Option<Uuid>,
    project_name: Option<String>,
    recipient_email: String,
    role: String,
    inviter_display_name: String,
    locale: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    accepted_at: Option<DateTime<Utc>>,
    accepted_by_user_id: Option<Uuid>,
    revoked_at: Option<DateTime<Utc>>,
    replaced_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InvitationView {
    id: Uuid,
    scope: InvitationScope,
    organization_id: Uuid,
    organization_name: String,
    project_id: Option<Uuid>,
    project_name: Option<String>,
    recipient_email: String,
    role: String,
    inviter_display_name: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    status: InvitationStatus,
}

#[derive(Debug, Serialize)]
struct InvitationPage {
    items: Vec<InvitationView>,
    next_cursor: Option<Uuid>,
}

impl From<InvitationRow> for InvitationView {
    fn from(row: InvitationRow) -> Self {
        let status = status(&row);
        Self {
            id: row.id,
            scope: scope(&row),
            organization_id: row.organization_id,
            organization_name: row.organization_name,
            project_id: row.project_id,
            project_name: row.project_name,
            recipient_email: row.recipient_email,
            role: row.role,
            inviter_display_name: row.inviter_display_name,
            created_at: row.created_at,
            expires_at: row.expires_at,
            status,
        }
    }
}

fn scope(row: &InvitationRow) -> InvitationScope {
    if row.project_id.is_some() {
        InvitationScope::Project
    } else {
        InvitationScope::Organization
    }
}

fn status(row: &InvitationRow) -> InvitationStatus {
    if row.accepted_at.is_some() {
        InvitationStatus::Accepted
    } else if row.revoked_at.is_some() {
        InvitationStatus::Revoked
    } else if row.replaced_at.is_some() {
        InvitationStatus::Replaced
    } else if row.expires_at <= Utc::now() {
        InvitationStatus::Expired
    } else {
        InvitationStatus::Pending
    }
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

async fn platform_identity(
    state: &InvitationState,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> Result<IdentityPrincipal, InvitationError> {
    let principal = identity(state, headers, request_id).await?;
    if principal.is_super_admin {
        Ok(principal)
    } else {
        Err(InvitationError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::FORBIDDEN,
            "super administrator role is required",
            request_id,
        ))
    }
}

async fn organization_actor(
    state: &InvitationState,
    headers: &HeaderMap,
    organization_id: Uuid,
    request_id: &RequestId,
) -> Result<IdentityPrincipal, InvitationError> {
    let principal = identity(state, headers, request_id).await?;
    if principal.is_super_admin {
        return Ok(principal);
    }
    if principal.active_organization_id != Some(organization_id) {
        return Err(not_found(ErrorCode::ORGANIZATION_NOT_FOUND, request_id));
    }
    if matches!(
        principal.organization_role,
        Some(OrganizationRole::Owner | OrganizationRole::Admin)
    ) {
        Ok(principal)
    } else {
        Err(forbidden(request_id))
    }
}

struct ProjectActor {
    principal: IdentityPrincipal,
    organization_id: Uuid,
    project_role: ProjectRole,
}

async fn project_actor(
    state: &InvitationState,
    headers: &HeaderMap,
    project_id: Uuid,
    request_id: &RequestId,
) -> Result<ProjectActor, InvitationError> {
    let principal = identity(state, headers, request_id).await?;
    let organization_id: Option<Uuid> = ProjectRepository::organization_of(&state.pool, project_id)
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    let organization_id =
        organization_id.ok_or_else(|| not_found(ErrorCode::PROJECT_NOT_FOUND, request_id))?;
    let access = resolve_project_access(&state.pool, principal, organization_id, project_id)
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?
        .ok_or_else(|| not_found(ErrorCode::PROJECT_NOT_FOUND, request_id))?;
    if !access.can_manage_members() {
        return Err(forbidden(request_id));
    }
    Ok(ProjectActor {
        principal,
        organization_id,
        project_role: access.role,
    })
}

fn not_found(code: ErrorCode, request_id: &RequestId) -> InvitationError {
    InvitationError::new(
        StatusCode::NOT_FOUND,
        code,
        "resource not found",
        request_id,
    )
}

fn forbidden(request_id: &RequestId) -> InvitationError {
    InvitationError::new(
        StatusCode::FORBIDDEN,
        ErrorCode::FORBIDDEN,
        "insufficient permission",
        request_id,
    )
}

fn invalid(message: &'static str, request_id: &RequestId) -> InvitationError {
    InvitationError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::VALIDATION_FAILED,
        message,
        request_id,
    )
}

fn conflict(code: ErrorCode, request_id: &RequestId) -> InvitationError {
    InvitationError::new(
        StatusCode::CONFLICT,
        code,
        "invitation conflicts with current state",
        request_id,
    )
}

fn page_limit(limit: Option<i64>, request_id: &RequestId) -> Result<i64, InvitationError> {
    let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if (1..=MAX_PAGE_LIMIT).contains(&limit) {
        Ok(limit)
    } else {
        Err(invalid("limit must be between 1 and 100", request_id))
    }
}

fn no_store<T: Serialize>(status: StatusCode, value: T) -> Response {
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

const INVITATION_SELECT: &str = "SELECT i.id,i.organization_id,o.name organization_name,i.project_id,p.name project_name,i.recipient_email,i.role,u.display_name inviter_display_name,i.locale,i.created_at,i.expires_at,i.accepted_at,i.accepted_by_user_id,i.revoked_at,i.replaced_at FROM invitations i JOIN organizations o ON o.id=i.organization_id LEFT JOIN projects p ON p.id=i.project_id JOIN users u ON u.id=i.inviter_user_id";

async fn load_invitation_by_digest(
    tx: &mut Transaction<'_, Postgres>,
    digest: [u8; 32],
) -> Result<Option<InvitationRow>, sqlx::Error> {
    let query = format!("{INVITATION_SELECT} WHERE i.token_digest=$1 FOR UPDATE OF i");
    sqlx::query_as(&query)
        .bind(digest.to_vec())
        .fetch_optional(&mut **tx)
        .await
}

fn is_live(row: &InvitationRow) -> bool {
    row.accepted_at.is_none()
        && row.revoked_at.is_none()
        && row.replaced_at.is_none()
        && row.expires_at > Utc::now()
}

fn page(mut rows: Vec<InvitationRow>, limit: i64) -> InvitationPage {
    let has_more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    if has_more {
        rows.pop();
    }
    let next_cursor = has_more.then(|| rows.last().map(|row| row.id)).flatten();
    InvitationPage {
        items: rows.into_iter().map(InvitationView::from).collect(),
        next_cursor,
    }
}

async fn list_platform(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response, InvitationError> {
    platform_identity(&state, &headers, &request_id).await?;
    let limit = page_limit(query.limit, &request_id)?;
    let sql = format!(
        "{INVITATION_SELECT} WHERE ($1::uuid IS NULL OR (i.created_at,i.id)<(SELECT created_at,id FROM invitations WHERE id=$1)) ORDER BY i.created_at DESC,i.id DESC LIMIT $2"
    );
    let rows = sqlx::query_as(&sql)
        .bind(query.cursor)
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?;
    Ok(no_store(StatusCode::OK, page(rows, limit)))
}

async fn list_platform_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Response, InvitationError> {
    platform_identity(&state, &headers, &request_id).await?;
    list_organization(
        State(state),
        Extension(request_id),
        headers,
        Path(organization_id),
        Query(query),
    )
    .await
}

async fn list_platform_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Response, InvitationError> {
    platform_identity(&state, &headers, &request_id).await?;
    list_project(
        State(state),
        Extension(request_id),
        headers,
        Path(project_id),
        Query(query),
    )
    .await
}

async fn list_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Response, InvitationError> {
    organization_actor(&state, &headers, organization_id, &request_id).await?;
    let limit = page_limit(query.limit, &request_id)?;
    let sql = format!(
        "{INVITATION_SELECT} WHERE i.organization_id=$1 AND i.project_id IS NULL AND ($2::uuid IS NULL OR (i.created_at,i.id)<(SELECT created_at,id FROM invitations WHERE id=$2 AND organization_id=$1 AND project_id IS NULL)) ORDER BY i.created_at DESC,i.id DESC LIMIT $3"
    );
    let rows = sqlx::query_as(&sql)
        .bind(organization_id)
        .bind(query.cursor)
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?;
    Ok(no_store(StatusCode::OK, page(rows, limit)))
}

async fn list_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Response, InvitationError> {
    project_actor(&state, &headers, project_id, &request_id).await?;
    let limit = page_limit(query.limit, &request_id)?;
    let sql = format!(
        "{INVITATION_SELECT} WHERE i.project_id=$1 AND ($2::uuid IS NULL OR (i.created_at,i.id)<(SELECT created_at,id FROM invitations WHERE id=$2 AND project_id=$1)) ORDER BY i.created_at DESC,i.id DESC LIMIT $3"
    );
    let rows = sqlx::query_as(&sql)
        .bind(project_id)
        .bind(query.cursor)
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?;
    Ok(no_store(StatusCode::OK, page(rows, limit)))
}

#[derive(Clone, Copy)]
struct IssueScope {
    organization_id: Uuid,
    project_id: Option<Uuid>,
}

struct IssueRequest {
    scope: IssueScope,
    recipient_email: String,
    role: String,
    locale: Locale,
    inviter_user_id: Uuid,
}

async fn create_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(input): Json<CreateInvitationRequest>,
) -> Result<Response, InvitationError> {
    require_mail(&state, &request_id)?;
    let inviter = organization_actor(&state, &headers, organization_id, &request_id).await?;
    let role = OrganizationRole::from_str(&input.role)
        .map_err(|()| invalid("role must be owner, admin, or member", &request_id))?;
    if role == OrganizationRole::Owner
        && !inviter.is_super_admin
        && inviter.organization_role != Some(OrganizationRole::Owner)
    {
        return Err(forbidden(&request_id));
    }
    let invitation = issue(
        &state,
        IssueRequest {
            scope: IssueScope {
                organization_id,
                project_id: None,
            },
            recipient_email: normalize_email(&input.email)
                .map_err(|_| invalid("email is invalid", &request_id))?,
            role: input.role,
            locale: input.locale,
            inviter_user_id: inviter.user_id,
        },
        &request_id,
    )
    .await?;
    Ok(no_store(StatusCode::CREATED, invitation))
}

async fn create_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Json(input): Json<CreateInvitationRequest>,
) -> Result<Response, InvitationError> {
    require_mail(&state, &request_id)?;
    let actor = project_actor(&state, &headers, project_id, &request_id).await?;
    let role = ProjectRole::from_str(&input.role)
        .map_err(|()| invalid("role must be admin or member", &request_id))?;
    if !can_manage_project_role(
        actor.principal.is_super_admin,
        actor.principal.organization_role,
        Some(actor.project_role),
        Some(role),
    ) {
        return Err(forbidden(&request_id));
    }
    let invitation = issue(
        &state,
        IssueRequest {
            scope: IssueScope {
                organization_id: actor.organization_id,
                project_id: Some(project_id),
            },
            recipient_email: normalize_email(&input.email)
                .map_err(|_| invalid("email is invalid", &request_id))?,
            role: input.role,
            locale: input.locale,
            inviter_user_id: actor.principal.user_id,
        },
        &request_id,
    )
    .await?;
    Ok(no_store(StatusCode::CREATED, invitation))
}

async fn create_platform_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(input): Json<CreateInvitationRequest>,
) -> Result<Response, InvitationError> {
    platform_identity(&state, &headers, &request_id).await?;
    create_organization(
        State(state),
        Extension(request_id),
        headers,
        Path(organization_id),
        Json(input),
    )
    .await
}

async fn create_platform_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    Json(input): Json<CreateInvitationRequest>,
) -> Result<Response, InvitationError> {
    platform_identity(&state, &headers, &request_id).await?;
    create_project(
        State(state),
        Extension(request_id),
        headers,
        Path(project_id),
        Json(input),
    )
    .await
}

fn require_mail(state: &InvitationState, request_id: &RequestId) -> Result<(), InvitationError> {
    if state.mail.enabled {
        Ok(())
    } else {
        Err(InvitationError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::MAIL_UNAVAILABLE,
            "invitation mail is unavailable",
            request_id,
        ))
    }
}

async fn issue(
    state: &InvitationState,
    request: IssueRequest,
    request_id: &RequestId,
) -> Result<InvitationView, InvitationError> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    let invitation = issue_in_transaction(
        &mut tx,
        &state.invitations,
        &state.mail,
        request,
        request_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    Ok(invitation)
}

async fn issue_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    invitation_config: &InvitationConfig,
    mail_config: &MailConfig,
    request: IssueRequest,
    request_id: &RequestId,
) -> Result<InvitationView, InvitationError> {
    validate_issue_target(tx, &request, request_id).await?;
    enforce_create_rate(tx, invitation_config, request.inviter_user_id, request_id).await?;
    let id = Uuid::new_v4();
    let expired_equivalent = reserve_expired_equivalent(tx, &request, request_id).await?;
    let token = InvitationToken::generate();
    let lifetime = Duration::from_std(invitation_config.lifetime)
        .map_err(|_| invalid("invitation lifetime is invalid", request_id))?;
    let expires_at = Utc::now() + lifetime;
    sqlx::query("INSERT INTO invitations(id,organization_id,project_id,recipient_email,role,inviter_user_id,locale,token_digest,expires_at,retain_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9+interval '365 days')")
        .bind(id).bind(request.scope.organization_id).bind(request.scope.project_id)
        .bind(&request.recipient_email).bind(&request.role).bind(request.inviter_user_id)
        .bind(request.locale.as_str()).bind(token.digest.to_vec()).bind(expires_at)
        .execute(&mut **tx).await.map_err(|error| map_issue_error(&error, request_id))?;
    if let Some(expired_id) = expired_equivalent {
        finalize_replacement(tx, expired_id, id, request_id).await?;
    }
    enqueue_issue_mail(
        tx,
        mail_config,
        &request,
        id,
        &token,
        expires_at,
        request_id,
    )
    .await?;
    audit(
        tx,
        request.inviter_user_id,
        "invitation.created",
        request.scope,
        id,
        Some(&request.role),
        request_id,
    )
    .await?;
    let invitation = load_invitation_by_id(tx, id)
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?
        .ok_or_else(|| InvitationError::database(&sqlx::Error::RowNotFound, request_id))?;
    Ok(invitation.into())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn issue_organization_invitation(
    tx: &mut Transaction<'_, Postgres>,
    config: &WebApiConfig,
    actor_user_id: Uuid,
    organization_id: Uuid,
    email: &str,
    role: OrganizationRole,
    locale: Locale,
    request_id: &RequestId,
) -> Result<InvitationView, InvitationError> {
    if !config.mail.enabled {
        return Err(InvitationError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::MAIL_UNAVAILABLE,
            "invitation mail is unavailable",
            request_id,
        ));
    }
    let email = normalize_email(email).map_err(|_| invalid("email is invalid", request_id))?;
    let role = match role {
        OrganizationRole::Owner => "owner",
        OrganizationRole::Admin => "admin",
        OrganizationRole::Member => "member",
    };
    issue_in_transaction(
        tx,
        &config.invitations,
        &config.mail,
        IssueRequest {
            scope: IssueScope {
                organization_id,
                project_id: None,
            },
            recipient_email: email,
            role: role.to_owned(),
            locale,
            inviter_user_id: actor_user_id,
        },
        request_id,
    )
    .await
}

async fn validate_issue_target(
    tx: &mut Transaction<'_, Postgres>,
    request: &IssueRequest,
    request_id: &RequestId,
) -> Result<(), InvitationError> {
    let target_exists: bool = if let Some(project_id) = request.scope.project_id {
        ProjectRepository::exists_in(&mut **tx, request.scope.organization_id, project_id).await
    } else {
        OrganizationRepository::exists(&mut **tx, request.scope.organization_id).await
    }
    .map_err(|error| InvitationError::database(&error, request_id))?;
    if !target_exists {
        return Err(not_found(ErrorCode::INVITATION_SCOPE_NOT_FOUND, request_id));
    }
    let membership_exists: bool = if let Some(project_id) = request.scope.project_id {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users u JOIN project_memberships m ON m.user_id=u.id WHERE u.email=$1 AND m.project_id=$2)")
            .bind(&request.recipient_email).bind(project_id).fetch_one(&mut **tx).await
    } else {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users u JOIN organization_memberships m ON m.user_id=u.id WHERE u.email=$1 AND m.organization_id=$2)")
            .bind(&request.recipient_email).bind(request.scope.organization_id).fetch_one(&mut **tx).await
    }.map_err(|error| InvitationError::database(&error, request_id))?;
    if membership_exists {
        return Err(conflict(ErrorCode::MEMBERSHIP_EXISTS, request_id));
    }
    Ok(())
}

async fn enforce_create_rate(
    tx: &mut Transaction<'_, Postgres>,
    config: &InvitationConfig,
    inviter_user_id: Uuid,
    request_id: &RequestId,
) -> Result<(), InvitationError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM invitations WHERE inviter_user_id=$1 AND created_at>now()-interval '1 hour'",
    )
    .bind(inviter_user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| InvitationError::database(&error, request_id))?;
    if count >= i64::from(config.create_limit_per_hour) {
        Err(InvitationError::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RATE_LIMITED,
            "invitation rate limit exceeded",
            request_id,
        ))
    } else {
        Ok(())
    }
}

async fn reserve_expired_equivalent(
    tx: &mut Transaction<'_, Postgres>,
    request: &IssueRequest,
    request_id: &RequestId,
) -> Result<Option<Uuid>, InvitationError> {
    let existing: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id,expires_at FROM invitations WHERE organization_id=$1 AND project_id IS NOT DISTINCT FROM $2 AND recipient_email=$3 AND accepted_at IS NULL AND revoked_at IS NULL AND replaced_at IS NULL FOR UPDATE",
    )
    .bind(request.scope.organization_id)
    .bind(request.scope.project_id)
    .bind(&request.recipient_email)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| InvitationError::database(&error, request_id))?;
    if let Some((id, expires_at)) = existing {
        if expires_at > Utc::now() {
            return Err(conflict(ErrorCode::INVITATION_EXISTS, request_id));
        }
        sqlx::query("UPDATE invitations SET revoked_at=now() WHERE id=$1")
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(|error| InvitationError::database(&error, request_id))?;
        return Ok(Some(id));
    }
    Ok(None)
}

async fn finalize_replacement(
    tx: &mut Transaction<'_, Postgres>,
    expired_id: Uuid,
    replacement_id: Uuid,
    request_id: &RequestId,
) -> Result<(), InvitationError> {
    sqlx::query("UPDATE invitations SET revoked_at=NULL,replaced_at=now(),replaced_by_invitation_id=$2 WHERE id=$1")
        .bind(expired_id).bind(replacement_id).execute(&mut **tx).await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    Ok(())
}

async fn enqueue_issue_mail(
    tx: &mut Transaction<'_, Postgres>,
    mail: &MailConfig,
    request: &IssueRequest,
    invitation_id: Uuid,
    token: &InvitationToken,
    expires_at: DateTime<Utc>,
    request_id: &RequestId,
) -> Result<(), InvitationError> {
    let context: (String, Option<String>, String) = sqlx::query_as(
        "SELECT o.name,p.name,u.display_name FROM organizations o LEFT JOIN projects p ON p.id=$2 JOIN users u ON u.id=$3 WHERE o.id=$1",
    )
    .bind(request.scope.organization_id)
    .bind(request.scope.project_id)
    .bind(request.inviter_user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| InvitationError::database(&error, request_id))?;
    let action_url = format!(
        "{}/invite#token={}",
        mail.public_web_url.as_str().trim_end_matches('/'),
        token.plaintext.as_str()
    );
    let expires_minutes = (expires_at - Utc::now()).num_minutes().max(1);
    let data = if let Some(project_name) = context.1 {
        TemplateData::ProjectInvitation {
            action_url,
            organization_name: context.0,
            project_name,
            inviter_display_name: context.2,
            role: request.role.clone(),
            expires_minutes,
        }
    } else {
        TemplateData::OrganizationInvitation {
            action_url,
            organization_name: context.0,
            inviter_display_name: context.2,
            role: request.role.clone(),
            expires_minutes,
        }
    };
    enqueue_invitation(
        tx,
        mail,
        &format!("invitation:{invitation_id}"),
        (request.recipient_email.clone(), request.locale),
        &data,
        invitation_id,
        expires_at,
    )
    .await
    .map_err(|error| mail_error(&error, request_id))
}

fn mail_error(_error: &MailError, request_id: &RequestId) -> InvitationError {
    tracing::error!(request_id=%request_id.0, "invitation mail intent failed");
    InvitationError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::MAIL_UNAVAILABLE,
        "invitation mail is unavailable",
        request_id,
    )
}

async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    actor_user_id: Uuid,
    action: &str,
    scope: IssueScope,
    invitation_id: Uuid,
    new_role: Option<&str>,
    request_id: &RequestId,
) -> Result<(), InvitationError> {
    write_access_audit(
        tx,
        AccessAuditEvent {
            actor: AccessAuditActor::User(actor_user_id),
            action,
            organization_id: Some(scope.organization_id),
            project_id: scope.project_id,
            target_user_id: None,
            invitation_id: Some(invitation_id),
            previous_role: None,
            new_role,
            request_id: Some(&request_id.0),
        },
    )
    .await
    .map_err(|error| InvitationError::database(&error, request_id))?;
    crate::metrics::record_invitation_lifecycle(true);
    Ok(())
}

async fn load_invitation_by_id(
    tx: &mut Transaction<'_, Postgres>,
    invitation_id: Uuid,
) -> Result<Option<InvitationRow>, sqlx::Error> {
    let query = format!("{INVITATION_SELECT} WHERE i.id=$1");
    sqlx::query_as(&query)
        .bind(invitation_id)
        .fetch_optional(&mut **tx)
        .await
}

fn map_issue_error(error: &sqlx::Error, request_id: &RequestId) -> InvitationError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "23505")
    {
        conflict(ErrorCode::INVITATION_EXISTS, request_id)
    } else {
        InvitationError::database(error, request_id)
    }
}

async fn load_invitation(
    pool: &PgPool,
    invitation_id: Uuid,
) -> Result<Option<InvitationRow>, sqlx::Error> {
    let query = format!("{INVITATION_SELECT} WHERE i.id=$1");
    sqlx::query_as(&query)
        .bind(invitation_id)
        .fetch_optional(pool)
        .await
}

pub(crate) async fn current_organization_owner_invitation(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Option<InvitationView>, sqlx::Error> {
    let query = format!(
        "{INVITATION_SELECT} WHERE i.organization_id=$1 AND i.project_id IS NULL AND i.role='owner' AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.replaced_at IS NULL ORDER BY i.created_at DESC,i.id DESC LIMIT 1"
    );
    let row: Option<InvitationRow> = sqlx::query_as(&query)
        .bind(organization_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(InvitationView::from))
}

async fn authorize_organization_invitation(
    state: &InvitationState,
    headers: &HeaderMap,
    organization_id: Uuid,
    invitation_id: Uuid,
    request_id: &RequestId,
) -> Result<(IdentityPrincipal, InvitationRow), InvitationError> {
    let principal = organization_actor(state, headers, organization_id, request_id).await?;
    let row = load_invitation(&state.pool, invitation_id)
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?
        .filter(|row| row.organization_id == organization_id && row.project_id.is_none())
        .ok_or_else(|| not_found(ErrorCode::INVITATION_NOT_FOUND, request_id))?;
    if row.role == "owner"
        && !principal.is_super_admin
        && principal.organization_role != Some(OrganizationRole::Owner)
    {
        return Err(forbidden(request_id));
    }
    Ok((principal, row))
}

async fn authorize_project_invitation(
    state: &InvitationState,
    headers: &HeaderMap,
    project_id: Uuid,
    invitation_id: Uuid,
    request_id: &RequestId,
) -> Result<(ProjectActor, InvitationRow), InvitationError> {
    let actor = project_actor(state, headers, project_id, request_id).await?;
    let row = load_invitation(&state.pool, invitation_id)
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?
        .filter(|row| row.project_id == Some(project_id))
        .ok_or_else(|| not_found(ErrorCode::INVITATION_NOT_FOUND, request_id))?;
    let role = ProjectRole::from_str(&row.role)
        .map_err(|()| InvitationError::database(&sqlx::Error::RowNotFound, request_id))?;
    if !can_manage_project_role(
        actor.principal.is_super_admin,
        actor.principal.organization_role,
        Some(actor.project_role),
        Some(role),
    ) {
        return Err(forbidden(request_id));
    }
    Ok((actor, row))
}

async fn resend_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((organization_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    require_mail(&state, &request_id)?;
    let (principal, row) = authorize_organization_invitation(
        &state,
        &headers,
        organization_id,
        invitation_id,
        &request_id,
    )
    .await?;
    let replacement = resend(&state, principal, row, &request_id).await?;
    Ok(no_store(StatusCode::CREATED, replacement))
}

async fn resend_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((project_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    require_mail(&state, &request_id)?;
    let (actor, row) =
        authorize_project_invitation(&state, &headers, project_id, invitation_id, &request_id)
            .await?;
    let replacement = resend(&state, actor.principal, row, &request_id).await?;
    Ok(no_store(StatusCode::CREATED, replacement))
}

async fn resend_platform_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(path): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    platform_identity(&state, &headers, &request_id).await?;
    resend_organization(State(state), Extension(request_id), headers, Path(path)).await
}

async fn resend_platform_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(path): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    platform_identity(&state, &headers, &request_id).await?;
    resend_project(State(state), Extension(request_id), headers, Path(path)).await
}

async fn resend(
    state: &InvitationState,
    principal: IdentityPrincipal,
    row: InvitationRow,
    request_id: &RequestId,
) -> Result<InvitationView, InvitationError> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    let locked = load_invitation_by_id_for_update(&mut tx, row.id)
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?
        .ok_or_else(|| not_found(ErrorCode::INVITATION_NOT_FOUND, request_id))?;
    if locked.accepted_at.is_some() || locked.revoked_at.is_some() || locked.replaced_at.is_some() {
        return Err(conflict(ErrorCode::INVITATION_NOT_PENDING, request_id));
    }
    enforce_resend_rate(&mut tx, state, principal.user_id, request_id).await?;
    let replacement_id = Uuid::new_v4();
    sqlx::query("UPDATE invitations SET revoked_at=now() WHERE id=$1")
        .bind(locked.id)
        .execute(&mut *tx)
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    let request = IssueRequest {
        scope: IssueScope {
            organization_id: locked.organization_id,
            project_id: locked.project_id,
        },
        recipient_email: locked.recipient_email,
        role: locked.role,
        locale: locked.locale.parse().unwrap_or(Locale::En),
        inviter_user_id: principal.user_id,
    };
    let token = InvitationToken::generate();
    let expires_at = Utc::now()
        + Duration::from_std(state.invitations.lifetime)
            .map_err(|_| invalid("invitation lifetime is invalid", request_id))?;
    insert_replacement(
        &mut tx,
        replacement_id,
        &request,
        &token,
        expires_at,
        request_id,
    )
    .await?;
    finalize_replacement(&mut tx, locked.id, replacement_id, request_id).await?;
    enqueue_issue_mail(
        &mut tx,
        &state.mail,
        &request,
        replacement_id,
        &token,
        expires_at,
        request_id,
    )
    .await?;
    audit(
        &mut tx,
        principal.user_id,
        "invitation.resent",
        request.scope,
        replacement_id,
        Some(&request.role),
        request_id,
    )
    .await?;
    let replacement = load_invitation_by_id(&mut tx, replacement_id)
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?
        .ok_or_else(|| InvitationError::database(&sqlx::Error::RowNotFound, request_id))?;
    tx.commit()
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    Ok(replacement.into())
}

async fn insert_replacement(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    request: &IssueRequest,
    token: &InvitationToken,
    expires_at: DateTime<Utc>,
    request_id: &RequestId,
) -> Result<(), InvitationError> {
    sqlx::query("INSERT INTO invitations(id,organization_id,project_id,recipient_email,role,inviter_user_id,locale,token_digest,expires_at,retain_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9+interval '365 days')")
        .bind(id).bind(request.scope.organization_id).bind(request.scope.project_id)
        .bind(&request.recipient_email).bind(&request.role).bind(request.inviter_user_id)
        .bind(request.locale.as_str()).bind(token.digest.to_vec()).bind(expires_at)
        .execute(&mut **tx).await.map_err(|error| map_issue_error(&error, request_id))?;
    Ok(())
}

async fn enforce_resend_rate(
    tx: &mut Transaction<'_, Postgres>,
    state: &InvitationState,
    actor_user_id: Uuid,
    request_id: &RequestId,
) -> Result<(), InvitationError> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM access_audit_records WHERE actor_user_id=$1 AND action='invitation.resent' AND created_at>now()-interval '1 hour'")
        .bind(actor_user_id).fetch_one(&mut **tx).await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    if count >= i64::from(state.invitations.resend_limit_per_hour) {
        return Err(InvitationError::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RATE_LIMITED,
            "invitation rate limit exceeded",
            request_id,
        ));
    }
    Ok(())
}

async fn load_invitation_by_id_for_update(
    tx: &mut Transaction<'_, Postgres>,
    invitation_id: Uuid,
) -> Result<Option<InvitationRow>, sqlx::Error> {
    let query = format!("{INVITATION_SELECT} WHERE i.id=$1 FOR UPDATE OF i");
    sqlx::query_as(&query)
        .bind(invitation_id)
        .fetch_optional(&mut **tx)
        .await
}

async fn revoke_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((organization_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    let (principal, row) = authorize_organization_invitation(
        &state,
        &headers,
        organization_id,
        invitation_id,
        &request_id,
    )
    .await?;
    revoke(&state, principal.user_id, row, &request_id).await?;
    Ok(no_store(StatusCode::NO_CONTENT, ()))
}

async fn revoke_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path((project_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    let (actor, row) =
        authorize_project_invitation(&state, &headers, project_id, invitation_id, &request_id)
            .await?;
    revoke(&state, actor.principal.user_id, row, &request_id).await?;
    Ok(no_store(StatusCode::NO_CONTENT, ()))
}

async fn revoke_platform_organization(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(path): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    platform_identity(&state, &headers, &request_id).await?;
    revoke_organization(State(state), Extension(request_id), headers, Path(path)).await
}

async fn revoke_platform_project(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(path): Path<(Uuid, Uuid)>,
) -> Result<Response, InvitationError> {
    platform_identity(&state, &headers, &request_id).await?;
    revoke_project(State(state), Extension(request_id), headers, Path(path)).await
}

async fn revoke(
    state: &InvitationState,
    actor_user_id: Uuid,
    row: InvitationRow,
    request_id: &RequestId,
) -> Result<(), InvitationError> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    let locked = load_invitation_by_id_for_update(&mut tx, row.id)
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?
        .ok_or_else(|| not_found(ErrorCode::INVITATION_NOT_FOUND, request_id))?;
    if locked.accepted_at.is_some() || locked.replaced_at.is_some() {
        return Err(conflict(ErrorCode::INVITATION_NOT_PENDING, request_id));
    }
    if locked.revoked_at.is_none() {
        sqlx::query("UPDATE invitations SET revoked_at=now() WHERE id=$1")
            .bind(locked.id)
            .execute(&mut *tx)
            .await
            .map_err(|error| InvitationError::database(&error, request_id))?;
        audit(
            &mut tx,
            actor_user_id,
            "invitation.revoked",
            IssueScope {
                organization_id: locked.organization_id,
                project_id: locked.project_id,
            },
            locked.id,
            None,
            request_id,
        )
        .await?;
    }
    tx.commit()
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum InvitationAccountState {
    NewUser,
    ExistingUser,
}

#[derive(Debug, Serialize)]
struct InvitationInspection {
    scope: InvitationScope,
    organization_name: String,
    project_name: Option<String>,
    role: String,
    inviter_display_name: String,
    expires_at: DateTime<Utc>,
    account_state: InvitationAccountState,
}

async fn inspect(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<InvitationTokenRequest>,
) -> Result<Response, InvitationError> {
    let digest =
        invitation_digest(&input.token).ok_or_else(|| InvitationError::unusable(&request_id))?;
    let query = format!("{INVITATION_SELECT} WHERE i.token_digest=$1");
    let row: InvitationRow = sqlx::query_as(&query)
        .bind(digest.to_vec())
        .fetch_optional(&state.pool)
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?
        .filter(is_live)
        .ok_or_else(|| InvitationError::unusable(&request_id))?;
    let user_exists: bool = UserRepository::exists_by_email(&state.pool, &row.recipient_email)
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?;
    let inspection = InvitationInspection {
        scope: scope(&row),
        organization_name: row.organization_name,
        project_name: row.project_name,
        role: row.role,
        inviter_display_name: row.inviter_display_name,
        expires_at: row.expires_at,
        account_state: if user_exists {
            InvitationAccountState::ExistingUser
        } else {
            InvitationAccountState::NewUser
        },
    };
    Ok(no_store(StatusCode::OK, inspection))
}

#[derive(Debug, Serialize)]
struct InvitationAcceptance {
    status: &'static str,
    scope: InvitationScope,
    organization_id: Uuid,
    project_id: Option<Uuid>,
    role: String,
    user_id: Uuid,
}

fn accepted(row: &InvitationRow, user_id: Uuid) -> InvitationAcceptance {
    InvitationAcceptance {
        status: "accepted",
        scope: scope(row),
        organization_id: row.organization_id,
        project_id: row.project_id,
        role: row.role.clone(),
        user_id,
    }
}

async fn accept_new_user(
    State(state): State<InvitationState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<NewUserAcceptanceRequest>,
) -> Result<Response, InvitationError> {
    validate_password(&input.password).map_err(|_| invalid("password is invalid", &request_id))?;
    if !valid_name(&input.display_name) {
        return Err(invalid("display name is invalid", &request_id));
    }
    let digest =
        invitation_digest(&input.token).ok_or_else(|| InvitationError::unusable(&request_id))?;
    let password_hash = hash_password(&input.password).map_err(|_error| {
        tracing::error!(request_id=%request_id.0, "invitation password hashing failed");
        InvitationError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::INTERNAL_ERROR,
            "internal server error",
            &request_id,
        )
    })?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?;
    let row = load_invitation_by_digest(&mut tx, digest)
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?
        .filter(is_live)
        .ok_or_else(|| InvitationError::unusable(&request_id))?;
    let user_exists: bool = UserRepository::exists_by_email(&mut *tx, &row.recipient_email)
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?;
    if user_exists {
        return Err(conflict(
            ErrorCode::INVITATION_REQUIRES_SIGN_IN,
            &request_id,
        ));
    }
    let user_id = Uuid::new_v4();
    UserRepository::insert_verified(
        &mut *tx,
        user_id,
        &row.recipient_email,
        &password_hash,
        input.locale.as_str(),
        &input.display_name,
    )
    .await
    .map_err(|error| map_accept_error(&error, &request_id))?;
    grant_and_consume(&mut tx, &row, user_id, &request_id).await?;
    let (_, session) = insert_session_with_context(
        &mut tx,
        user_id,
        Some(row.organization_id),
        None,
        state.session_lifetime,
    )
    .await
    .map_err(|error| InvitationError::database(&error, &request_id))?;
    tx.commit()
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?;
    let mut response = no_store(StatusCode::CREATED, accepted(&row, user_id));
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(
            session.expose(),
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
    let digest =
        invitation_digest(&input.token).ok_or_else(|| InvitationError::unusable(&request_id))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?;
    let row = load_invitation_by_digest(&mut tx, digest)
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?
        .ok_or_else(|| InvitationError::unusable(&request_id))?;
    if row.accepted_by_user_id == Some(principal.user_id) {
        tx.commit()
            .await
            .map_err(|error| InvitationError::database(&error, &request_id))?;
        return Ok(no_store(StatusCode::OK, accepted(&row, principal.user_id)));
    }
    if !is_live(&row) {
        return Err(InvitationError::unusable(&request_id));
    }
    let identity: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT email,email_verified_at FROM users WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
    )
    .bind(principal.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| InvitationError::database(&error, &request_id))?;
    let matches = identity
        .is_some_and(|(email, verified)| verified.is_some() && email == row.recipient_email);
    if !matches {
        return Err(conflict(
            ErrorCode::INVITATION_ACCOUNT_MISMATCH,
            &request_id,
        ));
    }
    grant_and_consume(&mut tx, &row, principal.user_id, &request_id).await?;
    tx.commit()
        .await
        .map_err(|error| InvitationError::database(&error, &request_id))?;
    Ok(no_store(StatusCode::OK, accepted(&row, principal.user_id)))
}

async fn grant_and_consume(
    tx: &mut Transaction<'_, Postgres>,
    invitation: &InvitationRow,
    user_id: Uuid,
    request_id: &RequestId,
) -> Result<(), InvitationError> {
    let consumed = sqlx::query("UPDATE invitations SET accepted_at=now(),accepted_by_user_id=$2 WHERE id=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND replaced_at IS NULL AND expires_at>now()")
        .bind(invitation.id).bind(user_id).execute(&mut **tx).await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    if consumed.rows_affected() != 1 {
        return Err(InvitationError::unusable(request_id));
    }
    if let Some(project_id) = invitation.project_id {
        MembershipRepository::grant_organization_role_if_absent(
            &mut **tx,
            invitation.organization_id,
            user_id,
            "member",
        )
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
        MembershipRepository::grant_project_role_if_absent(
            &mut **tx,
            invitation.organization_id,
            project_id,
            user_id,
            &invitation.role,
        )
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    } else {
        MembershipRepository::grant_organization_role_if_absent(
            &mut **tx,
            invitation.organization_id,
            user_id,
            &invitation.role,
        )
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    }
    activate_first_owner(tx, invitation)
        .await
        .map_err(|error| InvitationError::database(&error, request_id))?;
    audit(
        tx,
        user_id,
        "invitation.accepted",
        IssueScope {
            organization_id: invitation.organization_id,
            project_id: invitation.project_id,
        },
        invitation.id,
        Some(&invitation.role),
        request_id,
    )
    .await
}

async fn activate_first_owner(
    tx: &mut Transaction<'_, Postgres>,
    invitation: &InvitationRow,
) -> Result<(), sqlx::Error> {
    if invitation.project_id.is_none() && invitation.role == "owner" {
        OrganizationRepository::activate_when_owned(&mut **tx, invitation.organization_id).await?;
    }
    Ok(())
}

fn map_accept_error(error: &sqlx::Error, request_id: &RequestId) -> InvitationError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "23505")
    {
        conflict(ErrorCode::INVITATION_IDENTITY_CONFLICT, request_id)
    } else {
        InvitationError::database(error, request_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_tokens_are_canonical_high_entropy_and_redacted() {
        let token = InvitationToken::generate();
        assert_eq!(
            invitation_digest(token.plaintext.as_str()),
            Some(token.digest)
        );
        assert!(token.plaintext.starts_with(TOKEN_PREFIX));
        assert!(!format!("{token:?}").contains(token.plaintext.as_str()));
        assert!(invitation_digest("invalid").is_none());
        assert!(invitation_digest("oko_invitation_v1_short").is_none());
    }

    #[test]
    fn status_precedence_is_closed_and_safe() {
        let now = Utc::now();
        let mut row = sample_row(now + Duration::days(7));
        assert_eq!(status(&row), InvitationStatus::Pending);
        row.expires_at = now - Duration::seconds(1);
        assert_eq!(status(&row), InvitationStatus::Expired);
        row.replaced_at = Some(now);
        assert_eq!(status(&row), InvitationStatus::Replaced);
        row.replaced_at = None;
        row.revoked_at = Some(now);
        assert_eq!(status(&row), InvitationStatus::Revoked);
        row.revoked_at = None;
        row.accepted_at = Some(now);
        assert_eq!(status(&row), InvitationStatus::Accepted);
    }

    fn sample_row(expires_at: DateTime<Utc>) -> InvitationRow {
        InvitationRow {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            organization_name: "Northstar".into(),
            project_id: None,
            project_name: None,
            recipient_email: "user@example.com".into(),
            role: "member".into(),
            inviter_display_name: "Alice".into(),
            locale: "en".into(),
            created_at: Utc::now(),
            expires_at,
            accepted_at: None,
            accepted_by_user_id: None,
            revoked_at: None,
            replaced_at: None,
        }
    }
}
