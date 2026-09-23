use crate::error_code::ErrorCode;
use crate::repository::MembershipRepository;
use crate::repository::SessionRepository;
use crate::repository::UserRepository;
use crate::repository::email_actions::EmailActionRepository;
use crate::repository::{OrganizationRepository, OrganizationStatus};
use axum::{
    Extension, Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    access_audit::{AccessAuditActor, AccessAuditEvent, write_access_audit},
    auth::{
        AuthenticatedUser, OrganizationRole, SESSION_COOKIE, SessionToken,
        UserSessionAuthenticator, hash_password, normalize_email, session_digest, session_token,
        validate_password, verify_password,
    },
    transactional_mail::{Locale, MailConfig, TemplateData, enqueue},
    web_api::{RequestId, WebApiConfig},
};

const VERIFY_TTL_MINUTES: i64 = 24 * 60;
const RESET_TTL_MINUTES: i64 = 30;
const ACTION_COOLDOWN_SECONDS: i32 = 60;

#[derive(Clone, Debug)]
struct AuthState {
    pool: PgPool,
    authenticator: UserSessionAuthenticator,
    public_signup_enabled: bool,
    secure_cookie: bool,
    session_lifetime: std::time::Duration,
    mail: MailConfig,
}

pub fn router(pool: PgPool, config: &WebApiConfig) -> Router {
    Router::new()
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/auth/logout", post(logout))
        .route(
            "/api/v1/auth/email-verification-requests",
            post(resend_verification),
        )
        .route(
            "/api/v1/auth/email-verifications",
            post(confirm_verification),
        )
        .route(
            "/api/v1/auth/password-reset-requests",
            post(request_password_reset),
        )
        .route(
            "/api/v1/auth/password-resets",
            post(complete_password_reset),
        )
        .route("/api/v1/auth/password", put(change_password))
        .route("/api/v1/auth/preferences", put(update_preferences))
        .with_state(AuthState {
            authenticator: UserSessionAuthenticator::new(pool.clone()),
            pool,
            public_signup_enabled: config.public_signup_enabled,
            secure_cookie: config.secure_session_cookie,
            session_lifetime: config.session_lifetime,
            mail: config.mail.clone(),
        })
}

pub async fn recover_super_admin(
    pool: &PgPool,
    email: &str,
    admin_credential: Option<&str>,
) -> anyhow::Result<()> {
    let credential = admin_credential.ok_or_else(|| {
        anyhow::anyhow!("OKOSCOPE_ADMIN_CREDENTIAL is required for platform recovery")
    })?;
    crate::admin_auth::AdminAuthenticator::new(credential).map_err(anyhow::Error::msg)?;
    let email = normalize_email(email).map_err(anyhow::Error::msg)?;
    let mut tx = pool.begin().await?;
    MembershipRepository::lock_authority(&mut *tx).await?;
    let user_id = UserRepository::active_id_by_email_for_update(&mut *tx, &email)
        .await?
        .ok_or_else(|| anyhow::anyhow!("eligible verified user does not exist"))?;
    UserRepository::recover_super_admin(&mut *tx, user_id).await?;
    write_access_audit(
        &mut tx,
        AccessAuditEvent {
            actor: AccessAuditActor::SystemRecovery,
            action: "platform_recovery.completed",
            organization_id: None,
            project_id: None,
            target_user_id: Some(user_id),
            invitation_id: None,
            previous_role: None,
            new_role: Some("super_admin"),
            request_id: None,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn verify_user_access(pool: &PgPool, setup_enabled: bool) -> anyhow::Result<()> {
    let administrator_count = UserRepository::active_super_admin_count(pool).await?;
    anyhow::ensure!(
        setup_enabled || administrator_count > 0,
        "no active super administrator exists; configure setup authorization or run platform recovery"
    );
    Ok(())
}

#[derive(Debug)]
struct AuthError {
    status: StatusCode,
    code: ErrorCode,
    message: &'static str,
    request_id: RequestId,
}

impl AuthError {
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
    fn validation(message: &'static str, request_id: &RequestId) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            ErrorCode::VALIDATION_FAILED,
            message,
            request_id,
        )
    }
    fn internal(_error: &impl std::fmt::Display, request_id: &RequestId) -> Self {
        tracing::error!(request_id=%request_id.0, "user authentication operation failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::INTERNAL_ERROR,
            "internal server error",
            request_id,
        )
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body {
            error: ErrorCode,
            message: &'static str,
            request_id: String,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    email: String,
    password: String,
    display_name: String,
    organization_slug: String,
    organization_name: String,
    locale: Locale,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetRequest {
    token: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreferencesRequest {
    locale: Locale,
    display_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct Accepted {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    user: UserResponse,
    platform_role: Option<&'static str>,
    organizations: Vec<OrganizationResponse>,
    active_organization: Option<OrganizationResponse>,
    active_role: Option<OrganizationRole>,
    requires_organization_selection: bool,
    privileged_until: Option<chrono::DateTime<Utc>>,
    capabilities: serde_json::Value,
}

fn access_capabilities(is_super_admin: bool, role: Option<OrganizationRole>) -> serde_json::Value {
    let manages_organization = is_super_admin
        || matches!(
            role,
            Some(OrganizationRole::Owner | OrganizationRole::Admin)
        );
    let organization_roles = match (is_super_admin, role) {
        (true, _) | (_, Some(OrganizationRole::Owner)) => vec![
            OrganizationRole::Owner,
            OrganizationRole::Admin,
            OrganizationRole::Member,
        ],
        (_, Some(OrganizationRole::Admin)) => {
            vec![OrganizationRole::Admin, OrganizationRole::Member]
        }
        _ => Vec::new(),
    };
    let project_roles = if manages_organization {
        vec![
            crate::access_control::ProjectRole::Admin,
            crate::access_control::ProjectRole::Member,
        ]
    } else {
        Vec::new()
    };
    serde_json::json!({
        "manage_platform": is_super_admin,
        "manage_organization": manages_organization,
        "create_project": manages_organization,
        "manage_project_members": manages_organization,
        "create_application": manages_organization,
        "manage_credentials": manages_organization,
        "organization_roles_grantable": organization_roles,
        "project_roles_grantable": project_roles,
    })
}

#[derive(Debug, Serialize)]
struct UserResponse {
    id: Uuid,
    email: String,
    display_name: String,
    email_verified: bool,
    preferred_locale: Locale,
}

#[derive(Debug, Serialize)]
struct OrganizationResponse {
    id: Uuid,
    slug: String,
    name: String,
    role: OrganizationRole,
}

pub(crate) fn valid_slug(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
}

pub(crate) fn valid_name(value: &str) -> bool {
    value.trim() == value && (1..=120).contains(&value.chars().count())
}

pub(crate) fn session_cookie(
    token: &str,
    secure: bool,
    max_age: std::time::Duration,
) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; HttpOnly{secure}; SameSite=Lax; Path=/; Max-Age={}",
        max_age.as_secs()
    ))
    .expect("generated session cookie is valid")
}

fn expired_cookie(secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}=; HttpOnly{secure}; SameSite=Lax; Path=/; Max-Age=0"
    ))
    .expect("generated expired cookie is valid")
}

pub(crate) async fn insert_identity_session(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    privileged_until: Option<chrono::DateTime<Utc>>,
    lifetime: std::time::Duration,
) -> Result<(Uuid, SessionToken), sqlx::Error> {
    insert_session_with_context(tx, user_id, None, privileged_until, lifetime).await
}

pub(crate) async fn insert_session_with_context(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    organization_id: Option<Uuid>,
    privileged_until: Option<chrono::DateTime<Utc>>,
    lifetime: std::time::Duration,
) -> Result<(Uuid, SessionToken), sqlx::Error> {
    let session_id = Uuid::new_v4();
    let token = SessionToken::generate();
    let expires_at =
        Utc::now() + Duration::from_std(lifetime).unwrap_or_else(|_| Duration::hours(12));
    SessionRepository::insert(
        &mut **tx,
        session_id,
        user_id,
        organization_id,
        token.digest().as_slice(),
        expires_at,
        privileged_until,
    )
    .await?;
    Ok((session_id, token))
}

struct ActionToken {
    plaintext: Zeroizing<String>,
    digest: [u8; 32],
}

fn generate_action(purpose: &str) -> ActionToken {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let plaintext = Zeroizing::new(format!(
        "oko_{purpose}_v1_{}",
        URL_SAFE_NO_PAD.encode(bytes)
    ));
    let digest = Sha256::digest(plaintext.as_bytes()).into();
    ActionToken { plaintext, digest }
}

fn action_digest(token: &str, purpose: &str) -> Option<[u8; 32]> {
    let encoded = token.strip_prefix(&format!("oko_{purpose}_v1_"))?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(bytes) != encoded {
        return None;
    }
    Some(Sha256::digest(token.as_bytes()).into())
}

fn action_url(config: &MailConfig, route: &str, token: &str) -> String {
    format!(
        "{}{route}#token={token}",
        config.public_web_url.as_str().trim_end_matches('/')
    )
}

struct ActionIssue<'a> {
    user_id: Uuid,
    email: &'a str,
    locale: Locale,
    purpose: &'a str,
    logical_key: String,
    ttl_minutes: i64,
}

async fn issue_action(
    tx: &mut Transaction<'_, Postgres>,
    config: &MailConfig,
    issue: ActionIssue<'_>,
    data: impl FnOnce(String) -> TemplateData,
) -> Result<(), crate::transactional_mail::MailError> {
    EmailActionRepository::revoke_pending(&mut **tx, issue.user_id, issue.purpose).await?;
    let action_id = Uuid::new_v4();
    let token = generate_action(issue.purpose);
    let expires_at = Utc::now() + Duration::minutes(issue.ttl_minutes);
    EmailActionRepository::insert(
        &mut **tx,
        action_id,
        issue.user_id,
        issue.purpose,
        token.digest.to_vec(),
        expires_at,
    )
    .await?;
    let route = if issue.purpose == "verify_email" {
        "/verify-email"
    } else {
        "/reset-password"
    };
    let payload = data(action_url(config, route, token.plaintext.as_str()));
    enqueue(
        tx,
        config,
        &issue.logical_key,
        &[(issue.email.to_owned(), issue.locale)],
        &payload,
        Some(action_id),
        Some(expires_at),
    )
    .await
}

async fn register(
    State(state): State<AuthState>,
    Extension(request_id): Extension<RequestId>,
    Json(mut input): Json<RegisterRequest>,
) -> Result<Response, AuthError> {
    if !state.public_signup_enabled || !state.mail.enabled {
        return Err(AuthError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::REGISTRATION_DISABLED,
            "registration is disabled",
            &request_id,
        ));
    }
    let email = normalize_email(&input.email)
        .map_err(|message| AuthError::validation(message, &request_id))?;
    let display_name = input.display_name.trim().to_owned();
    let organization_name = input.organization_name.trim().to_owned();
    input.display_name = display_name;
    input.organization_name = organization_name;
    validate_password(&input.password)
        .map_err(|message| AuthError::validation(message, &request_id))?;
    if !valid_slug(&input.organization_slug)
        || !valid_name(&input.organization_name)
        || !valid_name(&input.display_name)
    {
        return Err(AuthError::validation(
            "organization slug or name is invalid",
            &request_id,
        ));
    }
    let password_hash =
        hash_password(&input.password).map_err(|error| AuthError::internal(&error, &request_id))?;
    let user_id = Uuid::new_v4();
    let organization_id = Uuid::new_v4();
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let result = create_registration(
        &mut tx,
        &state.mail,
        &input,
        &email,
        &password_hash,
        user_id,
        organization_id,
    )
    .await;
    if let Err(error) = result {
        if let crate::transactional_mail::MailError::Database(error) = &error
            && error
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
        {
            return Err(AuthError::new(
                StatusCode::CONFLICT,
                ErrorCode::REGISTRATION_CONFLICT,
                "email or organization slug is unavailable",
                &request_id,
            ));
        }
        return Err(AuthError::internal(&error, &request_id));
    }
    tx.commit()
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    Ok((StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response())
}

#[allow(clippy::too_many_arguments)]
async fn create_registration(
    tx: &mut Transaction<'_, Postgres>,
    mail: &MailConfig,
    input: &RegisterRequest,
    email: &str,
    password_hash: &str,
    user_id: Uuid,
    organization_id: Uuid,
) -> Result<(), crate::transactional_mail::MailError> {
    UserRepository::insert_unverified(
        &mut **tx,
        user_id,
        email,
        password_hash,
        input.locale.as_str(),
        &input.display_name,
    )
    .await?;
    OrganizationRepository::insert(
        &mut **tx,
        organization_id,
        &input.organization_slug,
        &input.organization_name,
        OrganizationStatus::Active,
    )
    .await?;
    MembershipRepository::insert_organization_role(&mut **tx, organization_id, user_id, "owner")
        .await?;
    let organization_name = input.organization_name.clone();
    issue_action(
        tx,
        mail,
        ActionIssue {
            user_id,
            email,
            locale: input.locale,
            purpose: "verify_email",
            logical_key: format!("registration:{user_id}"),
            ttl_minutes: VERIFY_TTL_MINUTES,
        },
        |url| TemplateData::VerifyEmail {
            action_url: url,
            organization_name,
            expires_minutes: VERIFY_TTL_MINUTES,
        },
    )
    .await
}

async fn lookup_user(pool: &PgPool, email: &str) -> Result<Option<AuthenticatedUser>, sqlx::Error> {
    UserRepository::sign_in_by_email(pool, email).await
}

async fn login(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<LoginRequest>,
) -> Result<Response, AuthError> {
    let email = normalize_email(&input.email).unwrap_or_default();
    let found = lookup_user(&state.pool, &email)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let dummy_hash = hash_password("okoscope enumeration resistance")
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let password_ok = found
        .as_ref()
        .is_some_and(|user| verify_password(&input.password, &user.password_hash));
    if found.is_none() {
        let _ = verify_password(&input.password, &dummy_hash);
    }
    let Some(user) = found.filter(|user| password_ok && user.disabled_at.is_none()) else {
        crate::metrics::record_authentication(false);
        return Err(AuthError::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::INVALID_CREDENTIALS,
            "invalid email or password",
            &request_id,
        ));
    };
    if user.email_verified_at.is_none() {
        return Err(AuthError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::EMAIL_VERIFICATION_REQUIRED,
            "email verification is required",
            &request_id,
        ));
    }
    establish_session(&state, &headers, &request_id, user).await
}

async fn establish_session(
    state: &AuthState,
    headers: &HeaderMap,
    request_id: &RequestId,
    user: AuthenticatedUser,
) -> Result<Response, AuthError> {
    let role = user
        .role
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|()| {
            AuthError::new(
                StatusCode::UNAUTHORIZED,
                ErrorCode::INVALID_CREDENTIALS,
                "invalid email or password",
                request_id,
            )
        })?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AuthError::internal(&error, request_id))?;
    if let Some(old) = session_token(headers).and_then(session_digest) {
        SessionRepository::revoke_by_token_digest(&mut *tx, &old)
            .await
            .map_err(|error| AuthError::internal(&error, request_id))?;
    }
    let (_, token) = insert_session_with_context(
        &mut tx,
        user.user_id,
        user.organization_id,
        None,
        state.session_lifetime,
    )
    .await
    .map_err(|error| AuthError::internal(&error, request_id))?;
    tx.commit()
        .await
        .map_err(|error| AuthError::internal(&error, request_id))?;
    crate::metrics::record_authentication(true);
    let locale = user.preferred_locale.parse().unwrap_or(Locale::En);
    let response_body = response_from_user(&state.pool, &user, role, locale, None)
        .await
        .map_err(|error| AuthError::internal(&error, request_id))?;
    let mut response = Json(response_body).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(token.expose(), state.secure_cookie, state.session_lifetime),
    );
    Ok(response)
}

async fn response_from_user(
    pool: &PgPool,
    user: &AuthenticatedUser,
    role: Option<OrganizationRole>,
    locale: Locale,
    privileged_until: Option<chrono::DateTime<Utc>>,
) -> Result<AuthResponse, sqlx::Error> {
    let organizations: Vec<(Uuid, String, String, String)> =
        MembershipRepository::active_organizations_of(pool, user.user_id).await?;
    let organizations = organizations
        .into_iter()
        .filter_map(|(id, slug, name, value)| {
            Some(OrganizationResponse {
                id,
                slug,
                name,
                role: value.parse().ok()?,
            })
        })
        .collect::<Vec<_>>();
    let active_organization = user
        .organization_id
        .zip(user.organization_slug.clone())
        .zip(user.organization_name.clone())
        .zip(role)
        .map(|(((id, slug), name), role)| OrganizationResponse {
            id,
            slug,
            name,
            role,
        });
    Ok(AuthResponse {
        user: UserResponse {
            id: user.user_id,
            email: user.email.clone(),
            display_name: user.display_name.clone(),
            email_verified: user.email_verified_at.is_some(),
            preferred_locale: locale,
        },
        platform_role: user.is_super_admin.then_some("super_admin"),
        requires_organization_selection: organizations.len() > 1 && active_organization.is_none(),
        organizations,
        active_organization,
        active_role: role,
        privileged_until,
        capabilities: access_capabilities(user.is_super_admin, role),
    })
}

async fn resend_verification(
    State(state): State<AuthState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<EmailRequest>,
) -> Result<Response, AuthError> {
    issue_requested_action(&state, &request_id, input.email, "verify_email").await
}

async fn request_password_reset(
    State(state): State<AuthState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<EmailRequest>,
) -> Result<Response, AuthError> {
    issue_requested_action(&state, &request_id, input.email, "reset_password").await
}

async fn issue_requested_action(
    state: &AuthState,
    request_id: &RequestId,
    raw_email: String,
    purpose: &str,
) -> Result<Response, AuthError> {
    let email = normalize_email(&raw_email)
        .map_err(|message| AuthError::validation(message, request_id))?;
    if !state.mail.enabled {
        return Ok((StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response());
    }
    let Some(user) = lookup_user(&state.pool, &email)
        .await
        .map_err(|error| AuthError::internal(&error, request_id))?
    else {
        return Ok((StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response());
    };
    let eligible = user.disabled_at.is_none()
        && ((purpose == "verify_email" && user.email_verified_at.is_none())
            || (purpose == "reset_password" && user.email_verified_at.is_some()));
    if eligible {
        enqueue_requested_action(state, user, purpose)
            .await
            .map_err(|error| AuthError::internal(&error, request_id))?;
    }
    Ok((StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response())
}

async fn enqueue_requested_action(
    state: &AuthState,
    user: AuthenticatedUser,
    purpose: &str,
) -> Result<(), crate::transactional_mail::MailError> {
    let mut tx = state.pool.begin().await?;
    let locale = user.preferred_locale.parse().unwrap_or(Locale::En);
    UserRepository::lock(&mut *tx, user.user_id).await?;
    let cooling_down: bool = EmailActionRepository::cooling_down(
        &mut *tx,
        user.user_id,
        purpose,
        f64::from(ACTION_COOLDOWN_SECONDS),
    )
    .await?;
    if cooling_down {
        tx.commit().await?;
        return Ok(());
    }
    let logical = format!(
        "{purpose}:{}:{}",
        user.user_id,
        Utc::now().timestamp() / i64::from(ACTION_COOLDOWN_SECONDS)
    );
    if purpose == "verify_email" {
        let organization = user
            .organization_name
            .unwrap_or_else(|| "Okoscope".to_owned());
        issue_action(
            &mut tx,
            &state.mail,
            ActionIssue {
                user_id: user.user_id,
                email: &user.email,
                locale,
                purpose,
                logical_key: logical,
                ttl_minutes: VERIFY_TTL_MINUTES,
            },
            |url| TemplateData::VerifyEmail {
                action_url: url,
                organization_name: organization,
                expires_minutes: VERIFY_TTL_MINUTES,
            },
        )
        .await?;
    } else {
        issue_action(
            &mut tx,
            &state.mail,
            ActionIssue {
                user_id: user.user_id,
                email: &user.email,
                locale,
                purpose,
                logical_key: logical,
                ttl_minutes: RESET_TTL_MINUTES,
            },
            |url| TemplateData::ResetPassword {
                action_url: url,
                expires_minutes: RESET_TTL_MINUTES,
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn confirm_verification(
    State(state): State<AuthState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<ActionRequest>,
) -> Result<Response, AuthError> {
    let digest =
        action_digest(&input.token, "verify_email").ok_or_else(|| unusable_action(&request_id))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let user_id = consume_action(&mut tx, digest, "verify_email")
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?
        .ok_or_else(|| unusable_action(&request_id))?;
    UserRepository::mark_email_verified(&mut *tx, user_id)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    EmailActionRepository::revoke_pending_verifications(&mut *tx, user_id)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    tx.commit()
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn unusable_action(request_id: &RequestId) -> AuthError {
    AuthError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::ACTION_TOKEN_INVALID,
        "action token is invalid or expired",
        request_id,
    )
}

async fn consume_action(
    tx: &mut Transaction<'_, Postgres>,
    digest: [u8; 32],
    purpose: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    EmailActionRepository::consume(&mut **tx, digest.to_vec(), purpose).await
}

async fn complete_password_reset(
    State(state): State<AuthState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<ResetRequest>,
) -> Result<Response, AuthError> {
    validate_password(&input.new_password)
        .map_err(|message| AuthError::validation(message, &request_id))?;
    let digest = action_digest(&input.token, "reset_password")
        .ok_or_else(|| unusable_action(&request_id))?;
    let password_hash = hash_password(&input.new_password)
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let user_id = consume_action(&mut tx, digest, "reset_password")
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?
        .ok_or_else(|| unusable_action(&request_id))?;
    UserRepository::set_password_hash(&mut *tx, user_id, password_hash)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    revoke_security_state(&mut tx, user_id, None)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    enqueue_password_changed(&mut tx, &state.mail, user_id)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    tx.commit()
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn authenticate(
    state: &AuthState,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> Result<crate::auth::IdentityPrincipal, AuthError> {
    state
        .authenticator
        .authenticate_identity(session_token(headers).unwrap_or_default())
        .await
        .map_err(|error| AuthError::internal(&error, request_id))?
        .ok_or_else(|| {
            AuthError::new(
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "authentication required",
                request_id,
            )
        })
}

async fn change_password(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<ChangePasswordRequest>,
) -> Result<Response, AuthError> {
    validate_password(&input.new_password)
        .map_err(|message| AuthError::validation(message, &request_id))?;
    let principal = authenticate(&state, &headers, &request_id).await?;
    let user = lookup_user_by_id(
        &state.pool,
        principal.user_id,
        principal.active_organization_id,
    )
    .await
    .map_err(|error| AuthError::internal(&error, &request_id))?
    .ok_or_else(|| unusable_session(&request_id))?;
    if !verify_password(&input.current_password, &user.password_hash) {
        return Err(AuthError::new(
            StatusCode::BAD_REQUEST,
            ErrorCode::CURRENT_PASSWORD_INVALID,
            "current password is incorrect",
            &request_id,
        ));
    }
    let password_hash = hash_password(&input.new_password)
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    UserRepository::set_password_hash(&mut *tx, user.user_id, password_hash)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    revoke_security_state(&mut tx, user.user_id, Some(principal.session_id))
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    SessionRepository::revoke(&mut *tx, principal.session_id)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let (_, token) = insert_session_with_context(
        &mut tx,
        user.user_id,
        user.organization_id,
        None,
        state.session_lifetime,
    )
    .await
    .map_err(|error| AuthError::internal(&error, &request_id))?;
    enqueue_password_changed(&mut tx, &state.mail, user.user_id)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    tx.commit()
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let locale = user.preferred_locale.parse().unwrap_or(Locale::En);
    let role = user
        .role
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|()| unusable_session(&request_id))?;
    let body = response_from_user(&state.pool, &user, role, locale, None)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(token.expose(), state.secure_cookie, state.session_lifetime),
    );
    Ok(response)
}

async fn revoke_security_state(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    except_session: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    SessionRepository::revoke_all_for_user(&mut **tx, user_id, except_session).await?;
    EmailActionRepository::revoke_all_pending(&mut **tx, user_id).await?;
    Ok(())
}

async fn enqueue_password_changed(
    tx: &mut Transaction<'_, Postgres>,
    mail: &MailConfig,
    user_id: Uuid,
) -> Result<(), crate::transactional_mail::MailError> {
    let row: Option<(String, String)> =
        UserRepository::email_and_locale(&mut **tx, user_id).await?;
    if let Some((email, locale)) = row {
        enqueue(
            tx,
            mail,
            &format!("password-changed:{user_id}:{}", Utc::now().timestamp()),
            &[(email, locale.parse().unwrap_or(Locale::En))],
            &TemplateData::PasswordChanged,
            None,
            None,
        )
        .await?;
    }
    Ok(())
}

async fn update_preferences(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(mut input): Json<PreferencesRequest>,
) -> Result<Json<AuthResponse>, AuthError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    input.display_name = input.display_name.map(|name| name.trim().to_owned());
    if input
        .display_name
        .as_deref()
        .is_some_and(|name| !valid_name(name))
    {
        return Err(AuthError::validation(
            "display name must contain 1-120 characters",
            &request_id,
        ));
    }
    UserRepository::update_preferences(
        &state.pool,
        principal.user_id,
        input.locale.as_str(),
        input.display_name,
    )
    .await
    .map_err(|error| AuthError::internal(&error, &request_id))?;
    let user = lookup_user_by_id(
        &state.pool,
        principal.user_id,
        principal.active_organization_id,
    )
    .await
    .map_err(|error| AuthError::internal(&error, &request_id))?
    .ok_or_else(|| unusable_session(&request_id))?;
    response_from_user(
        &state.pool,
        &user,
        principal.organization_role,
        input.locale,
        principal.privileged_until,
    )
    .await
    .map(Json)
    .map_err(|error| AuthError::internal(&error, &request_id))
}

async fn lookup_user_by_id(
    pool: &PgPool,
    user_id: Uuid,
    organization_id: Option<Uuid>,
) -> Result<Option<AuthenticatedUser>, sqlx::Error> {
    UserRepository::sign_in_by_id(pool, user_id, organization_id).await
}

fn unusable_session(request_id: &RequestId) -> AuthError {
    AuthError::new(
        StatusCode::UNAUTHORIZED,
        ErrorCode::UNAUTHORIZED,
        "authentication required",
        request_id,
    )
}

async fn me(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<AuthResponse>, AuthError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    let user = lookup_user_by_id(
        &state.pool,
        principal.user_id,
        principal.active_organization_id,
    )
    .await
    .map_err(|error| AuthError::internal(&error, &request_id))?
    .ok_or_else(|| unusable_session(&request_id))?;
    let locale = user.preferred_locale.parse().unwrap_or(Locale::En);
    response_from_user(
        &state.pool,
        &user,
        principal.organization_role,
        locale,
        principal.privileged_until,
    )
    .await
    .map(Json)
    .map_err(|error| AuthError::internal(&error, &request_id))
}

async fn logout(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Response, AuthError> {
    if let Some(digest) = session_token(&headers).and_then(session_digest) {
        SessionRepository::revoke_by_token_digest(&state.pool, &digest)
            .await
            .map_err(|error| AuthError::internal(&error, &request_id))?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, expired_cookie(state.secure_cookie));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_tokens_are_canonical_purpose_scoped_and_redacted() {
        let token = generate_action("verify_email");
        assert_eq!(
            action_digest(token.plaintext.as_str(), "verify_email"),
            Some(token.digest)
        );
        assert!(action_digest(token.plaintext.as_str(), "reset_password").is_none());
    }

    #[test]
    fn production_and_development_cookie_attributes_are_explicit() {
        assert!(
            session_cookie("opaque", true, std::time::Duration::from_secs(600))
                .to_str()
                .unwrap()
                .contains("Secure")
        );
        assert!(
            !session_cookie("opaque", false, std::time::Duration::from_secs(600))
                .to_str()
                .unwrap()
                .contains("Secure")
        );
        assert!(expired_cookie(true).to_str().unwrap().contains("Max-Age=0"));
    }
}
