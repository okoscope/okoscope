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
    registration_enabled: bool,
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
            registration_enabled: config.registration_enabled,
            secure_cookie: config.secure_session_cookie,
            session_lifetime: config.session_lifetime,
            mail: config.mail.clone(),
        })
}

pub async fn bootstrap_owner(
    pool: &PgPool,
    organization_id: Uuid,
    email: &str,
    password: &str,
) -> anyhow::Result<()> {
    let email = normalize_email(email).map_err(anyhow::Error::msg)?;
    validate_password(password).map_err(anyhow::Error::msg)?;
    let password_hash =
        hash_password(password).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut tx = pool.begin().await?;
    let existing_owner: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE organization_id=$1 AND role='owner')")
        .bind(organization_id).fetch_one(&mut *tx).await?;
    if existing_owner {
        tx.commit().await?;
        return Ok(());
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)")
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await?;
    anyhow::ensure!(exists, "organization does not exist");
    let user_id: Uuid = sqlx::query_scalar("INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,$3,now()) ON CONFLICT(email) DO UPDATE SET email_verified_at=coalesce(users.email_verified_at,now()) RETURNING id")
        .bind(Uuid::new_v4()).bind(email).bind(password_hash).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'owner') ON CONFLICT(organization_id,user_id) DO UPDATE SET role='owner'")
        .bind(organization_id).bind(user_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn verify_user_access(
    pool: &PgPool,
    registration_enabled: bool,
    setup_enabled: bool,
) -> anyhow::Result<()> {
    let owner_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM organization_memberships WHERE role='owner'")
            .fetch_one(pool)
            .await?;
    anyhow::ensure!(
        registration_enabled || setup_enabled || owner_count > 0,
        "no Organization owner exists; configure setup authorization, run bootstrap-owner, or explicitly enable registration"
    );
    Ok(())
}

#[derive(Debug)]
struct AuthError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    request_id: RequestId,
}

impl AuthError {
    fn new(
        status: StatusCode,
        code: &'static str,
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
            "validation_failed",
            message,
            request_id,
        )
    }
    fn internal(error: &impl std::fmt::Display, request_id: &RequestId) -> Self {
        tracing::error!(%error, request_id=%request_id.0, "user authentication operation failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "internal server error",
            request_id,
        )
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body {
            error: &'static str,
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
}

#[derive(Debug, Serialize)]
struct Accepted {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    user: UserResponse,
    organization: OrganizationResponse,
    role: OrganizationRole,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    id: Uuid,
    email: String,
    email_verified: bool,
    preferred_locale: Locale,
}

#[derive(Debug, Serialize)]
struct OrganizationResponse {
    id: Uuid,
    slug: String,
    name: String,
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

pub(crate) async fn insert_session(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    organization_id: Uuid,
    lifetime: std::time::Duration,
) -> Result<(Uuid, SessionToken), sqlx::Error> {
    let session_id = Uuid::new_v4();
    let token = SessionToken::generate();
    let expires_at =
        Utc::now() + Duration::from_std(lifetime).unwrap_or_else(|_| Duration::hours(12));
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)")
        .bind(session_id).bind(user_id).bind(organization_id).bind(token.digest().to_vec())
        .bind(expires_at).execute(&mut **tx).await?;
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
    sqlx::query("UPDATE user_email_actions SET revoked_at=now() WHERE user_id=$1 AND purpose=$2 AND consumed_at IS NULL AND revoked_at IS NULL")
        .bind(issue.user_id).bind(issue.purpose).execute(&mut **tx).await?;
    let action_id = Uuid::new_v4();
    let token = generate_action(issue.purpose);
    let expires_at = Utc::now() + Duration::minutes(issue.ttl_minutes);
    sqlx::query("INSERT INTO user_email_actions(id,user_id,purpose,token_digest,expires_at) VALUES($1,$2,$3,$4,$5)")
        .bind(action_id).bind(issue.user_id).bind(issue.purpose).bind(token.digest.to_vec()).bind(expires_at)
        .execute(&mut **tx).await?;
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
    Json(input): Json<RegisterRequest>,
) -> Result<Response, AuthError> {
    if !state.registration_enabled || !state.mail.enabled {
        return Err(AuthError::new(
            StatusCode::NOT_FOUND,
            "registration_disabled",
            "registration is disabled",
            &request_id,
        ));
    }
    let email = normalize_email(&input.email)
        .map_err(|message| AuthError::validation(message, &request_id))?;
    validate_password(&input.password)
        .map_err(|message| AuthError::validation(message, &request_id))?;
    if !valid_slug(&input.organization_slug) || !valid_name(&input.organization_name) {
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
                "registration_conflict",
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
    sqlx::query("INSERT INTO users(id,email,password_hash,email_verified_at,preferred_locale) VALUES($1,$2,$3,NULL,$4)")
        .bind(user_id).bind(email).bind(password_hash).bind(input.locale.as_str()).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,$3)")
        .bind(organization_id)
        .bind(&input.organization_slug)
        .bind(&input.organization_name)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'owner')",
    )
    .bind(organization_id)
    .bind(user_id)
    .execute(&mut **tx)
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
    sqlx::query_as("SELECT u.id user_id,u.email,u.password_hash,m.organization_id,o.slug organization_slug,o.name organization_name,m.role,u.disabled_at,u.email_verified_at,u.preferred_locale FROM users u JOIN organization_memberships m ON m.user_id=u.id JOIN organizations o ON o.id=m.organization_id WHERE u.email=$1 ORDER BY m.created_at,m.organization_id LIMIT 1")
        .bind(email).fetch_optional(pool).await
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
            "invalid_credentials",
            "invalid email or password",
            &request_id,
        ));
    };
    if user.email_verified_at.is_none() {
        return Err(AuthError::new(
            StatusCode::FORBIDDEN,
            "email_verification_required",
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
    let role = user.role.parse().map_err(|()| {
        AuthError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
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
        sqlx::query(
            "UPDATE user_sessions SET revoked_at=coalesce(revoked_at,now()) WHERE token_hash=$1",
        )
        .bind(old.to_vec())
        .execute(&mut *tx)
        .await
        .map_err(|error| AuthError::internal(&error, request_id))?;
    }
    let (_, token) = insert_session(
        &mut tx,
        user.user_id,
        user.organization_id,
        state.session_lifetime,
    )
    .await
    .map_err(|error| AuthError::internal(&error, request_id))?;
    tx.commit()
        .await
        .map_err(|error| AuthError::internal(&error, request_id))?;
    crate::metrics::record_authentication(true);
    let locale = user.preferred_locale.parse().unwrap_or(Locale::En);
    let mut response = Json(response_from_user(&user, role, locale)).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(token.expose(), state.secure_cookie, state.session_lifetime),
    );
    Ok(response)
}

fn response_from_user(
    user: &AuthenticatedUser,
    role: OrganizationRole,
    locale: Locale,
) -> AuthResponse {
    AuthResponse {
        user: UserResponse {
            id: user.user_id,
            email: user.email.clone(),
            email_verified: user.email_verified_at.is_some(),
            preferred_locale: locale,
        },
        organization: OrganizationResponse {
            id: user.organization_id,
            slug: user.organization_slug.clone(),
            name: user.organization_name.clone(),
        },
        role,
    }
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
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user.user_id)
        .execute(&mut *tx)
        .await?;
    let cooling_down: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_email_actions WHERE user_id=$1 AND purpose=$2 AND created_at>now()-make_interval(secs=>$3))")
        .bind(user.user_id).bind(purpose).bind(f64::from(ACTION_COOLDOWN_SECONDS))
        .fetch_one(&mut *tx).await?;
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
        let organization = user.organization_name;
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
    sqlx::query("UPDATE users SET email_verified_at=coalesce(email_verified_at,now()),updated_at=now() WHERE id=$1")
        .bind(user_id).execute(&mut *tx).await.map_err(|error| AuthError::internal(&error, &request_id))?;
    sqlx::query("UPDATE user_email_actions SET revoked_at=now() WHERE user_id=$1 AND purpose='verify_email' AND consumed_at IS NULL AND revoked_at IS NULL")
        .bind(user_id).execute(&mut *tx).await.map_err(|error| AuthError::internal(&error, &request_id))?;
    tx.commit()
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn unusable_action(request_id: &RequestId) -> AuthError {
    AuthError::new(
        StatusCode::BAD_REQUEST,
        "action_token_invalid",
        "action token is invalid or expired",
        request_id,
    )
}

async fn consume_action(
    tx: &mut Transaction<'_, Postgres>,
    digest: [u8; 32],
    purpose: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar("UPDATE user_email_actions SET consumed_at=now() WHERE id=(SELECT id FROM user_email_actions WHERE token_digest=$1 AND purpose=$2 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE) RETURNING user_id")
        .bind(digest.to_vec()).bind(purpose).fetch_optional(&mut **tx).await
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
    sqlx::query("UPDATE users SET password_hash=$2,updated_at=now() WHERE id=$1")
        .bind(user_id)
        .bind(password_hash)
        .execute(&mut *tx)
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
) -> Result<crate::auth::UserPrincipal, AuthError> {
    state
        .authenticator
        .authenticate(session_token(headers).unwrap_or_default())
        .await
        .map_err(|error| AuthError::internal(&error, request_id))?
        .ok_or_else(|| {
            AuthError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
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
    let user = lookup_user_by_id(&state.pool, principal.user_id, principal.organization_id)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?
        .ok_or_else(|| unusable_session(&request_id))?;
    if !verify_password(&input.current_password, &user.password_hash) {
        return Err(AuthError::new(
            StatusCode::BAD_REQUEST,
            "current_password_invalid",
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
    sqlx::query("UPDATE users SET password_hash=$2,updated_at=now() WHERE id=$1")
        .bind(user.user_id)
        .bind(password_hash)
        .execute(&mut *tx)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    revoke_security_state(&mut tx, user.user_id, Some(principal.session_id))
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    sqlx::query("UPDATE user_sessions SET revoked_at=now() WHERE id=$1")
        .bind(principal.session_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let (_, token) = insert_session(
        &mut tx,
        user.user_id,
        user.organization_id,
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
        .parse()
        .map_err(|()| unusable_session(&request_id))?;
    let mut response = Json(response_from_user(&user, role, locale)).into_response();
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
    sqlx::query("UPDATE user_sessions SET revoked_at=coalesce(revoked_at,now()) WHERE user_id=$1 AND ($2::uuid IS NULL OR id<>$2)")
        .bind(user_id).bind(except_session).execute(&mut **tx).await?;
    sqlx::query("UPDATE user_email_actions SET revoked_at=coalesce(revoked_at,now()) WHERE user_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL")
        .bind(user_id).execute(&mut **tx).await?;
    Ok(())
}

async fn enqueue_password_changed(
    tx: &mut Transaction<'_, Postgres>,
    mail: &MailConfig,
    user_id: Uuid,
) -> Result<(), crate::transactional_mail::MailError> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT email,preferred_locale FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await?;
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
    Json(input): Json<PreferencesRequest>,
) -> Result<Json<AuthResponse>, AuthError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    sqlx::query("UPDATE users SET preferred_locale=$2,updated_at=now() WHERE id=$1")
        .bind(principal.user_id)
        .bind(input.locale.as_str())
        .execute(&state.pool)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?;
    let user = lookup_user_by_id(&state.pool, principal.user_id, principal.organization_id)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?
        .ok_or_else(|| unusable_session(&request_id))?;
    Ok(Json(response_from_user(
        &user,
        principal.role,
        input.locale,
    )))
}

async fn lookup_user_by_id(
    pool: &PgPool,
    user_id: Uuid,
    organization_id: Uuid,
) -> Result<Option<AuthenticatedUser>, sqlx::Error> {
    sqlx::query_as("SELECT u.id user_id,u.email,u.password_hash,m.organization_id,o.slug organization_slug,o.name organization_name,m.role,u.disabled_at,u.email_verified_at,u.preferred_locale FROM users u JOIN organization_memberships m ON m.user_id=u.id AND m.organization_id=$2 JOIN organizations o ON o.id=m.organization_id WHERE u.id=$1")
        .bind(user_id).bind(organization_id).fetch_optional(pool).await
}

fn unusable_session(request_id: &RequestId) -> AuthError {
    AuthError::new(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
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
    let user = lookup_user_by_id(&state.pool, principal.user_id, principal.organization_id)
        .await
        .map_err(|error| AuthError::internal(&error, &request_id))?
        .ok_or_else(|| unusable_session(&request_id))?;
    let locale = user.preferred_locale.parse().unwrap_or(Locale::En);
    Ok(Json(response_from_user(&user, principal.role, locale)))
}

async fn logout(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Response, AuthError> {
    if let Some(digest) = session_token(&headers).and_then(session_digest) {
        sqlx::query(
            "UPDATE user_sessions SET revoked_at=coalesce(revoked_at,now()) WHERE token_hash=$1",
        )
        .bind(digest.to_vec())
        .execute(&state.pool)
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
