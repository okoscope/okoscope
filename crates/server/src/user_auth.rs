use axum::{
    Extension, Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::error_code::ErrorCode;
use crate::service::accounts::{
    AccountService, AccountServiceError, AuthResponse, EmailAction, Registration, SignedIn,
};
use crate::{
    auth::{IdentityPrincipal, SESSION_COOKIE, UserSessionAuthenticator, session_token},
    transactional_mail::Locale,
    web_api::{RequestId, WebApiConfig},
};

#[derive(Clone, Debug)]
struct AuthState {
    service: AccountService,
    authenticator: UserSessionAuthenticator,
    secure_cookie: bool,
    session_lifetime: std::time::Duration,
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
            service: AccountService::new(pool.clone(), config),
            authenticator: UserSessionAuthenticator::new(pool),
            secure_cookie: config.secure_session_cookie,
            session_lifetime: config.session_lifetime,
        })
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
    fn internal(_error: &impl std::fmt::Display, request_id: &RequestId) -> Self {
        tracing::error!(request_id=%request_id.0, "user authentication operation failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::INTERNAL_ERROR,
            "internal server error",
            request_id,
        )
    }

    /// The response for a failed account use case.
    fn from_service(error: AccountServiceError, request_id: &RequestId) -> Self {
        let (status, code, message) = match error {
            AccountServiceError::RegistrationDisabled => (
                StatusCode::NOT_FOUND,
                ErrorCode::REGISTRATION_DISABLED,
                "registration is disabled",
            ),
            AccountServiceError::Invalid(message) => (
                StatusCode::BAD_REQUEST,
                ErrorCode::VALIDATION_FAILED,
                message,
            ),
            AccountServiceError::RegistrationConflict => (
                StatusCode::CONFLICT,
                ErrorCode::REGISTRATION_CONFLICT,
                "email or organization slug is unavailable",
            ),
            AccountServiceError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::INVALID_CREDENTIALS,
                "invalid email or password",
            ),
            AccountServiceError::EmailVerificationRequired => (
                StatusCode::FORBIDDEN,
                ErrorCode::EMAIL_VERIFICATION_REQUIRED,
                "email verification is required",
            ),
            AccountServiceError::ActionTokenInvalid => (
                StatusCode::BAD_REQUEST,
                ErrorCode::ACTION_TOKEN_INVALID,
                "action token is invalid or expired",
            ),
            AccountServiceError::SessionUnusable => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "authentication required",
            ),
            AccountServiceError::CurrentPasswordInvalid => (
                StatusCode::BAD_REQUEST,
                ErrorCode::CURRENT_PASSWORD_INVALID,
                "current password is incorrect",
            ),
            error @ (AccountServiceError::PasswordHashing
            | AccountServiceError::Mail(_)
            | AccountServiceError::Database(_)) => return Self::internal(&error, request_id),
        };
        Self::new(status, code, message, request_id)
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

/// Maps a service error onto this request's response.
fn failed(request_id: &RequestId) -> impl Fn(AccountServiceError) -> AuthError + '_ {
    move |error| AuthError::from_service(error, request_id)
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

fn accepted() -> Response {
    (StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response()
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

fn signed_in(state: &AuthState, signed_in: SignedIn) -> Response {
    let mut response = Json(signed_in.user).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(
            signed_in.session.expose(),
            state.secure_cookie,
            state.session_lifetime,
        ),
    );
    response
}

async fn authenticate(
    state: &AuthState,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> Result<IdentityPrincipal, AuthError> {
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

async fn register(
    State(state): State<AuthState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<RegisterRequest>,
) -> Result<Response, AuthError> {
    state
        .service
        .register(Registration {
            email: input.email,
            password: input.password,
            display_name: input.display_name,
            organization_slug: input.organization_slug,
            organization_name: input.organization_name,
            locale: input.locale,
        })
        .await
        .map_err(failed(&request_id))?;
    Ok(accepted())
}

async fn login(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<LoginRequest>,
) -> Result<Response, AuthError> {
    let session = state
        .service
        .login(&input.email, &input.password, session_token(&headers))
        .await
        .map_err(failed(&request_id))?;
    Ok(signed_in(&state, session))
}

async fn resend_verification(
    State(state): State<AuthState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<EmailRequest>,
) -> Result<Response, AuthError> {
    state
        .service
        .request_email_action(&input.email, EmailAction::VerifyEmail)
        .await
        .map_err(failed(&request_id))?;
    Ok(accepted())
}

async fn request_password_reset(
    State(state): State<AuthState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<EmailRequest>,
) -> Result<Response, AuthError> {
    state
        .service
        .request_email_action(&input.email, EmailAction::ResetPassword)
        .await
        .map_err(failed(&request_id))?;
    Ok(accepted())
}

async fn confirm_verification(
    State(state): State<AuthState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<ActionRequest>,
) -> Result<Response, AuthError> {
    state
        .service
        .confirm_verification(&input.token)
        .await
        .map_err(failed(&request_id))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn complete_password_reset(
    State(state): State<AuthState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<ResetRequest>,
) -> Result<Response, AuthError> {
    state
        .service
        .complete_password_reset(&input.token, &input.new_password)
        .await
        .map_err(failed(&request_id))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn change_password(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<ChangePasswordRequest>,
) -> Result<Response, AuthError> {
    // An invalid new password is reported before authentication.
    state
        .service
        .validate_new_password(&input.new_password)
        .map_err(failed(&request_id))?;
    let principal = authenticate(&state, &headers, &request_id).await?;
    let session = state
        .service
        .change_password(principal, &input.current_password, &input.new_password)
        .await
        .map_err(failed(&request_id))?;
    Ok(signed_in(&state, session))
}

async fn update_preferences(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<PreferencesRequest>,
) -> Result<Json<AuthResponse>, AuthError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    state
        .service
        .update_preferences(principal, input.locale, input.display_name)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn me(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<AuthResponse>, AuthError> {
    let principal = authenticate(&state, &headers, &request_id).await?;
    state
        .service
        .me(principal)
        .await
        .map(Json)
        .map_err(failed(&request_id))
}

async fn logout(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Response, AuthError> {
    state
        .service
        .logout(session_token(&headers))
        .await
        .map_err(failed(&request_id))?;
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
