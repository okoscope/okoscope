//! User accounts: self-service registration, signing in and out, email
//! verification, password reset and change, and the user's own preferences.
//! Also the operator's recovery of a super administrator.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::access_audit::{AccessAuditActor, AccessAuditEvent, write_access_audit};
use crate::auth::{
    AuthenticatedUser, IdentityPrincipal, OrganizationRole, SessionToken, hash_password,
    normalize_email, session_digest, validate_password, verify_password,
};
use crate::repository::email_actions::EmailActionRepository;
use crate::repository::{
    MembershipRepository, OrganizationRepository, OrganizationStatus, SessionRepository,
    UserRepository,
};
use crate::service::identity::{insert_session_with_context, valid_name, valid_slug};
use crate::transactional_mail::{Locale, MailConfig, MailError, TemplateData, enqueue};
use crate::web_api::WebApiConfig;

const VERIFY_TTL_MINUTES: i64 = 24 * 60;
const RESET_TTL_MINUTES: i64 = 30;
const ACTION_COOLDOWN_SECONDS: i32 = 60;

/// Why an account use case failed.
#[derive(Debug, Error)]
pub enum AccountServiceError {
    /// Self-service registration is off, or mail is not configured.
    #[error("registration is disabled")]
    RegistrationDisabled,
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(&'static str),
    /// The email or the organization slug is already taken.
    #[error("email or organization slug is unavailable")]
    RegistrationConflict,
    /// The email and password do not name an enabled account.
    #[error("invalid email or password")]
    InvalidCredentials,
    /// The account exists but its email is not verified yet.
    #[error("email verification is required")]
    EmailVerificationRequired,
    /// The email action token is malformed, used or expired.
    #[error("action token is invalid or expired")]
    ActionTokenInvalid,
    /// The session no longer names a usable account.
    #[error("authentication required")]
    SessionUnusable,
    /// The current password given to change it is wrong.
    #[error("current password is incorrect")]
    CurrentPasswordInvalid,
    #[error("password hashing failed")]
    PasswordHashing,
    #[error("mail intent failed: {0}")]
    Mail(MailError),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

type Result<T, E = AccountServiceError> = std::result::Result<T, E>;

/// A self-service registration: the first user and their organization.
#[derive(Clone, Debug)]
pub struct Registration {
    pub email: String,
    pub password: String,
    pub display_name: String,
    pub organization_slug: String,
    pub organization_name: String,
    pub locale: Locale,
}

/// The signed-in user as the web UI sees them.
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    user: UserResponse,
    platform_role: Option<&'static str>,
    organizations: Vec<OrganizationResponse>,
    active_organization: Option<OrganizationResponse>,
    active_role: Option<OrganizationRole>,
    requires_organization_selection: bool,
    privileged_until: Option<chrono::DateTime<Utc>>,
    capabilities: serde_json::Value,
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

/// A use case that opened a new session: the signed-in user and the token of
/// the session.
#[derive(Debug)]
pub struct SignedIn {
    pub user: AuthResponse,
    pub session: SessionToken,
}

/// What an email action token is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailAction {
    VerifyEmail,
    ResetPassword,
}

impl EmailAction {
    fn purpose(self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email",
            Self::ResetPassword => "reset_password",
        }
    }
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

#[derive(Clone, Debug)]
pub struct AccountService {
    pool: PgPool,
    public_signup_enabled: bool,
    session_lifetime: std::time::Duration,
    mail: MailConfig,
}

impl AccountService {
    pub fn new(pool: PgPool, config: &WebApiConfig) -> Self {
        Self {
            pool,
            public_signup_enabled: config.public_signup_enabled,
            session_lifetime: config.session_lifetime,
            mail: config.mail.clone(),
        }
    }

    /// Creates an unverified user who owns a new organization, and mails them
    /// a verification link. Only when public signup and mail are both on.
    pub async fn register(&self, mut input: Registration) -> Result<()> {
        if !self.public_signup_enabled || !self.mail.enabled {
            return Err(AccountServiceError::RegistrationDisabled);
        }
        let email = normalize_email(&input.email).map_err(AccountServiceError::Invalid)?;
        let display_name = input.display_name.trim().to_owned();
        let organization_name = input.organization_name.trim().to_owned();
        input.display_name = display_name;
        input.organization_name = organization_name;
        validate_password(&input.password).map_err(AccountServiceError::Invalid)?;
        if !valid_slug(&input.organization_slug)
            || !valid_name(&input.organization_name)
            || !valid_name(&input.display_name)
        {
            return Err(AccountServiceError::Invalid(
                "organization slug or name is invalid",
            ));
        }
        let password_hash =
            hash_password(&input.password).map_err(|_| AccountServiceError::PasswordHashing)?;
        let user_id = Uuid::new_v4();
        let organization_id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;
        let result = create_registration(
            &mut tx,
            &self.mail,
            &input,
            &email,
            &password_hash,
            user_id,
            organization_id,
        )
        .await;
        if let Err(error) = result {
            if let MailError::Database(error) = &error
                && error
                    .as_database_error()
                    .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
            {
                return Err(AccountServiceError::RegistrationConflict);
            }
            return Err(AccountServiceError::Mail(error));
        }
        tx.commit().await?;
        Ok(())
    }

    /// Signs a user in with their password and opens a session in their
    /// default organization, replacing the session the browser presented.
    /// Unknown emails cost the same password verification as known ones.
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        previous_session: Option<&str>,
    ) -> Result<SignedIn> {
        let email = normalize_email(email).unwrap_or_default();
        let found: Option<AuthenticatedUser> =
            UserRepository::sign_in_by_email(&self.pool, &email).await?;
        let dummy_hash = hash_password("okoscope enumeration resistance")
            .map_err(|_| AccountServiceError::PasswordHashing)?;
        let password_ok = found
            .as_ref()
            .is_some_and(|user| verify_password(password, &user.password_hash));
        if found.is_none() {
            let _ = verify_password(password, &dummy_hash);
        }
        let Some(user) = found.filter(|user| password_ok && user.disabled_at.is_none()) else {
            crate::metrics::record_authentication(false);
            return Err(AccountServiceError::InvalidCredentials);
        };
        if user.email_verified_at.is_none() {
            return Err(AccountServiceError::EmailVerificationRequired);
        }
        let role = user
            .role
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|()| AccountServiceError::InvalidCredentials)?;
        let mut tx = self.pool.begin().await?;
        if let Some(old) = previous_session.and_then(session_digest) {
            SessionRepository::revoke_by_token_digest(&mut *tx, &old).await?;
        }
        let (_, session) = insert_session_with_context(
            &mut tx,
            user.user_id,
            user.organization_id,
            None,
            self.session_lifetime,
        )
        .await?;
        tx.commit().await?;
        crate::metrics::record_authentication(true);
        let locale = user.preferred_locale.parse().unwrap_or(Locale::En);
        let user = self.response_from_user(&user, role, locale, None).await?;
        Ok(SignedIn { user, session })
    }

    /// Revokes the presented session, if it is well formed.
    pub async fn logout(&self, session: Option<&str>) -> Result<()> {
        if let Some(digest) = session.and_then(session_digest) {
            SessionRepository::revoke_by_token_digest(&self.pool, &digest).await?;
        }
        Ok(())
    }

    /// The signed-in user.
    pub async fn me(&self, principal: IdentityPrincipal) -> Result<AuthResponse> {
        let user = self.user_of(principal).await?;
        let locale = user.preferred_locale.parse().unwrap_or(Locale::En);
        Ok(self
            .response_from_user(
                &user,
                principal.organization_role,
                locale,
                principal.privileged_until,
            )
            .await?)
    }

    /// Mails a fresh verification or reset link when the account is eligible
    /// for it. The answer never says whether the email is known, and repeated
    /// requests within a minute send nothing new.
    pub async fn request_email_action(&self, email: &str, action: EmailAction) -> Result<()> {
        let email = normalize_email(email).map_err(AccountServiceError::Invalid)?;
        if !self.mail.enabled {
            return Ok(());
        }
        let user: Option<AuthenticatedUser> =
            UserRepository::sign_in_by_email(&self.pool, &email).await?;
        let Some(user) = user else {
            return Ok(());
        };
        let eligible = user.disabled_at.is_none()
            && ((action == EmailAction::VerifyEmail && user.email_verified_at.is_none())
                || (action == EmailAction::ResetPassword && user.email_verified_at.is_some()));
        if eligible {
            self.enqueue_requested_action(user, action.purpose())
                .await
                .map_err(AccountServiceError::Mail)?;
        }
        Ok(())
    }

    /// Marks the account's email verified with the token from the mail.
    pub async fn confirm_verification(&self, token: &str) -> Result<()> {
        let digest =
            action_digest(token, "verify_email").ok_or(AccountServiceError::ActionTokenInvalid)?;
        let mut tx = self.pool.begin().await?;
        let user_id = EmailActionRepository::consume(&mut *tx, digest.to_vec(), "verify_email")
            .await?
            .ok_or(AccountServiceError::ActionTokenInvalid)?;
        UserRepository::mark_email_verified(&mut *tx, user_id).await?;
        EmailActionRepository::revoke_pending_verifications(&mut *tx, user_id).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Sets a new password with the token from the reset mail. Every session
    /// and pending email action of the user ends.
    pub async fn complete_password_reset(&self, token: &str, new_password: &str) -> Result<()> {
        self.validate_new_password(new_password)?;
        let digest = action_digest(token, "reset_password")
            .ok_or(AccountServiceError::ActionTokenInvalid)?;
        let password_hash =
            hash_password(new_password).map_err(|_| AccountServiceError::PasswordHashing)?;
        let mut tx = self.pool.begin().await?;
        let user_id = EmailActionRepository::consume(&mut *tx, digest.to_vec(), "reset_password")
            .await?
            .ok_or(AccountServiceError::ActionTokenInvalid)?;
        UserRepository::set_password_hash(&mut *tx, user_id, password_hash).await?;
        revoke_security_state(&mut tx, user_id, None).await?;
        enqueue_password_changed(&mut tx, &self.mail, user_id)
            .await
            .map_err(AccountServiceError::Mail)?;
        tx.commit().await?;
        Ok(())
    }

    /// Checks a new password's shape. Changing the password reports this
    /// before authentication, so the transport calls it first.
    pub fn validate_new_password(&self, new_password: &str) -> Result<()> {
        validate_password(new_password).map_err(AccountServiceError::Invalid)
    }

    /// Changes the signed-in user's password. Every other session and pending
    /// email action ends, and the current session is replaced by a new one.
    pub async fn change_password(
        &self,
        principal: IdentityPrincipal,
        current_password: &str,
        new_password: &str,
    ) -> Result<SignedIn> {
        self.validate_new_password(new_password)?;
        let user = self.user_of(principal).await?;
        if !verify_password(current_password, &user.password_hash) {
            return Err(AccountServiceError::CurrentPasswordInvalid);
        }
        let password_hash =
            hash_password(new_password).map_err(|_| AccountServiceError::PasswordHashing)?;
        let mut tx = self.pool.begin().await?;
        UserRepository::set_password_hash(&mut *tx, user.user_id, password_hash).await?;
        revoke_security_state(&mut tx, user.user_id, Some(principal.session_id)).await?;
        SessionRepository::revoke(&mut *tx, principal.session_id).await?;
        let (_, session) = insert_session_with_context(
            &mut tx,
            user.user_id,
            user.organization_id,
            None,
            self.session_lifetime,
        )
        .await?;
        enqueue_password_changed(&mut tx, &self.mail, user.user_id)
            .await
            .map_err(AccountServiceError::Mail)?;
        tx.commit().await?;
        let locale = user.preferred_locale.parse().unwrap_or(Locale::En);
        let role = user
            .role
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|()| AccountServiceError::SessionUnusable)?;
        let user = self.response_from_user(&user, role, locale, None).await?;
        Ok(SignedIn { user, session })
    }

    /// Updates the signed-in user's locale and, when given, display name.
    pub async fn update_preferences(
        &self,
        principal: IdentityPrincipal,
        locale: Locale,
        display_name: Option<String>,
    ) -> Result<AuthResponse> {
        let display_name = display_name.map(|name| name.trim().to_owned());
        if display_name
            .as_deref()
            .is_some_and(|name| !valid_name(name))
        {
            return Err(AccountServiceError::Invalid(
                "display name must contain 1-120 characters",
            ));
        }
        UserRepository::update_preferences(
            &self.pool,
            principal.user_id,
            locale.as_str(),
            display_name,
        )
        .await?;
        let user = self.user_of(principal).await?;
        Ok(self
            .response_from_user(
                &user,
                principal.organization_role,
                locale,
                principal.privileged_until,
            )
            .await?)
    }

    async fn user_of(&self, principal: IdentityPrincipal) -> Result<AuthenticatedUser> {
        UserRepository::sign_in_by_id(
            &self.pool,
            principal.user_id,
            principal.active_organization_id,
        )
        .await?
        .ok_or(AccountServiceError::SessionUnusable)
    }

    async fn response_from_user(
        &self,
        user: &AuthenticatedUser,
        role: Option<OrganizationRole>,
        locale: Locale,
        privileged_until: Option<chrono::DateTime<Utc>>,
    ) -> Result<AuthResponse, sqlx::Error> {
        let organizations: Vec<(Uuid, String, String, String)> =
            MembershipRepository::active_organizations_of(&self.pool, user.user_id).await?;
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
            requires_organization_selection: organizations.len() > 1
                && active_organization.is_none(),
            organizations,
            active_organization,
            active_role: role,
            privileged_until,
            capabilities: access_capabilities(user.is_super_admin, role),
        })
    }

    async fn enqueue_requested_action(
        &self,
        user: AuthenticatedUser,
        purpose: &str,
    ) -> Result<(), MailError> {
        let mut tx = self.pool.begin().await?;
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
                &self.mail,
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
                &self.mail,
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
}

/// Makes an existing, verified, enabled user a super administrator again. The
/// operator proves authority with the configured admin credential.
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

/// Refuses to start without a way to administer the platform: an active
/// super administrator, or a setup authorization to create the first one.
pub async fn verify_user_access(pool: &PgPool, setup_enabled: bool) -> anyhow::Result<()> {
    let administrator_count = UserRepository::active_super_admin_count(pool).await?;
    anyhow::ensure!(
        setup_enabled || administrator_count > 0,
        "no active super administrator exists; configure setup authorization or run platform recovery"
    );
    Ok(())
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

async fn issue_action(
    tx: &mut Transaction<'_, Postgres>,
    config: &MailConfig,
    issue: ActionIssue<'_>,
    data: impl FnOnce(String) -> TemplateData,
) -> Result<(), MailError> {
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

#[allow(clippy::too_many_arguments)]
async fn create_registration(
    tx: &mut Transaction<'_, Postgres>,
    mail: &MailConfig,
    input: &Registration,
    email: &str,
    password_hash: &str,
    user_id: Uuid,
    organization_id: Uuid,
) -> Result<(), MailError> {
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
) -> Result<(), MailError> {
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

    /// The use cases against a real database, through the service.
    mod use_cases {
        use super::super::*;

        const PASSWORD: &str = "correct horse battery staple";

        fn config(public_signup: bool) -> WebApiConfig {
            WebApiConfig::default()
                .with_user_auth(public_signup, false, std::time::Duration::from_secs(3600))
                .with_mail(MailConfig {
                    enabled: true,
                    public_web_url: url::Url::parse("https://ui.example.com").unwrap(),
                    encryption_key: [11; 32],
                    ..MailConfig::default()
                })
        }

        fn registration(email: &str, slug: &str) -> Registration {
            Registration {
                email: email.into(),
                password: PASSWORD.into(),
                display_name: " Alice ".into(),
                organization_slug: slug.into(),
                organization_name: "Northstar".into(),
                locale: Locale::En,
            }
        }

        /// Stores an email action for the user and returns its token.
        async fn action(pool: &PgPool, user_id: Uuid, purpose: &str) -> String {
            let token = generate_action(purpose);
            EmailActionRepository::insert(
                pool,
                Uuid::new_v4(),
                user_id,
                purpose,
                token.digest.to_vec(),
                Utc::now() + Duration::minutes(5),
            )
            .await
            .unwrap();
            token.plaintext.to_string()
        }

        async fn user_id(pool: &PgPool, email: &str) -> Uuid {
            let user: AuthenticatedUser = UserRepository::sign_in_by_email(pool, email)
                .await
                .unwrap()
                .unwrap();
            user.user_id
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn registration_is_gated_validated_and_unique(pool: PgPool) {
            let closed = AccountService::new(pool.clone(), &config(false));
            assert!(matches!(
                closed.register(registration("bad", "-")).await,
                Err(AccountServiceError::RegistrationDisabled)
            ));

            let service = AccountService::new(pool.clone(), &config(true));
            assert!(matches!(
                service.register(registration("bad", "-")).await,
                Err(AccountServiceError::Invalid(_))
            ));
            let mut weak = registration("alice@example.test", "-");
            weak.password = "short".into();
            assert!(matches!(
                service.register(weak).await,
                Err(AccountServiceError::Invalid(_))
            ));
            assert!(matches!(
                service
                    .register(registration("alice@example.test", "-"))
                    .await,
                Err(AccountServiceError::Invalid(
                    "organization slug or name is invalid"
                ))
            ));
            service
                .register(registration("Alice@Example.test", "northstar"))
                .await
                .unwrap();
            assert!(matches!(
                service
                    .register(registration("other@example.test", "northstar"))
                    .await,
                Err(AccountServiceError::RegistrationConflict)
            ));

            // The new owner signs in only after verifying the email.
            assert!(matches!(
                service.login("alice@example.test", PASSWORD, None).await,
                Err(AccountServiceError::EmailVerificationRequired)
            ));
            assert!(matches!(
                service
                    .login("alice@example.test", "wrong password", None)
                    .await,
                Err(AccountServiceError::InvalidCredentials)
            ));
            assert!(matches!(
                service.login("nobody@example.test", PASSWORD, None).await,
                Err(AccountServiceError::InvalidCredentials)
            ));
            let alice = user_id(&pool, "alice@example.test").await;
            let token = action(&pool, alice, "verify_email").await;
            assert!(matches!(
                service.confirm_verification("oko_verify_email_v1_x").await,
                Err(AccountServiceError::ActionTokenInvalid)
            ));
            service.confirm_verification(&token).await.unwrap();
            assert!(matches!(
                service.confirm_verification(&token).await,
                Err(AccountServiceError::ActionTokenInvalid)
            ));

            let signed_in = service
                .login(" ALICE@example.test ", PASSWORD, Some("not a session"))
                .await
                .unwrap();
            assert_eq!(signed_in.user.user.display_name, "Alice");
            assert_eq!(signed_in.user.active_role, Some(OrganizationRole::Owner));
            assert!(!signed_in.user.requires_organization_selection);
            service
                .logout(Some(signed_in.session.expose()))
                .await
                .unwrap();
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn passwords_reset_and_change_end_other_sessions(pool: PgPool) {
            let service = AccountService::new(pool.clone(), &config(true));
            service
                .register(registration("alice@example.test", "northstar"))
                .await
                .unwrap();
            let alice = user_id(&pool, "alice@example.test").await;
            let verify = action(&pool, alice, "verify_email").await;
            service.confirm_verification(&verify).await.unwrap();

            // Requests never reveal whether the email is known.
            service
                .request_email_action("nobody@example.test", EmailAction::ResetPassword)
                .await
                .unwrap();
            assert!(matches!(
                service
                    .request_email_action("bad", EmailAction::ResetPassword)
                    .await,
                Err(AccountServiceError::Invalid(_))
            ));
            service
                .request_email_action("alice@example.test", EmailAction::ResetPassword)
                .await
                .unwrap();

            // The new password is checked before the token.
            assert!(matches!(
                service.complete_password_reset("garbage", "short").await,
                Err(AccountServiceError::Invalid(_))
            ));
            assert!(matches!(
                service
                    .complete_password_reset("garbage", "another long password")
                    .await,
                Err(AccountServiceError::ActionTokenInvalid)
            ));
            let reset = action(&pool, alice, "reset_password").await;
            service
                .complete_password_reset(&reset, "another long password")
                .await
                .unwrap();
            assert!(matches!(
                service.login("alice@example.test", PASSWORD, None).await,
                Err(AccountServiceError::InvalidCredentials)
            ));
            let signed_in = service
                .login("alice@example.test", "another long password", None)
                .await
                .unwrap();
            let organization = signed_in.user.active_organization.as_ref().unwrap().id;

            let principal = IdentityPrincipal {
                user_id: alice,
                session_id: Uuid::new_v4(),
                active_organization_id: Some(organization),
                organization_role: Some(OrganizationRole::Owner),
                is_super_admin: false,
                privileged_until: None,
            };
            assert!(matches!(
                service
                    .change_password(principal, "wrong password", PASSWORD)
                    .await,
                Err(AccountServiceError::CurrentPasswordInvalid)
            ));
            service
                .change_password(principal, "another long password", PASSWORD)
                .await
                .unwrap();
            let sessions: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM user_sessions WHERE user_id=$1 AND revoked_at IS NULL",
            )
            .bind(alice)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(sessions, 1, "only the replacement session stays");

            assert!(matches!(
                service
                    .update_preferences(principal, Locale::En, Some("   ".into()))
                    .await,
                Err(AccountServiceError::Invalid(
                    "display name must contain 1-120 characters"
                ))
            ));
            let updated = service
                .update_preferences(principal, Locale::En, Some(" Alice B ".into()))
                .await
                .unwrap();
            assert_eq!(updated.user.display_name, "Alice B");
            let me = service.me(principal).await.unwrap();
            assert_eq!(me.user.display_name, "Alice B");
            assert!(matches!(
                service
                    .me(IdentityPrincipal {
                        user_id: Uuid::new_v4(),
                        ..principal
                    })
                    .await,
                Err(AccountServiceError::SessionUnusable)
            ));
        }
    }
}
