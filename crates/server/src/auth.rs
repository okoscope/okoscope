use std::{fmt, str::FromStr, time::Duration};

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const SESSION_COOKIE: &str = "okoscope_session";
pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
const SESSION_PREFIX: &str = "oko_session_v1_";
const SESSION_BYTES: usize = 32;
const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_CHARS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionScope {
    pub organization_id: Uuid,
    pub cluster_id: Uuid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    Owner,
    Member,
}

impl OrganizationRole {
    pub fn is_owner(self) -> bool {
        self == Self::Owner
    }
}

impl FromStr for OrganizationRole {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "owner" => Ok(Self::Owner),
            "member" => Ok(Self::Member),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPrincipal {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub organization_id: Uuid,
    pub role: OrganizationRole,
}

#[derive(Clone, Debug)]
pub struct UserSessionAuthenticator {
    pool: PgPool,
}

impl UserSessionAuthenticator {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn authenticate(&self, token: &str) -> Result<Option<UserPrincipal>, sqlx::Error> {
        let Some(digest) = session_digest(token) else {
            return Ok(None);
        };
        let identity: Option<(Uuid, Uuid, Uuid, String)> = sqlx::query_as(
            "UPDATE user_sessions s SET last_used_at=now() FROM users u,organization_memberships m WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.id=s.user_id AND u.disabled_at IS NULL AND m.user_id=s.user_id AND m.organization_id=s.organization_id RETURNING s.id,s.user_id,s.organization_id,m.role",
        )
        .bind(digest.to_vec())
        .fetch_optional(&self.pool)
        .await?;
        Ok(
            identity.and_then(|(session_id, user_id, organization_id, role)| {
                Some(UserPrincipal {
                    user_id,
                    session_id,
                    organization_id,
                    role: role.parse().ok()?,
                })
            }),
        )
    }

    pub async fn authenticate_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<UserPrincipal>, sqlx::Error> {
        let Some(token) = session_token(headers) else {
            return Ok(None);
        };
        self.authenticate(token).await
    }
}

pub fn session_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| (name == SESSION_COOKIE).then_some(value))
}

pub fn normalize_email(value: &str) -> Result<String, &'static str> {
    let normalized = value.trim().to_ascii_lowercase();
    let valid = (3..=254).contains(&normalized.len())
        && normalized.is_ascii()
        && !normalized.contains(char::is_whitespace)
        && normalized.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
        });
    valid
        .then_some(normalized)
        .ok_or("email must be a valid address of at most 254 ASCII characters")
}

pub fn validate_password(value: &str) -> Result<(), &'static str> {
    if (MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&value.chars().count()) {
        Ok(())
    } else {
        Err("password must contain between 12 and 256 characters")
    }
}

pub fn hash_password(value: &str) -> Result<String, argon2::password_hash::Error> {
    validate_password(value).map_err(|_| argon2::password_hash::Error::Password)?;
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(value.as_bytes(), &salt)?
        .to_string())
}

pub fn verify_password(value: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(value.as_bytes(), &hash)
            .is_ok()
    })
}

pub struct SessionToken {
    plaintext: Zeroizing<String>,
    digest: [u8; 32],
}

impl SessionToken {
    pub fn generate() -> Self {
        let mut bytes = [0_u8; SESSION_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        let plaintext =
            Zeroizing::new(format!("{SESSION_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)));
        let digest = Sha256::digest(plaintext.as_bytes()).into();
        Self { plaintext, digest }
    }

    pub fn expose(&self) -> &str {
        self.plaintext.as_str()
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionToken")
            .finish_non_exhaustive()
    }
}

pub fn session_digest(token: &str) -> Option<[u8; 32]> {
    let encoded = token.strip_prefix(SESSION_PREFIX)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    if bytes.len() != SESSION_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return None;
    }
    Some(Sha256::digest(token.as_bytes()).into())
}

#[derive(Debug, sqlx::FromRow)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub organization_id: Uuid,
    pub organization_slug: String,
    pub organization_name: String,
    pub role: String,
    pub disabled_at: Option<DateTime<Utc>>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub preferred_locale: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_bounds_email() {
        assert_eq!(
            normalize_email(" User@Example.COM ").unwrap(),
            "user@example.com"
        );
        assert!(normalize_email("missing-at.example.com").is_err());
        assert!(normalize_email("user@example").is_err());
    }

    #[test]
    fn hashes_and_verifies_password_without_exposing_it() {
        let password = "correct horse battery staple";
        let hash = hash_password(password).unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(!hash.contains(password));
        assert!(verify_password(password, &hash));
        assert!(!verify_password("incorrect password", &hash));
    }

    #[test]
    fn session_tokens_are_canonical_and_redacted() {
        let token = SessionToken::generate();
        assert_eq!(session_digest(token.expose()).unwrap(), *token.digest());
        assert!(!format!("{token:?}").contains(token.expose()));
        assert!(session_digest("invalid").is_none());
    }

    #[test]
    fn legacy_bearer_credentials_are_not_session_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer former-organization-api-credential".parse().unwrap(),
        );
        assert!(session_token(&headers).is_none());
    }
}
