use crate::repository::application_credentials::ApplicationCredentialRepository;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const TOKEN_PREFIX: &str = "oko_app_v1_";
const TOKEN_BYTES: usize = 32;
const TOKEN_HINT_CHARS: usize = 8;

pub struct ApplicationToken {
    plaintext: Zeroizing<String>,
    digest: [u8; 32],
    hint: String,
}

impl ApplicationToken {
    pub fn generate() -> Self {
        let mut bytes = [0_u8; TOKEN_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    pub fn parse(value: &str) -> Result<Self, ApplicationTokenError> {
        let encoded = value
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(ApplicationTokenError::InvalidFormat)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ApplicationTokenError::InvalidFormat)?;
        let bytes: [u8; TOKEN_BYTES] = decoded
            .try_into()
            .map_err(|_| ApplicationTokenError::InvalidFormat)?;
        let token = Self::from_bytes(bytes);
        if token.plaintext.as_str() != value {
            return Err(ApplicationTokenError::InvalidFormat);
        }
        Ok(token)
    }

    pub fn expose(&self) -> &str {
        self.plaintext.as_str()
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn hint(&self) -> &str {
        &self.hint
    }

    pub fn digest_matches(&self, candidate: &[u8]) -> bool {
        self.digest.as_slice().ct_eq(candidate).into()
    }

    fn from_bytes(bytes: [u8; TOKEN_BYTES]) -> Self {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let plaintext = Zeroizing::new(format!("{TOKEN_PREFIX}{encoded}"));
        let digest = Sha256::digest(plaintext.as_bytes()).into();
        let hint = encoded[encoded.len() - TOKEN_HINT_CHARS..].to_owned();
        Self {
            plaintext,
            digest,
            hint,
        }
    }
}

impl fmt::Debug for ApplicationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationToken")
            .field("plaintext", &"[REDACTED]")
            .field("hint", &self.hint)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ApplicationTokenError {
    #[error("application credential has an invalid format")]
    InvalidFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationCredentialScope {
    pub credential_id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ApplicationCredentialSummary {
    pub id: Uuid,
    pub name: String,
    pub token_hint: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub struct IssuedApplicationCredential {
    pub summary: ApplicationCredentialSummary,
    token: ApplicationToken,
}

impl IssuedApplicationCredential {
    pub fn token(&self) -> &str {
        self.token.expose()
    }
}

impl fmt::Debug for IssuedApplicationCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedApplicationCredential")
            .field("summary", &self.summary)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum ApplicationCredentialError {
    #[error(transparent)]
    InvalidToken(#[from] ApplicationTokenError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub async fn issue(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    name: &str,
) -> Result<IssuedApplicationCredential, sqlx::Error> {
    let token = ApplicationToken::generate();
    let summary = ApplicationCredentialRepository::insert::<_, ApplicationCredentialSummary>(
        &mut **tx,
        Uuid::new_v4(),
        organization_id,
        project_id,
        application_id,
        name,
        token.digest().as_slice(),
        token.hint(),
    )
    .await?;
    Ok(IssuedApplicationCredential { summary, token })
}

pub async fn list(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<Vec<ApplicationCredentialSummary>, sqlx::Error> {
    ApplicationCredentialRepository::list(pool, organization_id, project_id, application_id).await
}

pub async fn revoke(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    credential_id: Uuid,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    ApplicationCredentialRepository::revoke_in_application(
        pool,
        organization_id,
        project_id,
        application_id,
        credential_id,
    )
    .await
    .map(Option::flatten)
}

pub async fn authenticate(
    pool: &PgPool,
    plaintext: &str,
) -> Result<Option<ApplicationCredentialScope>, ApplicationCredentialError> {
    let token = ApplicationToken::parse(plaintext)?;
    let scope =
        ApplicationCredentialRepository::authenticate(pool, token.digest().as_slice()).await?;
    Ok(scope.map(
        |(credential_id, organization_id, project_id, application_id)| ApplicationCredentialScope {
            credential_id,
            organization_id,
            project_id,
            application_id,
        },
    ))
}

pub async fn remains_active(
    tx: &mut Transaction<'_, Postgres>,
    scope: ApplicationCredentialScope,
) -> Result<bool, sqlx::Error> {
    ApplicationCredentialRepository::is_active(
        &mut **tx,
        scope.credential_id,
        scope.organization_id,
        scope.project_id,
        scope.application_id,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_round_trip_without_debug_exposure() {
        let token = ApplicationToken::generate();
        let parsed = ApplicationToken::parse(token.expose()).unwrap();

        assert!(token.expose().starts_with(TOKEN_PREFIX));
        assert_eq!(token.digest(), parsed.digest());
        assert_eq!(token.hint(), parsed.hint());
        assert!(token.digest_matches(parsed.digest()));
        assert!(!format!("{token:?}").contains(token.expose()));
    }

    #[test]
    fn malformed_tokens_have_one_safe_error() {
        for value in ["", "wrong", "oko_app_v1_bad!", "oko_app_v1_YQ"] {
            assert_eq!(
                ApplicationToken::parse(value).unwrap_err(),
                ApplicationTokenError::InvalidFormat
            );
        }
    }

    #[test]
    fn generated_tokens_are_distinct() {
        let first = ApplicationToken::generate();
        let second = ApplicationToken::generate();
        assert_ne!(first.expose(), second.expose());
        assert!(!first.digest_matches(second.digest()));
    }
}
