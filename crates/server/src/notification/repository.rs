use crate::repository::notification_deliveries::NotificationDeliveryRepository;
use crate::repository::webhook_destinations::WebhookDestinationRepository;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::crypto::{SecretVault, SecretVaultError};

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct WebhookDestination {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub deliver_backfill: bool,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct DestinationRepository {
    pool: PgPool,
    vault: SecretVault,
}

#[derive(Clone, Debug)]
pub struct DestinationUpdate<'a> {
    pub name: Option<&'a str>,
    pub url: Option<&'a str>,
    pub deliver_backfill: Option<bool>,
    pub enabled: Option<bool>,
    pub expected_revision: i64,
}

#[derive(Clone, Debug, FromRow)]
pub struct WebhookTarget {
    pub id: Uuid,
    pub url: String,
    pub enabled: bool,
    pub encrypted_secret: Vec<u8>,
    pub secret_nonce: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum DestinationError {
    #[error("destination was not found")]
    NotFound,
    #[error("destination revision conflict")]
    RevisionConflict,
    #[error("destination name must contain between 1 and 200 characters")]
    InvalidName,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("secret vault error: {0}")]
    Vault(#[from] SecretVaultError),
}

impl DestinationRepository {
    #[must_use]
    pub fn new(pool: PgPool, vault: SecretVault) -> Self {
        Self { pool, vault }
    }

    pub async fn project_owned(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        crate::repository::ProjectRepository::exists_in(&self.pool, organization_id, project_id)
            .await
    }

    pub async fn list(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Vec<WebhookDestination>, sqlx::Error> {
        WebhookDestinationRepository::list(&self.pool, organization_id, project_id).await
    }

    pub async fn get(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        id: Uuid,
    ) -> Result<Option<WebhookDestination>, sqlx::Error> {
        WebhookDestinationRepository::get(&self.pool, organization_id, project_id, id).await
    }

    pub async fn target(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        id: Uuid,
    ) -> Result<Option<WebhookTarget>, sqlx::Error> {
        WebhookDestinationRepository::target(&self.pool, organization_id, project_id, id).await
    }

    pub async fn create(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        name: &str,
        url: &str,
        deliver_backfill: bool,
    ) -> Result<(WebhookDestination, Zeroizing<String>), DestinationError> {
        validate_name(name)?;
        if !self.project_owned(organization_id, project_id).await? {
            return Err(DestinationError::NotFound);
        }
        let secret = SecretVault::generate_secret();
        let encrypted = self.vault.encrypt(secret.as_bytes())?;
        let destination = WebhookDestinationRepository::insert(
            &self.pool,
            Uuid::new_v4(),
            organization_id,
            project_id,
            name.trim(),
            url,
            encrypted.ciphertext,
            encrypted.nonce.as_slice(),
            deliver_backfill,
        )
        .await?;
        Ok((destination, secret))
    }

    pub async fn update(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        id: Uuid,
        update: DestinationUpdate<'_>,
    ) -> Result<WebhookDestination, DestinationError> {
        if let Some(name) = update.name {
            validate_name(name)?;
        }
        let destination = WebhookDestinationRepository::update(
            &self.pool,
            organization_id,
            project_id,
            id,
            update.name.map(str::trim),
            update.url,
            update.deliver_backfill,
            update.enabled,
            update.expected_revision,
        )
        .await?;
        if let Some(destination) = destination {
            return Ok(destination);
        }
        if self.get(organization_id, project_id, id).await?.is_some() {
            Err(DestinationError::RevisionConflict)
        } else {
            Err(DestinationError::NotFound)
        }
    }

    pub async fn disable(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        id: Uuid,
    ) -> Result<WebhookDestination, DestinationError> {
        let mut tx = self.pool.begin().await?;
        let destination: Option<WebhookDestination> =
            WebhookDestinationRepository::disable(&mut *tx, organization_id, project_id, id)
                .await?;
        let destination = destination.ok_or(DestinationError::NotFound)?;
        NotificationDeliveryRepository::cancel_for_destination(
            &mut *tx,
            organization_id,
            project_id,
            id,
        )
        .await?;
        tx.commit().await?;
        Ok(destination)
    }

    pub async fn rotate_secret(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        id: Uuid,
    ) -> Result<(WebhookDestination, Zeroizing<String>), DestinationError> {
        let secret = SecretVault::generate_secret();
        let encrypted = self.vault.encrypt(secret.as_bytes())?;
        let destination = WebhookDestinationRepository::rotate_secret(
            &self.pool,
            organization_id,
            project_id,
            id,
            encrypted.ciphertext,
            encrypted.nonce.as_slice(),
        )
        .await?
        .ok_or(DestinationError::NotFound)?;
        Ok((destination, secret))
    }
}

fn validate_name(name: &str) -> Result<(), DestinationError> {
    if (1..=200).contains(&name.trim().chars().count()) {
        Ok(())
    } else {
        Err(DestinationError::InvalidName)
    }
}
