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
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE organization_id=$1 AND id=$2)",
        )
        .bind(organization_id)
        .bind(project_id)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn list(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Vec<WebhookDestination>, sqlx::Error> {
        sqlx::query_as("SELECT id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at FROM webhook_destinations WHERE organization_id=$1 AND project_id=$2 ORDER BY created_at DESC,id DESC")
            .bind(organization_id).bind(project_id).fetch_all(&self.pool).await
    }

    pub async fn get(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        id: Uuid,
    ) -> Result<Option<WebhookDestination>, sqlx::Error> {
        sqlx::query_as("SELECT id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at FROM webhook_destinations WHERE organization_id=$1 AND project_id=$2 AND id=$3")
            .bind(organization_id).bind(project_id).bind(id).fetch_optional(&self.pool).await
    }

    pub async fn target(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        id: Uuid,
    ) -> Result<Option<WebhookTarget>, sqlx::Error> {
        sqlx::query_as("SELECT id,url,enabled,encrypted_secret,secret_nonce FROM webhook_destinations WHERE organization_id=$1 AND project_id=$2 AND id=$3")
            .bind(organization_id).bind(project_id).bind(id).fetch_optional(&self.pool).await
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
        let destination = sqlx::query_as("INSERT INTO webhook_destinations (id,organization_id,project_id,name,url,encrypted_secret,secret_nonce,deliver_backfill) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at")
            .bind(Uuid::new_v4()).bind(organization_id).bind(project_id).bind(name.trim()).bind(url)
            .bind(encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(deliver_backfill)
            .fetch_one(&self.pool).await?;
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
        let destination = sqlx::query_as("UPDATE webhook_destinations SET name=COALESCE($4,name),url=COALESCE($5,url),deliver_backfill=COALESCE($6,deliver_backfill),enabled=COALESCE($7,enabled),disabled_at=CASE WHEN $7=true THEN NULL WHEN $7=false THEN COALESCE(disabled_at,now()) ELSE disabled_at END,revision=revision+1,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND id=$3 AND revision=$8 RETURNING id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at")
            .bind(organization_id).bind(project_id).bind(id).bind(update.name.map(str::trim)).bind(update.url)
            .bind(update.deliver_backfill).bind(update.enabled).bind(update.expected_revision).fetch_optional(&self.pool).await?;
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
        let destination: Option<WebhookDestination> = sqlx::query_as("UPDATE webhook_destinations SET enabled=false,disabled_at=COALESCE(disabled_at,now()),updated_at=now(),revision=revision+1 WHERE organization_id=$1 AND project_id=$2 AND id=$3 RETURNING id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at")
            .bind(organization_id).bind(project_id).bind(id).fetch_optional(&mut *tx).await?;
        let destination = destination.ok_or(DestinationError::NotFound)?;
        sqlx::query("UPDATE notification_deliveries SET status='cancelled',terminal_at=now(),updated_at=now(),lease_owner=NULL,lease_expires_at=NULL,last_error_class='destination_disabled',last_error='destination disabled before delivery' WHERE organization_id=$1 AND project_id=$2 AND destination_id=$3 AND status IN ('pending','in_flight')")
            .bind(organization_id).bind(project_id).bind(id).execute(&mut *tx).await?;
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
        let destination = sqlx::query_as("UPDATE webhook_destinations SET encrypted_secret=$4,secret_nonce=$5,revision=revision+1,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND id=$3 RETURNING id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at")
            .bind(organization_id).bind(project_id).bind(id).bind(encrypted.ciphertext).bind(encrypted.nonce.as_slice())
            .fetch_optional(&self.pool).await?.ok_or(DestinationError::NotFound)?;
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
