use crate::repository::notification_retention::NotificationRetentionRepository;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, FromRow)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub enabled: bool,
    pub history_days: i32,
}

impl RetentionPolicy {
    pub fn valid(self) -> bool {
        (1..=3650).contains(&self.history_days)
    }
}

#[derive(Debug, Serialize)]
pub struct ProjectRetention {
    #[serde(rename = "override")]
    pub policy_override: Option<RetentionPolicy>,
    pub effective: RetentionPolicy,
    pub inherited: RetentionPolicy,
    pub source: &'static str,
}

/// Import only organizations present when migration 22 ran; never overwrite user edits.
pub async fn initialize(pool: &PgPool, legacy: RetentionPolicy) -> Result<(), sqlx::Error> {
    if !legacy.valid() {
        return Err(sqlx::Error::Protocol(
            "invalid legacy retention window".into(),
        ));
    }
    NotificationRetentionRepository::initialize_organizations(
        pool,
        legacy.enabled,
        legacy.history_days,
    )
    .await?;
    Ok(())
}

pub async fn organization(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Option<RetentionPolicy>, sqlx::Error> {
    NotificationRetentionRepository::organization_policy(pool, organization_id).await
}

#[derive(FromRow)]
struct ProjectPolicyRow {
    override_enabled: Option<bool>,
    override_days: Option<i32>,
    #[sqlx(flatten)]
    effective: RetentionPolicy,
    inherited_enabled: bool,
    inherited_days: i32,
}

pub async fn project(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<Option<ProjectRetention>, sqlx::Error> {
    let row: Option<ProjectPolicyRow> =
        NotificationRetentionRepository::project_policy(pool, organization_id, project_id).await?;
    Ok(row.map(|row| {
        let policy_override =
            row.override_enabled
                .zip(row.override_days)
                .map(|(enabled, history_days)| RetentionPolicy {
                    enabled,
                    history_days,
                });
        ProjectRetention {
            source: if policy_override.is_some() {
                "project"
            } else {
                "organization"
            },
            policy_override,
            effective: row.effective,
            inherited: RetentionPolicy {
                enabled: row.inherited_enabled,
                history_days: row.inherited_days,
            },
        }
    }))
}

pub async fn set_organization(
    pool: &PgPool,
    organization_id: Uuid,
    actor: Uuid,
    policy: RetentionPolicy,
) -> Result<(), sqlx::Error> {
    NotificationRetentionRepository::set_organization_policy(
        pool,
        organization_id,
        policy.enabled,
        policy.history_days,
        actor,
    )
    .await?;
    Ok(())
}

pub async fn set_project(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    actor: Uuid,
    policy: Option<RetentionPolicy>,
) -> Result<(), sqlx::Error> {
    NotificationRetentionRepository::set_project_override(
        pool,
        organization_id,
        project_id,
        policy.map(|p| p.enabled),
        policy.map(|p| p.history_days),
        actor,
    )
    .await?;
    Ok(())
}
