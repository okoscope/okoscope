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
    sqlx::query("UPDATE organizations SET notification_retention_enabled=$1,notification_retention_days=$2,notification_retention_initialized=true,notification_retention_updated_at=now() WHERE NOT notification_retention_initialized")
        .bind(legacy.enabled).bind(legacy.history_days).execute(pool).await?;
    Ok(())
}

pub async fn organization(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Option<RetentionPolicy>, sqlx::Error> {
    sqlx::query_as("SELECT notification_retention_enabled enabled,notification_retention_days history_days FROM organizations WHERE id=$1 AND notification_retention_initialized")
        .bind(organization_id).fetch_optional(pool).await
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
    let row: Option<ProjectPolicyRow> = sqlx::query_as(
        "SELECT p.notification_retention_enabled override_enabled,p.notification_retention_days override_days,e.enabled,e.history_days,o.notification_retention_enabled inherited_enabled,o.notification_retention_days inherited_days FROM projects p JOIN organizations o ON o.id=p.organization_id JOIN effective_notification_retention e ON e.project_id=p.id WHERE p.organization_id=$1 AND p.id=$2",
    ).bind(organization_id).bind(project_id).fetch_optional(pool).await?;
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
    sqlx::query("UPDATE organizations SET notification_retention_enabled=$2,notification_retention_days=$3,notification_retention_initialized=true,notification_retention_updated_at=now(),notification_retention_updated_by=$4 WHERE id=$1")
        .bind(organization_id).bind(policy.enabled).bind(policy.history_days).bind(actor)
        .execute(pool).await?;
    Ok(())
}

pub async fn set_project(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    actor: Uuid,
    policy: Option<RetentionPolicy>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE projects SET notification_retention_enabled=$3,notification_retention_days=$4,notification_retention_updated_at=now(),notification_retention_updated_by=$5 WHERE organization_id=$1 AND id=$2")
        .bind(organization_id).bind(project_id).bind(policy.map(|p| p.enabled))
        .bind(policy.map(|p| p.history_days)).bind(actor).execute(pool).await?;
    Ok(())
}
