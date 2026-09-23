use crate::repository::organizations::OrganizationRepository;
use crate::repository::projects::ProjectRepository;
use crate::repository::runtime_retention::RuntimeRetentionRepository;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, FromRow)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub enabled: bool,
    pub raw_days: i32,
    #[serde(deserialize_with = "required_nullable_days")]
    pub history_days: Option<i32>,
}

fn required_nullable_days<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i32>, D::Error> {
    Option::<i32>::deserialize(deserializer)
}

impl RetentionPolicy {
    pub fn valid(self) -> bool {
        (1..=3650).contains(&self.raw_days)
            && self
                .history_days
                .is_none_or(|days| (self.raw_days..=3650).contains(&days))
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

pub async fn organization(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Option<RetentionPolicy>, sqlx::Error> {
    RuntimeRetentionRepository::organization_policy(pool, organization_id).await
}

#[derive(FromRow)]
struct ProjectPolicyRow {
    override_enabled: Option<bool>,
    override_raw_days: Option<i32>,
    override_history_days: Option<i32>,
    #[sqlx(flatten)]
    inherited: RetentionPolicy,
}

impl ProjectPolicyRow {
    fn resolve(self) -> ProjectRetention {
        let policy_override =
            self.override_enabled
                .zip(self.override_raw_days)
                .map(|(enabled, raw_days)| RetentionPolicy {
                    enabled,
                    raw_days,
                    history_days: self.override_history_days,
                });
        ProjectRetention {
            source: if policy_override.is_some() {
                "project"
            } else {
                "organization"
            },
            effective: policy_override.unwrap_or(self.inherited),
            policy_override,
            inherited: self.inherited,
        }
    }
}

pub async fn project(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<Option<ProjectRetention>, sqlx::Error> {
    let row: Option<ProjectPolicyRow> =
        RuntimeRetentionRepository::project_policy(pool, organization_id, project_id).await?;
    Ok(row.map(ProjectPolicyRow::resolve))
}

pub async fn set_organization(
    pool: &PgPool,
    organization_id: Uuid,
    actor: Uuid,
    policy: RetentionPolicy,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    OrganizationRepository::lock_for_update(&mut *tx, organization_id).await?;
    RuntimeRetentionRepository::set_organization_policy(
        &mut *tx,
        organization_id,
        policy.enabled,
        policy.raw_days,
        policy.history_days,
        actor,
    )
    .await?;
    tx.commit().await
}

pub async fn set_project(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    actor: Uuid,
    policy: Option<RetentionPolicy>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    OrganizationRepository::lock_for_update(&mut *tx, organization_id).await?;
    ProjectRepository::lock_row_for_update(&mut *tx, organization_id, project_id).await?;
    RuntimeRetentionRepository::set_project_override(
        &mut *tx,
        organization_id,
        project_id,
        policy.map(|p| p.enabled),
        policy.map(|p| p.raw_days),
        policy.and_then(|p| p.history_days),
        actor,
    )
    .await?;
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_horizons_including_forever() {
        for (raw_days, history_days, valid) in [
            (30, Some(365), true),
            (30, None, true),
            (30, Some(30), true),
            (0, None, false),
            (3651, None, false),
            (30, Some(29), false),
            (30, Some(3651), false),
        ] {
            assert_eq!(
                RetentionPolicy {
                    enabled: false,
                    raw_days,
                    history_days
                }
                .valid(),
                valid
            );
        }
    }

    #[test]
    fn forever_and_disabled_are_complete_overrides() {
        let inherited = RetentionPolicy {
            enabled: true,
            raw_days: 30,
            history_days: Some(365),
        };
        let result = ProjectPolicyRow {
            override_enabled: Some(false),
            override_raw_days: Some(7),
            override_history_days: None,
            inherited,
        }
        .resolve();
        assert_eq!(result.source, "project");
        assert_eq!(result.effective.history_days, None);
        assert!(!result.effective.enabled);
        let inherited_result = ProjectPolicyRow {
            override_enabled: None,
            override_raw_days: None,
            override_history_days: None,
            inherited,
        }
        .resolve();
        assert_eq!(inherited_result.source, "organization");
        assert_eq!(inherited_result.effective, inherited);
    }

    #[test]
    fn complete_policy_requires_explicit_history_horizon() {
        assert!(
            serde_json::from_str::<RetentionPolicy>(r#"{"enabled":true,"raw_days":30}"#).is_err()
        );
        assert!(
            serde_json::from_str::<RetentionPolicy>(
                r#"{"enabled":true,"raw_days":30,"history_days":null}"#
            )
            .is_ok()
        );
    }
}
