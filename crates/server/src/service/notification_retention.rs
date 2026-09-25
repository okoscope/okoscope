//! How long notification history is kept, per organization and project.
//! The policy types and where they are stored are here; the use cases are in
//! [`super::retention`].

use crate::repository::notification_retention::NotificationRetentionRepository;
use crate::service::retention::{RetentionService, RetentionSettings};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

pub use crate::service::retention::RetentionServiceError;

/// Notification history settings.
#[derive(Debug)]
pub struct NotificationHistory;

pub type NotificationRetentionService = RetentionService<NotificationHistory>;

impl RetentionSettings for NotificationHistory {
    type Policy = RetentionPolicy;
    type Project = ProjectRetention;

    fn valid(policy: RetentionPolicy) -> bool {
        policy.valid()
    }

    async fn organization(
        pool: &PgPool,
        organization_id: Uuid,
    ) -> Result<Option<RetentionPolicy>, sqlx::Error> {
        NotificationRetentionRepository::organization_policy(pool, organization_id).await
    }

    async fn project(
        pool: &PgPool,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Option<ProjectRetention>, sqlx::Error> {
        let row: Option<ProjectPolicyRow> =
            NotificationRetentionRepository::project_policy(pool, organization_id, project_id)
                .await?;
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

    async fn set_organization(
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

    async fn set_project(
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
}

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

#[derive(FromRow)]
struct ProjectPolicyRow {
    override_enabled: Option<bool>,
    override_days: Option<i32>,
    #[sqlx(flatten)]
    effective: RetentionPolicy,
    inherited_enabled: bool,
    inherited_days: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{IdentityPrincipal, OrganizationRole};
    use crate::repository::test_support::{Tenant, tenant, user};

    fn principal(tenant: &Tenant, user_id: Uuid, role: OrganizationRole) -> IdentityPrincipal {
        IdentityPrincipal {
            user_id,
            session_id: Uuid::new_v4(),
            active_organization_id: Some(tenant.organization_id),
            organization_role: Some(role),
            is_super_admin: false,
            privileged_until: None,
        }
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn history_windows_follow_the_same_authority(pool: PgPool) {
        let tenant = tenant(&pool, "notification-retention").await;
        let service = NotificationRetentionService::new(pool.clone());
        let owner = principal(&tenant, user(&pool).await, OrganizationRole::Owner);
        let admin = principal(&tenant, user(&pool).await, OrganizationRole::Admin);
        let policy = |history_days| RetentionPolicy {
            enabled: true,
            history_days,
        };

        assert!(matches!(
            service
                .set_organization(admin, tenant.organization_id, Some(policy(30)))
                .await,
            Err(RetentionServiceError::Forbidden)
        ));
        assert!(matches!(
            service
                .set_organization(owner, tenant.organization_id, Some(policy(0)))
                .await,
            Err(RetentionServiceError::Invalid)
        ));
        service
            .set_organization(owner, tenant.organization_id, Some(policy(30)))
            .await
            .unwrap();
        let project = service
            .change_project(admin, tenant.project_id, Some(policy(7)))
            .await
            .unwrap();
        assert_eq!(project.effective.history_days, 7);
        assert_eq!(project.inherited.history_days, 30);
        assert!(matches!(
            service.project(admin, Uuid::new_v4()).await,
            Err(RetentionServiceError::NotFound)
        ));
    }
}
