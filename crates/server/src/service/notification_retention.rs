//! How long notification history is kept, per organization and project.
//! The use cases are in [`super::retention`].

use sqlx::PgPool;
use uuid::Uuid;

use crate::notification::retention_settings::{
    self as settings, ProjectRetention, RetentionPolicy,
};
use crate::service::retention::{RetentionService, RetentionSettings};

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
        settings::organization(pool, organization_id).await
    }

    async fn project(
        pool: &PgPool,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Option<ProjectRetention>, sqlx::Error> {
        settings::project(pool, organization_id, project_id).await
    }

    async fn set_organization(
        pool: &PgPool,
        organization_id: Uuid,
        actor: Uuid,
        policy: RetentionPolicy,
    ) -> Result<(), sqlx::Error> {
        settings::set_organization(pool, organization_id, actor, policy).await
    }

    async fn set_project(
        pool: &PgPool,
        organization_id: Uuid,
        project_id: Uuid,
        actor: Uuid,
        policy: Option<RetentionPolicy>,
    ) -> Result<(), sqlx::Error> {
        settings::set_project(pool, organization_id, project_id, actor, policy).await
    }
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
