//! How long runtime evidence is kept, per organization and project.
//! The use cases are in [`super::retention`].

use sqlx::PgPool;
use uuid::Uuid;

use crate::runtime_retention::settings::{self as settings, ProjectRetention, RetentionPolicy};
use crate::service::retention::{RetentionService, RetentionSettings};

pub use crate::service::retention::RetentionServiceError;

/// Runtime evidence settings.
#[derive(Debug)]
pub struct RuntimeEvidence;

pub type RuntimeRetentionService = RetentionService<RuntimeEvidence>;

impl RetentionSettings for RuntimeEvidence {
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
    use crate::repository::MembershipRepository;
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

    fn policy(raw_days: i32, history_days: Option<i32>) -> RetentionPolicy {
        RetentionPolicy {
            enabled: true,
            raw_days,
            history_days,
        }
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn organization_defaults_are_read_by_admins_and_set_by_owners(pool: PgPool) {
        let tenant = tenant(&pool, "runtime-retention-organization").await;
        let service = RuntimeRetentionService::new(pool.clone());
        let organization = tenant.organization_id;
        let owner = principal(&tenant, user(&pool).await, OrganizationRole::Owner);
        let admin = principal(&tenant, user(&pool).await, OrganizationRole::Admin);
        let member = principal(&tenant, user(&pool).await, OrganizationRole::Member);

        assert!(matches!(
            service.organization(member, organization).await,
            Err(RetentionServiceError::NotFound)
        ));
        service.organization(admin, organization).await.unwrap();
        assert!(matches!(
            service
                .set_organization(admin, organization, Some(policy(30, None)))
                .await,
            Err(RetentionServiceError::Forbidden)
        ));
        // Another organization is not found before any role check.
        let elsewhere = IdentityPrincipal {
            active_organization_id: Some(Uuid::new_v4()),
            ..owner
        };
        assert!(matches!(
            service
                .set_organization(elsewhere, organization, None)
                .await,
            Err(RetentionServiceError::NotFound)
        ));
        // A missing or out-of-bounds policy is refused after authority.
        assert!(matches!(
            service.set_organization(owner, organization, None).await,
            Err(RetentionServiceError::Invalid)
        ));
        assert!(matches!(
            service
                .set_organization(owner, organization, Some(policy(30, Some(29))))
                .await,
            Err(RetentionServiceError::Invalid)
        ));
        let stored = service
            .set_organization(owner, organization, Some(policy(30, Some(365))))
            .await
            .unwrap();
        assert_eq!(stored.raw_days, 30);
        assert_eq!(
            service
                .organization(admin, organization)
                .await
                .unwrap()
                .raw_days,
            30
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn project_overrides_need_project_administration(pool: PgPool) {
        let tenant = tenant(&pool, "runtime-retention-project").await;
        let service = RuntimeRetentionService::new(pool.clone());
        let project = tenant.project_id;
        let admin = principal(&tenant, user(&pool).await, OrganizationRole::Admin);
        let user_id = user(&pool).await;
        MembershipRepository::insert_organization_role(
            &pool,
            tenant.organization_id,
            user_id,
            "member",
        )
        .await
        .unwrap();
        let member = principal(&tenant, user_id, OrganizationRole::Member);

        assert!(matches!(
            service.project(member, project).await,
            Err(RetentionServiceError::NotFound)
        ));
        MembershipRepository::insert_project_role(
            &pool,
            tenant.organization_id,
            project,
            user_id,
            "member",
        )
        .await
        .unwrap();
        let inherited = service.project(member, project).await.unwrap();
        assert!(inherited.policy_override.is_none());
        assert!(matches!(
            service
                .change_project(member, project, Some(policy(30, None)))
                .await,
            Err(RetentionServiceError::Forbidden)
        ));
        let changed = service
            .change_project(admin, project, Some(policy(14, None)))
            .await
            .unwrap();
        assert_eq!(changed.effective.raw_days, 14);
        let reset = service.change_project(admin, project, None).await.unwrap();
        assert!(reset.policy_override.is_none());
    }
}
