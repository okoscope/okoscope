//! How long runtime evidence is kept, per organization and project.
//!
//! Organization owners and admins read the organization default; owners (or
//! super administrators) change it. Anyone who sees a project reads its
//! settings; those who manage its members change them.

use thiserror::Error;
use uuid::Uuid;

use sqlx::PgPool;

use crate::access_control::{EffectiveProjectAccess, resolve_project_access};
use crate::auth::{IdentityPrincipal, OrganizationRole};
use crate::repository::ProjectRepository;
use crate::runtime_retention::settings::{self as settings, ProjectRetention, RetentionPolicy};

/// Why a retention settings use case failed.
#[derive(Debug, Error)]
pub enum RetentionServiceError {
    /// The principal may see the settings but not change them.
    #[error("owner role is required")]
    Forbidden,
    /// The organization or project does not exist, or the principal may not
    /// see its settings.
    #[error("retention settings not found")]
    NotFound,
    /// The policy's bounds are invalid.
    #[error("retention policy is invalid")]
    Invalid,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

type Result<T, E = RetentionServiceError> = std::result::Result<T, E>;

#[derive(Clone, Debug)]
pub struct RuntimeRetentionService {
    pool: PgPool,
}

impl RuntimeRetentionService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The organization default.
    pub async fn organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
    ) -> Result<RetentionPolicy> {
        self.owned_organization(principal, organization_id).await
    }

    /// Replaces the organization default. `None` stands for a
    /// body that is not a policy; it is refused after the authority checks,
    /// like a policy out of bounds.
    pub async fn set_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        policy: Option<RetentionPolicy>,
    ) -> Result<RetentionPolicy> {
        if !principal.is_super_admin && principal.active_organization_id != Some(organization_id) {
            return Err(RetentionServiceError::NotFound);
        }
        owner(principal, organization_id)?;
        self.owned_organization(principal, organization_id).await?;
        let policy = policy.ok_or(RetentionServiceError::Invalid)?;
        validate(policy)?;
        settings::set_organization(&self.pool, organization_id, principal.user_id, policy).await?;
        Ok(policy)
    }

    /// A project's settings with what it inherits.
    pub async fn project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<ProjectRetention> {
        let (_, _, retention) = self.owned_project(principal, project_id).await?;
        Ok(retention)
    }

    /// Sets a project's own policy, or with `None` returns it to the
    /// organization default.
    pub async fn change_project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        policy: Option<RetentionPolicy>,
    ) -> Result<ProjectRetention> {
        let (organization_id, access, _) = self.owned_project(principal, project_id).await?;
        if !access.can_manage_members() {
            return Err(RetentionServiceError::Forbidden);
        }
        if let Some(policy) = policy {
            validate(policy)?;
        }
        settings::set_project(
            &self.pool,
            organization_id,
            project_id,
            principal.user_id,
            policy,
        )
        .await?;
        let (_, _, retention) = self.owned_project(principal, project_id).await?;
        Ok(retention)
    }

    async fn owned_organization(
        &self,
        user: IdentityPrincipal,
        id: Uuid,
    ) -> Result<RetentionPolicy> {
        let can_read = user.is_super_admin
            || user.active_organization_id == Some(id)
                && user
                    .organization_role
                    .is_some_and(OrganizationRole::inherits_project_access);
        if !can_read {
            return Err(RetentionServiceError::NotFound);
        }
        settings::organization(&self.pool, id)
            .await?
            .ok_or(RetentionServiceError::NotFound)
    }

    async fn owned_project(
        &self,
        user: IdentityPrincipal,
        id: Uuid,
    ) -> Result<(Uuid, EffectiveProjectAccess, ProjectRetention)> {
        let organization_id: Uuid = ProjectRepository::organization_of(&self.pool, id)
            .await?
            .ok_or(RetentionServiceError::NotFound)?;
        let access = resolve_project_access(&self.pool, user, organization_id, id)
            .await?
            .ok_or(RetentionServiceError::NotFound)?;
        let retention = settings::project(&self.pool, organization_id, id)
            .await?
            .ok_or(RetentionServiceError::NotFound)?;
        Ok((organization_id, access, retention))
    }
}

fn owner(principal: IdentityPrincipal, organization_id: Uuid) -> Result<()> {
    if principal.is_super_admin
        || principal.active_organization_id == Some(organization_id)
            && principal.organization_role == Some(OrganizationRole::Owner)
    {
        Ok(())
    } else {
        Err(RetentionServiceError::Forbidden)
    }
}

fn validate(policy: RetentionPolicy) -> Result<()> {
    if policy.valid() {
        Ok(())
    } else {
        Err(RetentionServiceError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
