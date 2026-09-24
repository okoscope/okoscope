//! How long notification history is kept, per organization and project.
//!
//! Organization owners and admins read the organization default; owners (or
//! super administrators) change it. Anyone who sees a project reads its
//! settings; those who manage its members change them.

use thiserror::Error;
use uuid::Uuid;

use sqlx::PgPool;

use crate::access_control::{EffectiveProjectAccess, resolve_project_access};
use crate::auth::{IdentityPrincipal, OrganizationRole};
use crate::notification::retention_settings::{
    self as settings, ProjectRetention, RetentionPolicy,
};
use crate::repository::ProjectRepository;

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
pub struct NotificationRetentionService {
    pool: PgPool,
}

impl NotificationRetentionService {
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

    /// Replaces the organization default.
    pub async fn set_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        policy: RetentionPolicy,
    ) -> Result<RetentionPolicy> {
        if !principal.is_super_admin && principal.active_organization_id != Some(organization_id) {
            return Err(RetentionServiceError::NotFound);
        }
        owner(principal, organization_id)?;
        self.owned_organization(principal, organization_id).await?;
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
                .set_organization(admin, tenant.organization_id, policy(30))
                .await,
            Err(RetentionServiceError::Forbidden)
        ));
        assert!(matches!(
            service
                .set_organization(owner, tenant.organization_id, policy(0))
                .await,
            Err(RetentionServiceError::Invalid)
        ));
        service
            .set_organization(owner, tenant.organization_id, policy(30))
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
