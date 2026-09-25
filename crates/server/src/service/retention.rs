//! Retention settings: how long a kind of data is kept, per organization and
//! project. Notification history and runtime evidence share these use cases
//! and differ only in their [`RetentionSettings`].
//!
//! Organization owners and admins read the organization default; owners (or
//! super administrators) change it. Anyone who sees a project reads its
//! settings; those who manage its members change them.

use std::marker::PhantomData;

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::access_control::EffectiveProjectAccess;
use crate::auth::{IdentityPrincipal, OrganizationRole};
use crate::service::project_access::{ProjectScope, project_scope};

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

/// Where one kind of retention settings is stored, and what makes its policy
/// valid.
pub trait RetentionSettings {
    type Policy: Copy + Send;
    type Project: Send;

    fn valid(policy: Self::Policy) -> bool;

    fn organization(
        pool: &PgPool,
        organization_id: Uuid,
    ) -> impl Future<Output = Result<Option<Self::Policy>, sqlx::Error>> + Send;

    fn project(
        pool: &PgPool,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> impl Future<Output = Result<Option<Self::Project>, sqlx::Error>> + Send;

    fn set_organization(
        pool: &PgPool,
        organization_id: Uuid,
        actor: Uuid,
        policy: Self::Policy,
    ) -> impl Future<Output = Result<(), sqlx::Error>> + Send;

    fn set_project(
        pool: &PgPool,
        organization_id: Uuid,
        project_id: Uuid,
        actor: Uuid,
        policy: Option<Self::Policy>,
    ) -> impl Future<Output = Result<(), sqlx::Error>> + Send;
}

/// The retention settings use cases, for the kind of settings `S` names.
#[derive(Debug)]
pub struct RetentionService<S> {
    pool: PgPool,
    settings: PhantomData<fn() -> S>,
}

impl<S> Clone for RetentionService<S> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            settings: PhantomData,
        }
    }
}

impl<S: RetentionSettings> RetentionService<S> {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            settings: PhantomData,
        }
    }

    /// The organization default.
    pub async fn organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
    ) -> Result<S::Policy> {
        self.owned_organization(principal, organization_id).await
    }

    /// Replaces the organization default. `None` stands for a
    /// body that is not a policy; it is refused after the authority checks,
    /// like a policy out of bounds.
    pub async fn set_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        policy: Option<S::Policy>,
    ) -> Result<S::Policy> {
        if !principal.is_super_admin && principal.active_organization_id != Some(organization_id) {
            return Err(RetentionServiceError::NotFound);
        }
        owner(principal, organization_id)?;
        self.owned_organization(principal, organization_id).await?;
        let policy = policy.ok_or(RetentionServiceError::Invalid)?;
        validate::<S>(policy)?;
        S::set_organization(&self.pool, organization_id, principal.user_id, policy).await?;
        Ok(policy)
    }

    /// A project's settings with what it inherits.
    pub async fn project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<S::Project> {
        let (_, _, retention) = self.owned_project(principal, project_id).await?;
        Ok(retention)
    }

    /// Sets a project's own policy, or with `None` returns it to the
    /// organization default.
    pub async fn change_project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        policy: Option<S::Policy>,
    ) -> Result<S::Project> {
        let (organization_id, access, _) = self.owned_project(principal, project_id).await?;
        if !access.can_manage_members() {
            return Err(RetentionServiceError::Forbidden);
        }
        if let Some(policy) = policy {
            validate::<S>(policy)?;
        }
        S::set_project(
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

    async fn owned_organization(&self, user: IdentityPrincipal, id: Uuid) -> Result<S::Policy> {
        let can_read = user.is_super_admin
            || user.active_organization_id == Some(id)
                && user
                    .organization_role
                    .is_some_and(OrganizationRole::inherits_project_access);
        if !can_read {
            return Err(RetentionServiceError::NotFound);
        }
        S::organization(&self.pool, id)
            .await?
            .ok_or(RetentionServiceError::NotFound)
    }

    async fn owned_project(
        &self,
        user: IdentityPrincipal,
        id: Uuid,
    ) -> Result<(Uuid, EffectiveProjectAccess, S::Project)> {
        let ProjectScope {
            organization_id,
            access,
        } = project_scope(&self.pool, user, id)
            .await?
            .ok_or(RetentionServiceError::NotFound)?;
        let retention = S::project(&self.pool, organization_id, id)
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

fn validate<S: RetentionSettings>(policy: S::Policy) -> Result<()> {
    if S::valid(policy) {
        Ok(())
    } else {
        Err(RetentionServiceError::Invalid)
    }
}
