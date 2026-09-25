//! How long runtime evidence is kept, per organization and project.
//! The policy types and where they are stored are here; the use cases are in
//! [`super::retention`].

use crate::repository::organizations::OrganizationRepository;
use crate::repository::projects::ProjectRepository;
use crate::repository::runtime_retention::RuntimeRetentionRepository;
use crate::service::retention::{RetentionService, RetentionSettings};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

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
        RuntimeRetentionRepository::organization_policy(pool, organization_id).await
    }

    async fn project(
        pool: &PgPool,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Option<ProjectRetention>, sqlx::Error> {
        let row: Option<ProjectPolicyRow> =
            RuntimeRetentionRepository::project_policy(pool, organization_id, project_id).await?;
        Ok(row.map(ProjectPolicyRow::resolve))
    }

    async fn set_organization(
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

    async fn set_project(
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
}

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

#[cfg(test)]
mod settings_tests {
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
