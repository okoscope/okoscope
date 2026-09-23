use crate::repository::MembershipRepository;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{IdentityPrincipal, OrganizationRole};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformRole {
    SuperAdmin,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectRole {
    Admin,
    Member,
}

impl FromStr for ProjectRole {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveAccessSource {
    Platform,
    Organization,
    Project,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct EffectiveProjectAccess {
    pub role: ProjectRole,
    pub source: EffectiveAccessSource,
}

impl EffectiveProjectAccess {
    pub fn can_manage_members(self) -> bool {
        self.role == ProjectRole::Admin
    }
}

pub async fn resolve_project_access(
    pool: &PgPool,
    principal: IdentityPrincipal,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<Option<EffectiveProjectAccess>, sqlx::Error> {
    let project_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND organization_id=$2)",
    )
    .bind(project_id)
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    if !project_exists {
        return Ok(None);
    }
    if principal.is_super_admin {
        return Ok(Some(EffectiveProjectAccess {
            role: ProjectRole::Admin,
            source: EffectiveAccessSource::Platform,
        }));
    }
    if principal.active_organization_id != Some(organization_id) {
        return Ok(None);
    }
    if principal
        .organization_role
        .is_some_and(OrganizationRole::inherits_project_access)
    {
        return Ok(Some(EffectiveProjectAccess {
            role: ProjectRole::Admin,
            source: EffectiveAccessSource::Organization,
        }));
    }
    let role =
        MembershipRepository::project_role(pool, organization_id, project_id, principal.user_id)
            .await?;
    Ok(role.and_then(|value| {
        Some(EffectiveProjectAccess {
            role: value.parse().ok()?,
            source: EffectiveAccessSource::Project,
        })
    }))
}

pub fn can_manage_organization_role(
    actor: OrganizationRole,
    current: OrganizationRole,
    next: Option<OrganizationRole>,
) -> bool {
    match actor {
        OrganizationRole::Owner => true,
        OrganizationRole::Admin => {
            current != OrganizationRole::Owner && next != Some(OrganizationRole::Owner)
        }
        OrganizationRole::Member => false,
    }
}

pub fn can_manage_project_role(
    platform: bool,
    organization: Option<OrganizationRole>,
    project: Option<ProjectRole>,
    next: Option<ProjectRole>,
) -> bool {
    platform
        || organization.is_some_and(OrganizationRole::inherits_project_access)
        || (project == Some(ProjectRole::Admin) && next != Some(ProjectRole::Admin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_grant_rules_are_explicit() {
        assert!(can_manage_organization_role(
            OrganizationRole::Owner,
            OrganizationRole::Owner,
            Some(OrganizationRole::Member)
        ));
        assert!(!can_manage_organization_role(
            OrganizationRole::Admin,
            OrganizationRole::Member,
            Some(OrganizationRole::Owner)
        ));
        assert!(can_manage_project_role(
            false,
            None,
            Some(ProjectRole::Admin),
            Some(ProjectRole::Member)
        ));
        assert!(!can_manage_project_role(
            false,
            None,
            Some(ProjectRole::Admin),
            Some(ProjectRole::Admin)
        ));
    }

    #[test]
    fn organization_role_matrix_is_complete() {
        let roles = [
            OrganizationRole::Owner,
            OrganizationRole::Admin,
            OrganizationRole::Member,
        ];
        for actor in roles {
            for current in roles {
                for next in roles.map(Some).into_iter().chain([None]) {
                    let expected = actor == OrganizationRole::Owner
                        || (actor == OrganizationRole::Admin
                            && current != OrganizationRole::Owner
                            && next != Some(OrganizationRole::Owner));
                    assert_eq!(
                        can_manage_organization_role(actor, current, next),
                        expected,
                        "actor={actor:?} current={current:?} next={next:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn project_role_matrix_is_complete() {
        let organization_roles = [
            None,
            Some(OrganizationRole::Owner),
            Some(OrganizationRole::Admin),
            Some(OrganizationRole::Member),
        ];
        let project_roles = [None, Some(ProjectRole::Admin), Some(ProjectRole::Member)];
        let targets = [None, Some(ProjectRole::Admin), Some(ProjectRole::Member)];
        for platform in [false, true] {
            for organization in organization_roles {
                for project in project_roles {
                    for next in targets {
                        let expected = platform
                            || organization.is_some_and(OrganizationRole::inherits_project_access)
                            || (project == Some(ProjectRole::Admin)
                                && next != Some(ProjectRole::Admin));
                        assert_eq!(
                            can_manage_project_role(platform, organization, project, next),
                            expected,
                            "platform={platform} organization={organization:?} project={project:?} next={next:?}"
                        );
                    }
                }
            }
        }
    }
}
