//! Project access shared by the services: which organization a project
//! belongs to and what the caller may do in it.
//!
//! Every project-scoped use case starts here. A project the caller cannot see
//! is reported the same way as a project that does not exist, so a service
//! maps `None` onto its `NotFound`.

use sqlx::PgPool;
use uuid::Uuid;

use crate::access_control::{EffectiveProjectAccess, ProjectRole, resolve_project_access};
use crate::auth::{IdentityPrincipal, UserPrincipal};
use crate::repository::{MembershipRepository, ProjectRepository};

/// A project the caller may see: its organization and the caller's access.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectScope {
    pub organization_id: Uuid,
    pub access: EffectiveProjectAccess,
}

/// Looks up the project's organization, then resolves the caller's access to
/// it. `None` when the project does not exist or the caller cannot see it.
pub(crate) async fn project_scope(
    pool: &PgPool,
    principal: IdentityPrincipal,
    project_id: Uuid,
) -> Result<Option<ProjectScope>, sqlx::Error> {
    let Some(organization_id) = ProjectRepository::organization_of(pool, project_id).await? else {
        return Ok(None);
    };
    let access = resolve_project_access(pool, principal, organization_id, project_id).await?;
    Ok(access.map(|access| ProjectScope {
        organization_id,
        access,
    }))
}

/// The role a tenant user holds in a project of their active organization,
/// and where it comes from: `"organization"` when the organization role
/// inherits project access, `"project"` for a project membership. `None`
/// when the user holds no role in the project.
pub(crate) async fn member_project_role(
    pool: &PgPool,
    principal: UserPrincipal,
    project_id: Uuid,
) -> Result<Option<(ProjectRole, &'static str)>, sqlx::Error> {
    if principal.role.inherits_project_access() {
        return Ok(Some((ProjectRole::Admin, "organization")));
    }
    let role = MembershipRepository::project_role(
        pool,
        principal.organization_id,
        project_id,
        principal.user_id,
    )
    .await?;
    Ok(role.and_then(|value| Some((value.parse().ok()?, "project"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_control::EffectiveAccessSource;
    use crate::auth::OrganizationRole;
    use crate::repository::test_support::{Tenant, tenant, user};

    fn identity(tenant: &Tenant, user_id: Uuid, role: OrganizationRole) -> IdentityPrincipal {
        IdentityPrincipal {
            user_id,
            session_id: Uuid::new_v4(),
            active_organization_id: Some(tenant.organization_id),
            organization_role: Some(role),
            is_super_admin: false,
            privileged_until: None,
        }
    }

    fn member(tenant: &Tenant, user_id: Uuid, role: OrganizationRole) -> UserPrincipal {
        UserPrincipal {
            user_id,
            session_id: Uuid::new_v4(),
            organization_id: tenant.organization_id,
            role,
        }
    }

    async fn plain_member(pool: &PgPool, tenant: &Tenant) -> Uuid {
        let user_id = user(pool).await;
        MembershipRepository::insert_organization_role(
            pool,
            tenant.organization_id,
            user_id,
            "member",
        )
        .await
        .unwrap();
        user_id
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_scope_names_the_organization_of_a_visible_project(pool: PgPool) {
        let tenant = tenant(&pool, "project-access-scope").await;
        let owner = identity(&tenant, Uuid::new_v4(), OrganizationRole::Owner);

        let scope = project_scope(&pool, owner, tenant.project_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(scope.organization_id, tenant.organization_id);
        assert_eq!(scope.access.role, ProjectRole::Admin);
        assert_eq!(scope.access.source, EffectiveAccessSource::Organization);

        assert!(
            project_scope(&pool, owner, Uuid::new_v4())
                .await
                .unwrap()
                .is_none()
        );

        let user_id = plain_member(&pool, &tenant).await;
        let plain = identity(&tenant, user_id, OrganizationRole::Member);
        assert!(
            project_scope(&pool, plain, tenant.project_id)
                .await
                .unwrap()
                .is_none()
        );
        MembershipRepository::insert_project_role(
            &pool,
            tenant.organization_id,
            tenant.project_id,
            user_id,
            "member",
        )
        .await
        .unwrap();
        let scope = project_scope(&pool, plain, tenant.project_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(scope.access.role, ProjectRole::Member);
        assert_eq!(scope.access.source, EffectiveAccessSource::Project);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn members_hold_a_role_only_through_inheritance_or_membership(pool: PgPool) {
        let tenant = tenant(&pool, "project-access-member").await;
        let admin = member(&tenant, Uuid::new_v4(), OrganizationRole::Admin);
        assert_eq!(
            member_project_role(&pool, admin, tenant.project_id)
                .await
                .unwrap(),
            Some((ProjectRole::Admin, "organization"))
        );

        let user_id = plain_member(&pool, &tenant).await;
        let plain = member(&tenant, user_id, OrganizationRole::Member);
        assert_eq!(
            member_project_role(&pool, plain, tenant.project_id)
                .await
                .unwrap(),
            None
        );
        MembershipRepository::insert_project_role(
            &pool,
            tenant.organization_id,
            tenant.project_id,
            user_id,
            "member",
        )
        .await
        .unwrap();
        assert_eq!(
            member_project_role(&pool, plain, tenant.project_id)
                .await
                .unwrap(),
            Some((ProjectRole::Member, "project"))
        );
    }
}
