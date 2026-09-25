use chrono::Utc;
use server::{
    access_control::{EffectiveAccessSource, ProjectRole, resolve_project_access},
    auth::{IdentityPrincipal, OrganizationRole},
};
use uuid::Uuid;

/// Every project route family: the route is in the handler, the project
/// access check in the service it calls, through `service::project_access`.
const SERVICE_ROUTE_SOURCES: &[(&str, &str, &str)] = &[
    (
        include_str!("../src/releases.rs"),
        include_str!("../src/service/releases.rs"),
        "/releases",
    ),
    (
        include_str!("../src/access_api.rs"),
        include_str!("../src/service/access.rs"),
        "/api/v1/projects/{project_id}/members",
    ),
    (
        include_str!("../src/invitation_api.rs"),
        include_str!("../src/service/invitations.rs"),
        "/api/v1/projects/{project_id}/invitations",
    ),
    (
        include_str!("../src/inventory_api.rs"),
        include_str!("../src/service/inventory.rs"),
        "/runtime-inventory",
    ),
    (
        include_str!("../src/dns_group_api.rs"),
        include_str!("../src/service/dns_groups.rs"),
        "/runtime-inventory/dns-groups",
    ),
    (
        include_str!("../src/attention.rs"),
        include_str!("../src/service/attention.rs"),
        "/api/v1/attention-summary",
    ),
    (
        include_str!("../src/resources.rs"),
        include_str!("../src/service/resources.rs"),
        "/resources",
    ),
    (
        include_str!("../src/policy_api.rs"),
        include_str!("../src/service/policies.rs"),
        "/policies",
    ),
    (
        include_str!("../src/api.rs"),
        include_str!("../src/service/runtime_groups.rs"),
        "/api/v1/runtime-groups",
    ),
    (
        include_str!("../src/notification/api.rs"),
        include_str!("../src/service/notifications.rs"),
        "/webhook-destinations",
    ),
    (
        include_str!("../src/notification/retention_api.rs"),
        include_str!("../src/service/retention.rs"),
        "/notification-retention",
    ),
    (
        include_str!("../src/runtime_retention/api.rs"),
        include_str!("../src/service/retention.rs"),
        "/runtime-retention",
    ),
];

#[test]
fn every_descendant_route_family_has_a_project_access_seam() {
    for (handler, service, route_family) in SERVICE_ROUTE_SOURCES {
        assert!(
            handler.contains(route_family),
            "missing route family {route_family}"
        );
        assert!(
            service.contains("project_scope(") || service.contains("resolve_project_access"),
            "{route_family} bypasses the common project resolver"
        );
    }
    let shared = include_str!("../src/service/project_access.rs");
    assert!(
        shared.contains("resolve_project_access(pool, principal, organization_id, project_id)")
    );
    let attention = include_str!("../src/service/attention.rs");
    assert!(attention.contains("project_ids"));
    let attention_queries = include_str!("../src/repository/attention.rs");
    assert!(attention_queries.contains("project_id=ANY($2)"));
}

fn principal(
    user_id: Uuid,
    organization_id: Option<Uuid>,
    role: Option<OrganizationRole>,
    is_super_admin: bool,
) -> IdentityPrincipal {
    IdentityPrincipal {
        user_id,
        session_id: Uuid::new_v4(),
        active_organization_id: organization_id,
        organization_role: role,
        is_super_admin,
        privileged_until: Some(Utc::now()),
    }
}

async fn insert_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let password_hash = server::auth::hash_password("project-access-test-password").unwrap();
    sqlx::query(
        "INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,$3,now())",
    )
    .bind(id)
    .bind(format!("{id}@example.test"))
    .bind(password_hash)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn effective_access_matrix_is_tenant_safe(pool: sqlx::PgPool) {
    let organization_id = Uuid::new_v4();
    let foreign_organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Access')")
        .bind(organization_id)
        .bind(organization_id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Foreign')")
        .bind(foreign_organization_id)
        .bind(foreign_organization_id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'project','Project')",
    )
    .bind(project_id)
    .bind(organization_id)
    .execute(&pool)
    .await
    .unwrap();
    let owner = insert_user(&pool).await;
    let member = insert_user(&pool).await;
    for (user_id, role) in [(owner, "owner"), (member, "member")] {
        sqlx::query(
            "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(role)
        .execute(&pool)
        .await
        .unwrap();
    }
    let inherited = resolve_project_access(
        &pool,
        principal(
            owner,
            Some(organization_id),
            Some(OrganizationRole::Owner),
            false,
        ),
        organization_id,
        project_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(inherited.source, EffectiveAccessSource::Organization);
    assert_eq!(inherited.role, ProjectRole::Admin);
    assert!(
        resolve_project_access(
            &pool,
            principal(
                member,
                Some(organization_id),
                Some(OrganizationRole::Member),
                false
            ),
            organization_id,
            project_id,
        )
        .await
        .unwrap()
        .is_none()
    );
    sqlx::query("INSERT INTO project_memberships(organization_id,project_id,user_id,role) VALUES($1,$2,$3,'member')")
        .bind(organization_id)
        .bind(project_id)
        .bind(member)
        .execute(&pool)
        .await
        .unwrap();
    let assigned = resolve_project_access(
        &pool,
        principal(
            member,
            Some(organization_id),
            Some(OrganizationRole::Member),
            false,
        ),
        organization_id,
        project_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(assigned.source, EffectiveAccessSource::Project);
    assert_eq!(assigned.role, ProjectRole::Member);
    assert!(
        resolve_project_access(
            &pool,
            principal(
                member,
                Some(foreign_organization_id),
                Some(OrganizationRole::Member),
                false
            ),
            organization_id,
            project_id,
        )
        .await
        .unwrap()
        .is_none()
    );
    let platform = resolve_project_access(
        &pool,
        principal(Uuid::new_v4(), None, None, true),
        organization_id,
        project_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(platform.source, EffectiveAccessSource::Platform);
}
