//! Membership persistence: who belongs to an organization or a project, and
//! in what role.
//!
//! These rows decide authorization, so the predicates that read them are the
//! ones [`crate::repository`] exists to hold. Two of them were restated
//! verbatim in separate modules — the project-role lookup that
//! [`crate::navigation`] and [`crate::access_control`] each spelled out, and
//! the organization-role lookup that additionally requires the organization to
//! be active.
//!
//! # What is not here, and why
//!
//! Three membership checks stay where they are, embedded in larger statements:
//! the session guard in [`crate::auth`], the application-visibility check in
//! [`crate::agent_health`], and the sign-in projection in
//! [`crate::user_auth`]. Unlike the tenant predicates in
//! [`crate::repository::users`], these correlate through positional
//! parameters — `$5` in one statement, `$3` in another — and through columns
//! of the enclosing query. A shared fragment cannot carry a parameter index,
//! so extracting them would mean a string that only reads correctly at one
//! call site, which is worse than the duplication it removes.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Queries against `organization_memberships` and `project_memberships`.
#[derive(Clone, Copy, Debug)]
pub struct MembershipRepository;

impl MembershipRepository {
    /// Returns the user's role in the project, or `None` when they hold no
    /// membership of their own.
    ///
    /// `None` is not "no access": a user who inherits project access from an
    /// organization role has no row here, and callers resolve that before
    /// asking. It means only that there is no direct grant.
    ///
    /// All three columns are matched. Narrowing to `project_id` alone would
    /// still identify the project, since the id is unique, but it would let a
    /// mismatched organization pass unnoticed if a future caller supplies one.
    pub async fn project_role<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT role FROM project_memberships
            WHERE organization_id = $1
              AND project_id = $2
              AND user_id = $3
            "#,
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(user_id)
        .fetch_optional(executor)
        .await
    }

    /// Returns the user's role in the organization, provided the organization
    /// is active.
    ///
    /// The status join is part of the authorization decision, not a detail of
    /// the query. An organization awaiting its first owner, or one being torn
    /// down, still has membership rows; treating those as grants would let a
    /// member act inside an organization that is not yet, or no longer, in
    /// service. A caller wanting the role regardless of status is asking a
    /// different question and needs a different method.
    pub async fn organization_role_when_active<'e, E>(
        executor: E,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> Result<Option<String>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT m.role FROM organization_memberships m
            JOIN organizations o ON o.id = m.organization_id
            WHERE m.user_id = $1
              AND m.organization_id = $2
              AND o.status = 'active'
            "#,
        )
        .bind(user_id)
        .bind(organization_id)
        .fetch_optional(executor)
        .await
    }

    /// Returns the projects within an organization the user holds a direct
    /// membership of, ordered by id.
    ///
    /// The order is part of the contract: callers page over the result, and an
    /// unordered scan would let rows repeat or vanish between pages.
    pub async fn accessible_project_ids<'e, E>(
        executor: E,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT project_id FROM project_memberships
            WHERE organization_id = $1 AND user_id = $2
            ORDER BY project_id
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_all(executor)
        .await
    }

    /// Counts the owners of an organization.
    ///
    /// Used to refuse the removal or demotion that would leave an organization
    /// with none. This counts rows, not people who can act: an owner whose
    /// account is disabled still holds the role, and still keeps the
    /// organization from becoming ownerless. That is deliberately weaker than
    /// [`crate::repository::users::UserRepository::active_organization_owners`],
    /// which addresses mail and must not write to an account nobody can use.
    pub async fn organization_owner_count<'e, E>(
        executor: E,
        organization_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT count(*) FROM organization_memberships
            WHERE organization_id = $1 AND role = 'owner'
            "#,
        )
        .bind(organization_id)
        .fetch_one(executor)
        .await
    }

    /// Grants an organization role, failing if the user already holds one.
    ///
    /// The primary key rejects a duplicate, and the caller reports that as a
    /// conflict. Use [`Self::grant_organization_role_if_absent`] where a repeat
    /// is expected rather than an error.
    pub async fn insert_organization_role<'e, E>(
        executor: E,
        organization_id: Uuid,
        user_id: Uuid,
        role: &str,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            INSERT INTO organization_memberships(organization_id, user_id, role)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(role)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Grants an organization role, leaving an existing one untouched.
    ///
    /// Accepting an invitation takes this path: the invitation may name a role
    /// the user already holds, and re-accepting must not fail, nor silently
    /// change a role the invitation was not issued to change.
    pub async fn grant_organization_role_if_absent<'e, E>(
        executor: E,
        organization_id: Uuid,
        user_id: Uuid,
        role: &str,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            INSERT INTO organization_memberships(organization_id, user_id, role)
            VALUES ($1, $2, $3)
            ON CONFLICT (organization_id, user_id) DO NOTHING
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(role)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Grants a project role, failing if the user already holds one.
    ///
    /// A project membership requires an organization membership: the foreign
    /// key `project_memberships_organization_id_user_id_fkey` refuses a row
    /// whose `(organization_id, user_id)` pair has none. Callers granting both
    /// must do so in that order, which is why accepting a project invitation
    /// grants the organization role first.
    pub async fn insert_project_role<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        user_id: Uuid,
        role: &str,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            INSERT INTO project_memberships(organization_id, project_id, user_id, role)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(user_id)
        .bind(role)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Grants a project role, leaving an existing one untouched.
    ///
    /// Subject to the same ordering requirement as [`Self::insert_project_role`].
    pub async fn grant_project_role_if_absent<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        user_id: Uuid,
        role: &str,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            INSERT INTO project_memberships(organization_id, project_id, user_id, role)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (project_id, user_id) DO NOTHING
            "#,
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(user_id)
        .bind(role)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Revokes an organization membership, reporting whether one was removed.
    pub async fn remove_organization_role<'e, E>(
        executor: E,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        Ok(sqlx::query(
            r#"
            DELETE FROM organization_memberships
            WHERE organization_id = $1 AND user_id = $2
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(executor)
        .await?
        .rows_affected()
            > 0)
    }

    /// Revokes a project membership, reporting whether one was removed.
    pub async fn remove_project_role<'e, E>(
        executor: E,
        project_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        Ok(sqlx::query(
            r#"
            DELETE FROM project_memberships
            WHERE project_id = $1 AND user_id = $2
            "#,
        )
        .bind(project_id)
        .bind(user_id)
        .execute(executor)
        .await?
        .rows_affected()
            > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::MembershipRepository;
    use sqlx::PgPool;
    use uuid::Uuid;

    struct Fixture {
        organization: Uuid,
        project: Uuid,
        user: Uuid,
    }

    async fn seed(pool: &PgPool, status: &str) -> Fixture {
        let fixture = Fixture {
            organization: Uuid::new_v4(),
            project: Uuid::new_v4(),
            user: Uuid::new_v4(),
        };
        sqlx::query("INSERT INTO organizations(id,slug,name,status) VALUES($1,$2,'Members',$3)")
            .bind(fixture.organization)
            .bind(fixture.organization.to_string())
            .bind(status)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','P')")
            .bind(fixture.project)
            .bind(fixture.organization)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,$3,now())",
        )
        .bind(fixture.user)
        .bind(format!("{}@example.test", fixture.user))
        .bind("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$0123456789abcdef")
        .execute(pool)
        .await
        .unwrap();
        fixture
    }

    /// A project membership is refused without an organization membership for
    /// the same pair, so tests that grant one start here.
    async fn join_organization(pool: &PgPool, fixture: &Fixture) {
        MembershipRepository::insert_organization_role(
            pool,
            fixture.organization,
            fixture.user,
            "member",
        )
        .await
        .unwrap();
    }

    /// All three columns are matched, so a membership cannot be read through a
    /// tenant path it does not belong to.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_project_role_is_visible_only_through_its_own_tenant_path(pool: PgPool) {
        let fixture = seed(&pool, "active").await;
        join_organization(&pool, &fixture).await;
        MembershipRepository::insert_project_role(
            &pool,
            fixture.organization,
            fixture.project,
            fixture.user,
            "admin",
        )
        .await
        .unwrap();

        assert_eq!(
            MembershipRepository::project_role(
                &pool,
                fixture.organization,
                fixture.project,
                fixture.user
            )
            .await
            .unwrap(),
            Some("admin".to_owned())
        );
        assert_eq!(
            MembershipRepository::project_role(
                &pool,
                Uuid::new_v4(),
                fixture.project,
                fixture.user
            )
            .await
            .unwrap(),
            None,
            "a mismatched organization must not resolve the membership"
        );
        assert_eq!(
            MembershipRepository::project_role(
                &pool,
                fixture.organization,
                fixture.project,
                Uuid::new_v4()
            )
            .await
            .unwrap(),
            None
        );
    }

    /// The organization's status is part of the authorization decision. A
    /// membership of an organization awaiting its first owner is not a grant.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_membership_of_an_inactive_organization_is_not_a_role(pool: PgPool) {
        let fixture = seed(&pool, "pending_owner").await;
        MembershipRepository::insert_organization_role(
            &pool,
            fixture.organization,
            fixture.user,
            "owner",
        )
        .await
        .unwrap();

        assert_eq!(
            MembershipRepository::organization_role_when_active(
                &pool,
                fixture.user,
                fixture.organization
            )
            .await
            .unwrap(),
            None,
            "a pending organization must not confer a role"
        );

        sqlx::query("UPDATE organizations SET status='active' WHERE id=$1")
            .bind(fixture.organization)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            MembershipRepository::organization_role_when_active(
                &pool,
                fixture.user,
                fixture.organization
            )
            .await
            .unwrap(),
            Some("owner".to_owned()),
            "the same row confers the role once the organization is active"
        );
    }

    /// The owner count guards against an ownerless organization, so it counts
    /// rows rather than people who can act. An owner whose account is disabled
    /// still holds the role — this is deliberately weaker than the user
    /// repository's mail-addressing query, and the two must not be conflated.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_owner_count_includes_an_owner_who_cannot_act(pool: PgPool) {
        let fixture = seed(&pool, "active").await;
        MembershipRepository::insert_organization_role(
            &pool,
            fixture.organization,
            fixture.user,
            "owner",
        )
        .await
        .unwrap();
        assert_eq!(
            MembershipRepository::organization_owner_count(&pool, fixture.organization)
                .await
                .unwrap(),
            1
        );

        // The database refuses to disable the only owner — protect_user_authority
        // in migration 0027 guards that the same way the super-administrator
        // trigger does — so a second owner is needed to observe the difference.
        let second = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,$3,now())",
        )
        .bind(second)
        .bind(format!("{second}@example.test"))
        .bind("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$0123456789abcdef")
        .execute(&pool)
        .await
        .unwrap();
        MembershipRepository::insert_organization_role(
            &pool,
            fixture.organization,
            second,
            "owner",
        )
        .await
        .unwrap();
        sqlx::query("UPDATE users SET disabled_at=now() WHERE id=$1")
            .bind(fixture.user)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            MembershipRepository::organization_owner_count(&pool, fixture.organization)
                .await
                .unwrap(),
            2,
            "a disabled owner still keeps the organization from being ownerless"
        );
        assert_eq!(
            crate::repository::UserRepository::active_organization_owners(
                &pool,
                fixture.organization
            )
            .await
            .unwrap()
            .len(),
            1,
            "but is no longer addressable, which is the other query's job"
        );
    }

    /// The two grant paths differ only in what they do about an existing row:
    /// one reports a conflict, the other leaves the role as it stands. An
    /// invitation naming a role the user already holds must not silently
    /// change it.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn granting_if_absent_never_overwrites_an_existing_role(pool: PgPool) {
        let fixture = seed(&pool, "active").await;
        MembershipRepository::insert_organization_role(
            &pool,
            fixture.organization,
            fixture.user,
            "owner",
        )
        .await
        .unwrap();

        assert!(
            MembershipRepository::insert_organization_role(
                &pool,
                fixture.organization,
                fixture.user,
                "member"
            )
            .await
            .is_err(),
            "a plain insert must report the duplicate"
        );

        MembershipRepository::grant_organization_role_if_absent(
            &pool,
            fixture.organization,
            fixture.user,
            "member",
        )
        .await
        .unwrap();
        assert_eq!(
            MembershipRepository::organization_role_when_active(
                &pool,
                fixture.user,
                fixture.organization
            )
            .await
            .unwrap(),
            Some("owner".to_owned()),
            "the existing role must survive an if-absent grant"
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn accessible_projects_are_scoped_and_ordered(pool: PgPool) {
        let fixture = seed(&pool, "active").await;
        join_organization(&pool, &fixture).await;
        let mut expected = vec![fixture.project];
        for _ in 0..2 {
            let project = Uuid::new_v4();
            sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,$3,'P')")
                .bind(project)
                .bind(fixture.organization)
                .bind(project.to_string())
                .execute(&pool)
                .await
                .unwrap();
            expected.push(project);
        }
        for project in &expected {
            MembershipRepository::insert_project_role(
                &pool,
                fixture.organization,
                *project,
                fixture.user,
                "member",
            )
            .await
            .unwrap();
        }
        expected.sort();

        assert_eq!(
            MembershipRepository::accessible_project_ids(&pool, fixture.organization, fixture.user)
                .await
                .unwrap(),
            expected,
            "paging callers depend on the order"
        );
        assert!(
            MembershipRepository::accessible_project_ids(&pool, Uuid::new_v4(), fixture.user)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn removal_reports_whether_anything_was_revoked(pool: PgPool) {
        let fixture = seed(&pool, "active").await;
        join_organization(&pool, &fixture).await;
        MembershipRepository::insert_project_role(
            &pool,
            fixture.organization,
            fixture.project,
            fixture.user,
            "member",
        )
        .await
        .unwrap();

        assert!(
            MembershipRepository::remove_project_role(&pool, fixture.project, fixture.user)
                .await
                .unwrap()
        );
        assert!(
            !MembershipRepository::remove_project_role(&pool, fixture.project, fixture.user)
                .await
                .unwrap(),
            "removing an absent membership reports false rather than failing"
        );
    }
}
