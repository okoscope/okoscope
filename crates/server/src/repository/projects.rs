//! Project-scoped persistence.
//!
//! A project is addressed by the pair `(organization_id, id)`. The id alone is
//! unique, but every tenant-facing lookup matches both, so a caller holding the
//! wrong organization finds nothing rather than someone else's project.
//!
//! That pair used to be bound in whichever order each call site happened to
//! write its SQL — `(organization, project)` in two places and
//! `(project, organization)` in two others. Both are `Uuid`, so a swap would
//! compile and silently return `false` for every real project. The methods here
//! take them as named arguments.
//!
//! Per-project retention settings stay in [`crate::runtime_retention::settings`]
//! and [`crate::notification::retention_settings`], and the retention workers
//! advance their own watermarks, beside the code that interprets them.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgConnection, PgExecutor};
use uuid::Uuid;

use crate::repository::OrganizationRepository;

/// A project row as stored.
#[derive(Clone, Debug, FromRow, PartialEq)]
pub struct StoredProject {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub slug: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
}

/// A project held under an update lock, with the state lock-holders read.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LockedProject {
    /// Raw runtime events observed before this instant have been compacted
    /// away by retention. Work that reconciles raw evidence must not treat
    /// their absence as the absence of the behaviour they recorded.
    pub runtime_closed_before: Option<DateTime<Utc>>,
}

/// Queries against the `projects` table.
#[derive(Clone, Copy, Debug)]
pub struct ProjectRepository;

impl ProjectRepository {
    /// Reports whether the project exists within the organization.
    ///
    /// `false` covers both "no such project" and "belongs to another
    /// organization" by design; callers map both onto `404`.
    pub async fn exists_in<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE organization_id = $1 AND id = $2)",
        )
        .bind(organization_id)
        .bind(project_id)
        .fetch_one(executor)
        .await
    }

    /// Locks a project for update, taking the organization's share lock first,
    /// and returns what lock-holders need to read. `None` when the project
    /// does not exist within the organization.
    ///
    /// This is the lock order every project-scoped writer must follow:
    /// organization `FOR SHARE`, then project `FOR UPDATE`. Taking them the
    /// other way round deadlocks against a writer that follows it — resource
    /// cleanup once did, in a single `JOIN … FOR UPDATE` that locked the
    /// project first.
    ///
    /// It issues two statements, so it needs a connection rather than any
    /// executor; pass `&mut *tx`, since the locks last only as long as the
    /// transaction.
    pub async fn lock_for_update(
        conn: &mut PgConnection,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Option<LockedProject>, sqlx::Error> {
        if !OrganizationRepository::lock_shared(&mut *conn, organization_id).await? {
            return Ok(None);
        }
        let closed: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(
            "SELECT runtime_closed_before FROM projects \
             WHERE organization_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(project_id)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(closed.map(|runtime_closed_before| LockedProject {
            runtime_closed_before,
        }))
    }

    /// Creates a project in an organization, returning the stored row, or
    /// `None` when the organization does not exist.
    ///
    /// The organization check is part of the insert — `INSERT … SELECT` from
    /// `organizations` — so a project cannot be created under an organization
    /// deleted after the caller last looked. A duplicate slug within the
    /// organization fails on the unique index.
    pub async fn insert<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        slug: &str,
        name: &str,
    ) -> Result<Option<StoredProject>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO projects(id, organization_id, slug, name)
            SELECT $1, id, $3, $4 FROM organizations WHERE id = $2
            RETURNING id, organization_id, slug, name, created_at, archived_at
            "#,
        )
        .bind(id)
        .bind(organization_id)
        .bind(slug)
        .bind(name)
        .fetch_optional(executor)
        .await
    }

    /// Returns the ids of every project in an organization, ordered by id.
    ///
    /// Used where access is inherited from an organization role, so every
    /// project is visible. The order is part of the contract, since callers
    /// page over the result.
    pub async fn ids_in<'e, E>(executor: E, organization_id: Uuid) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar("SELECT id FROM projects WHERE organization_id = $1 ORDER BY id")
            .bind(organization_id)
            .fetch_all(executor)
            .await
    }

    /// Returns the organization owning the project, or `None` when no such
    /// project exists.
    ///
    /// This is the entry point for resolving a tenant from a project path
    /// segment. Callers authorize the resulting organization before using it;
    /// the lookup itself is deliberately unauthenticated, because the caller
    /// needs the organization in order to run that authorization.
    pub async fn organization_of<'e, E>(
        executor: E,
        project_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT organization_id FROM projects WHERE id = $1
            "#,
        )
        .bind(project_id)
        .fetch_optional(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::ProjectRepository;
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn seed_organization(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Projects')")
            .bind(id)
            .bind(id.to_string())
            .execute(pool)
            .await
            .unwrap();
        id
    }

    async fn seed_project(pool: &PgPool, organization: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        ProjectRepository::insert(pool, id, organization, &id.to_string(), "P")
            .await
            .unwrap()
            .expect("organization exists");
        id
    }

    /// Both arguments are `Uuid`, so a swapped pair would compile. This pins
    /// which one is which, and that the wrong organization finds nothing.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_project_exists_only_within_its_own_organization(pool: PgPool) {
        let owner = seed_organization(&pool).await;
        let other = seed_organization(&pool).await;
        let project = seed_project(&pool, owner).await;

        assert!(
            ProjectRepository::exists_in(&pool, owner, project)
                .await
                .unwrap()
        );
        assert!(
            !ProjectRepository::exists_in(&pool, other, project)
                .await
                .unwrap(),
            "another organization must not see the project"
        );
        assert!(
            !ProjectRepository::exists_in(&pool, project, owner)
                .await
                .unwrap(),
            "swapped arguments must not match"
        );
    }

    /// Creation checks the organization in the same statement, and a slug is
    /// unique within an organization but may repeat across them.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn creation_requires_the_organization_and_a_free_slug(pool: PgPool) {
        assert!(
            ProjectRepository::insert(&pool, Uuid::new_v4(), Uuid::new_v4(), "p", "P")
                .await
                .unwrap()
                .is_none(),
            "no project under an organization that does not exist"
        );

        let first = seed_organization(&pool).await;
        let second = seed_organization(&pool).await;
        let stored = ProjectRepository::insert(&pool, Uuid::new_v4(), first, "api", "API")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                stored.organization_id,
                stored.slug.as_str(),
                stored.archived_at
            ),
            (first, "api", None)
        );
        assert!(
            ProjectRepository::insert(&pool, Uuid::new_v4(), first, "api", "Again")
                .await
                .is_err(),
            "a slug repeats only across organizations"
        );
        assert!(
            ProjectRepository::insert(&pool, Uuid::new_v4(), second, "api", "API")
                .await
                .unwrap()
                .is_some()
        );
    }

    /// The lock is real — a second writer cannot take it — and a project
    /// outside the organization is not locked at all.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn locking_holds_the_project_and_reports_its_watermark(pool: PgPool) {
        let organization = seed_organization(&pool).await;
        let project = seed_project(&pool, organization).await;
        let closed = chrono::Utc::now() - chrono::Duration::days(3);
        sqlx::query("UPDATE projects SET runtime_closed_before=$2 WHERE id=$1")
            .bind(project)
            .bind(closed)
            .execute(&pool)
            .await
            .unwrap();

        let mut holder = pool.begin().await.unwrap();
        let locked = ProjectRepository::lock_for_update(&mut holder, organization, project)
            .await
            .unwrap()
            .expect("project is in the organization");
        assert_eq!(
            locked.runtime_closed_before.map(|at| at.timestamp_micros()),
            Some(closed.timestamp_micros())
        );

        let contended = sqlx::query("SELECT id FROM projects WHERE id=$1 FOR UPDATE NOWAIT")
            .bind(project)
            .execute(&pool)
            .await;
        assert!(contended.is_err(), "the project row must be held");
        holder.commit().await.unwrap();

        let mut other = pool.begin().await.unwrap();
        assert!(
            ProjectRepository::lock_for_update(&mut other, seed_organization(&pool).await, project)
                .await
                .unwrap()
                .is_none(),
            "a project outside the organization is not found"
        );
        other.commit().await.unwrap();
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn listing_is_scoped_and_ordered(pool: PgPool) {
        let organization = seed_organization(&pool).await;
        let other = seed_organization(&pool).await;
        let mut expected = Vec::new();
        for _ in 0..3 {
            expected.push(seed_project(&pool, organization).await);
        }
        seed_project(&pool, other).await;
        expected.sort();

        assert_eq!(
            ProjectRepository::ids_in(&pool, organization)
                .await
                .unwrap(),
            expected
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn resolves_the_owning_organization(pool: PgPool) {
        let organization = Uuid::new_v4();
        let project = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Repository')")
            .bind(organization)
            .bind(organization.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','P')")
            .bind(project)
            .bind(organization)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            ProjectRepository::organization_of(&pool, project)
                .await
                .unwrap(),
            Some(organization)
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn reports_an_unknown_project_as_absent(pool: PgPool) {
        assert_eq!(
            ProjectRepository::organization_of(&pool, Uuid::new_v4())
                .await
                .unwrap(),
            None
        );
    }
}
