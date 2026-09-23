//! Application-scoped persistence.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Scalar subqueries aggregating a project's applications.
///
/// Fragments rather than methods for the same reason as
/// [`crate::repository::event_groups::aggregates`]: callers embed them in a
/// paginated project listing, and a method would issue a query per row.
pub mod aggregates {
    /// Counts the applications of a project. Expects `projects` aliased as `p`.
    ///
    /// Carries the full tenant path. One of its two call sites matched on
    /// `project_id` alone; the composite foreign key makes that equivalent, so
    /// the count does not change, but a reader no longer needs the schema to
    /// see that it is scoped.
    pub const COUNT_FOR_PROJECT: &str = "(SELECT count(*) FROM applications a \
         WHERE a.organization_id=p.organization_id AND a.project_id=p.id)";
}

/// An application row as stored.
#[derive(Clone, Debug, FromRow, PartialEq)]
pub struct StoredApplication {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub slug: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// Queries against the `applications` table.
///
/// Every lookup takes the full tenant path (organization, project,
/// application). Narrowing a lookup to fewer than all three columns would let
/// a caller reach an application owned by another tenant, so the repository
/// does not expose such a query.
///
/// Creation is the one place that takes less: it names the project and takes
/// the organization from the project's own row, so the two can never disagree.
#[derive(Clone, Copy, Debug)]
pub struct ApplicationRepository;

impl ApplicationRepository {
    /// Records an application, or renames the project's one with this slug,
    /// and returns its id.
    pub async fn upsert_by_slug<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        slug: &str,
        name: &str,
    ) -> Result<Uuid, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("INSERT INTO applications (id, organization_id, project_id, slug, name) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (project_id, slug) DO UPDATE SET name = EXCLUDED.name RETURNING id")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(slug)
            .bind(name)
            .fetch_one(executor)
            .await
    }

    /// The project's first 200 applications, oldest first.
    ///
    /// Selects `id`, `organization_id`, `project_id`, `slug`, `name` and
    /// `created_at`.
    pub async fn summaries<'e, E, T>(executor: E, project_id: Uuid) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,organization_id,project_id,slug,name,created_at FROM applications WHERE project_id=$1 ORDER BY created_at,id LIMIT 200")
            .bind(project_id)
            .fetch_all(executor)
            .await
    }

    /// One application of the project with the columns of
    /// [`Self::summaries`].
    pub async fn summary<'e, E, T>(
        executor: E,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,organization_id,project_id,slug,name,created_at FROM applications WHERE project_id=$1 AND id=$2")
            .bind(project_id)
            .bind(application_id)
            .fetch_optional(executor)
            .await
    }

    /// The organization of an application of the project.
    pub async fn organization_of<'e, E>(
        executor: E,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT organization_id FROM applications WHERE project_id=$1 AND id=$2",
        )
        .bind(project_id)
        .bind(application_id)
        .fetch_optional(executor)
        .await
    }

    /// A page of the project's applications by id, after the cursor when one
    /// is given, for platform administration, with their release and runtime
    /// group counts and latest observation.
    ///
    /// Selects `id`, `project_id`, `slug`, `name`, `created_at`,
    /// `release_count`, `runtime_group_count` and `latest_observed_at`.
    pub async fn platform_page<'e, E, T>(
        executor: E,
        project_id: Uuid,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as(&format!("SELECT a.id,a.project_id,a.slug,a.name,a.created_at,{} release_count,{} runtime_group_count,{} latest_observed_at FROM applications a WHERE a.project_id=$1 AND ($2::uuid IS NULL OR a.id>$2) ORDER BY a.id LIMIT $3", crate::repository::releases::aggregates::COUNT_FOR_APPLICATION, crate::repository::event_groups::aggregates::COUNT_ALL_FOR_APPLICATION,crate::repository::event_groups::aggregates::LATEST_SEEN_ALL_FOR_APPLICATION))
            .bind(project_id)
            .bind(cursor)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// Creates an application in a project, returning the stored row, or
    /// `None` when the project does not exist.
    ///
    /// The organization comes from the project row in the same statement.
    /// Supplying it separately would allow a mismatched pair, which the
    /// composite foreign key would reject as an internal error; deriving it
    /// makes that pair unrepresentable, and a project deleted after the caller
    /// looked yields `None` rather than a constraint violation. A duplicate
    /// slug within the project fails on the unique index.
    pub async fn insert<'e, E>(
        executor: E,
        id: Uuid,
        project_id: Uuid,
        slug: &str,
        name: &str,
    ) -> Result<Option<StoredApplication>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO applications(id, organization_id, project_id, slug, name)
            SELECT $1, organization_id, id, $3, $4 FROM projects WHERE id = $2
            RETURNING id, organization_id, project_id, slug, name, created_at
            "#,
        )
        .bind(id)
        .bind(project_id)
        .bind(slug)
        .bind(name)
        .fetch_optional(executor)
        .await
    }

    /// Reports whether the application exists within the given tenant scope.
    ///
    /// A `false` result is indistinguishable from "exists but belongs to
    /// another tenant" by design: callers map both onto `404` so that the API
    /// does not disclose the existence of other tenants' applications.
    pub async fn exists<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM applications
                WHERE organization_id = $1
                  AND project_id = $2
                  AND id = $3
            )
            "#,
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(application_id)
        .fetch_one(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{ApplicationRepository, aggregates};
    use crate::repository::ProjectRepository;
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn seed_project(pool: &PgPool) -> (Uuid, Uuid) {
        let organization = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Applications')")
            .bind(organization)
            .bind(organization.to_string())
            .execute(pool)
            .await
            .unwrap();
        let project = Uuid::new_v4();
        ProjectRepository::insert(pool, project, organization, &project.to_string(), "P")
            .await
            .unwrap()
            .unwrap();
        (organization, project)
    }

    /// Creation takes the organization from the project, so the stored pair
    /// always agrees, and a missing project yields `None` rather than a
    /// constraint violation.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn creation_derives_the_organization_from_the_project(pool: PgPool) {
        let (organization, project) = seed_project(&pool).await;
        let stored = ApplicationRepository::insert(&pool, Uuid::new_v4(), project, "api", "API")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (stored.organization_id, stored.project_id),
            (organization, project)
        );

        assert!(
            ApplicationRepository::insert(&pool, Uuid::new_v4(), Uuid::new_v4(), "api", "API")
                .await
                .unwrap()
                .is_none(),
            "no application under a project that does not exist"
        );
    }

    /// A slug is unique within a project and may repeat across projects.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_slug_is_unique_within_its_project(pool: PgPool) {
        let (_, first) = seed_project(&pool).await;
        let (_, second) = seed_project(&pool).await;
        ApplicationRepository::insert(&pool, Uuid::new_v4(), first, "api", "API")
            .await
            .unwrap()
            .unwrap();
        assert!(
            ApplicationRepository::insert(&pool, Uuid::new_v4(), first, "api", "Again")
                .await
                .is_err()
        );
        assert!(
            ApplicationRepository::insert(&pool, Uuid::new_v4(), second, "api", "API")
                .await
                .unwrap()
                .is_some()
        );
    }

    /// The tenant path is three `Uuid`s, and ingestion used to bind them in
    /// the reverse order from this method. Any permutation other than the
    /// right one must fail to match.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn only_the_right_argument_order_matches(pool: PgPool) {
        let (organization, project) = seed_project(&pool).await;
        let application = ApplicationRepository::insert(&pool, Uuid::new_v4(), project, "a", "A")
            .await
            .unwrap()
            .unwrap()
            .id;

        assert!(
            ApplicationRepository::exists(&pool, organization, project, application)
                .await
                .unwrap()
        );
        for (a, b, c) in [
            (application, project, organization),
            (project, organization, application),
            (organization, application, project),
        ] {
            assert!(
                !ApplicationRepository::exists(&pool, a, b, c).await.unwrap(),
                "a permuted tenant path must not match"
            );
        }
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_count_fragment_counts_a_projects_applications(pool: PgPool) {
        let (_, project) = seed_project(&pool).await;
        let (_, other) = seed_project(&pool).await;
        for slug in ["a", "b"] {
            ApplicationRepository::insert(&pool, Uuid::new_v4(), project, slug, slug)
                .await
                .unwrap()
                .unwrap();
        }
        ApplicationRepository::insert(&pool, Uuid::new_v4(), other, "c", "c")
            .await
            .unwrap()
            .unwrap();

        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT {} FROM projects p WHERE p.id=$1",
            aggregates::COUNT_FOR_PROJECT
        ))
        .bind(project)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 2);
    }

    async fn seed(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
        let organization = Uuid::new_v4();
        let project = Uuid::new_v4();
        let application = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Repository')")
            .bind(organization)
            .bind(organization.to_string())
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','P')")
            .bind(project)
            .bind(organization)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO applications(id,organization_id,project_id,slug,name) VALUES($1,$2,$3,'a','A')",
        )
        .bind(application)
        .bind(organization)
        .bind(project)
        .execute(pool)
        .await
        .unwrap();
        (organization, project, application)
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn exists_within_the_owning_tenant(pool: PgPool) {
        let (organization, project, application) = seed(&pool).await;
        assert!(
            ApplicationRepository::exists(&pool, organization, project, application)
                .await
                .unwrap()
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn hides_an_application_from_a_foreign_tenant(pool: PgPool) {
        let (organization, project, application) = seed(&pool).await;
        let (other_organization, other_project, _) = seed(&pool).await;

        // A mismatch in any segment of the tenant path must read as absent,
        // otherwise one tenant could probe another tenant's identifiers.
        assert!(
            !ApplicationRepository::exists(&pool, other_organization, project, application)
                .await
                .unwrap()
        );
        assert!(
            !ApplicationRepository::exists(&pool, organization, other_project, application)
                .await
                .unwrap()
        );
        assert!(
            !ApplicationRepository::exists(&pool, organization, project, Uuid::new_v4())
                .await
                .unwrap()
        );
    }
}

#[cfg(test)]
mod platform_statement_tests {
    use chrono::{DateTime, Utc};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::ApplicationRepository;
    use crate::repository::test_support::{exec, ingest, manual_release, tenant};

    #[derive(Debug, FromRow)]
    struct PlatformApplication {
        id: Uuid,
        release_count: i64,
        runtime_group_count: i64,
        latest_observed_at: Option<DateTime<Utc>>,
    }

    #[derive(Debug, FromRow)]
    struct Application {
        id: Uuid,
        organization_id: Uuid,
        slug: String,
    }

    /// Platform pages carry release and runtime group counts and the latest
    /// observation; the summaries list a project's applications oldest first;
    /// single reads stay within the project.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn applications_page_list_and_resolve(pool: PgPool) {
        let own = tenant(&pool, "applications-platform").await;
        let other = tenant(&pool, "applications-platform-other").await;
        manual_release(&pool, &own, "v1", Utc::now()).await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let quiet =
            ApplicationRepository::insert(&pool, Uuid::new_v4(), own.project_id, "quiet", "Quiet")
                .await
                .unwrap()
                .unwrap()
                .id;
        let mut by_id = vec![own.application_id, quiet];
        by_id.sort();

        let page: Vec<PlatformApplication> =
            ApplicationRepository::platform_page(&pool, own.project_id, None, 10)
                .await
                .unwrap();
        assert_eq!(page.iter().map(|a| a.id).collect::<Vec<_>>(), by_id);
        let busy = page.iter().find(|a| a.id == own.application_id).unwrap();
        assert_eq!((busy.release_count, busy.runtime_group_count), (1, 1));
        assert!(busy.latest_observed_at.is_some());
        let idle = page.iter().find(|a| a.id == quiet).unwrap();
        assert_eq!((idle.release_count, idle.runtime_group_count), (0, 0));
        assert!(idle.latest_observed_at.is_none());
        let after: Vec<PlatformApplication> =
            ApplicationRepository::platform_page(&pool, own.project_id, Some(by_id[0]), 10)
                .await
                .unwrap();
        assert_eq!(after.iter().map(|a| a.id).collect::<Vec<_>>(), by_id[1..]);

        let listed: Vec<Application> = ApplicationRepository::summaries(&pool, own.project_id)
            .await
            .unwrap();
        assert_eq!(
            listed.iter().map(|a| a.id).collect::<Vec<_>>(),
            [own.application_id, quiet]
        );
        let one: Application = ApplicationRepository::summary(&pool, own.project_id, quiet)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (one.organization_id, one.slug.as_str()),
            (own.organization_id, "quiet")
        );
        assert!(
            ApplicationRepository::summary::<_, Application>(&pool, other.project_id, quiet)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            ApplicationRepository::organization_of(&pool, own.project_id, quiet)
                .await
                .unwrap(),
            Some(own.organization_id)
        );
        assert_eq!(
            ApplicationRepository::organization_of(&pool, other.project_id, quiet)
                .await
                .unwrap(),
            None
        );
    }
}
