//! Navigation reads: the organization a user is in, its projects and
//! applications with their summary counts, and the agents reporting runtime
//! events for an application.
//!
//! Every statement here is scoped by the caller's organization, and the
//! project and application listings page by `(created_at, id)`. The row shapes
//! belong to the navigation endpoints, so the listing methods are generic over
//! the row type and document the columns they select.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::repository::event_groups::aggregates;

/// Reads behind the tenant navigation endpoints.
#[derive(Clone, Copy, Debug)]
pub struct NavigationRepository;

impl NavigationRepository {
    /// The organization's `id`, `slug`, `name` and `created_at`.
    pub async fn organization<'e, E, T>(
        executor: E,
        organization_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,slug,name,created_at FROM organizations WHERE id=$1")
            .bind(organization_id)
            .fetch_optional(executor)
            .await
    }

    /// A page of the organization's projects ordered by `(created_at, id)`,
    /// after the cursor when one is given.
    ///
    /// Selects `id`, `slug`, `name`, `created_at`, `archived_at`,
    /// `application_count` and `runtime_group_count`.
    pub async fn project_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        cursor_created_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as(&format!("SELECT p.id,p.slug,p.name,p.created_at,p.archived_at,{} application_count,{} runtime_group_count FROM projects p WHERE p.organization_id=$1 AND ($2::timestamptz IS NULL OR (p.created_at,p.id)>($2,$3)) ORDER BY p.created_at,p.id LIMIT $4", crate::repository::applications::aggregates::COUNT_FOR_PROJECT, aggregates::COUNT_ALL_FOR_PROJECT))
            .bind(organization_id)
            .bind(cursor_created_at)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// One project with the same columns as [`Self::project_page`].
    pub async fn project<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as(&format!("SELECT p.id,p.slug,p.name,p.created_at,p.archived_at,{} application_count,{} runtime_group_count FROM projects p WHERE p.organization_id=$1 AND p.id=$2", crate::repository::applications::aggregates::COUNT_FOR_PROJECT, aggregates::COUNT_ALL_FOR_PROJECT))
            .bind(organization_id)
            .bind(project_id)
            .fetch_optional(executor)
            .await
    }

    /// A page of a project's applications ordered by `(created_at, id)`,
    /// after the cursor when one is given.
    ///
    /// Selects `id`, `project_id`, `slug`, `name`, `created_at`,
    /// `release_count`, `runtime_group_count` and `latest_observed_at`.
    pub async fn application_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        cursor_created_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as(&format!("SELECT a.id,a.project_id,a.slug,a.name,a.created_at,{} release_count,{} runtime_group_count,{} latest_observed_at FROM applications a WHERE a.organization_id=$1 AND a.project_id=$2 AND ($3::timestamptz IS NULL OR (a.created_at,a.id)>($3,$4)) ORDER BY a.created_at,a.id LIMIT $5", crate::repository::releases::aggregates::COUNT_FOR_APPLICATION, aggregates::COUNT_WITH_EVIDENCE_FOR_APPLICATION,aggregates::LATEST_SEEN_WITH_EVIDENCE_FOR_APPLICATION))
            .bind(organization_id)
            .bind(project_id)
            .bind(cursor_created_at)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// One application with the same columns as [`Self::application_page`].
    pub async fn application<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as(&format!("SELECT a.id,a.project_id,a.slug,a.name,a.created_at,{} release_count,{} runtime_group_count,{} latest_observed_at FROM applications a WHERE a.organization_id=$1 AND a.project_id=$2 AND a.id=$3", crate::repository::releases::aggregates::COUNT_FOR_APPLICATION, aggregates::COUNT_WITH_EVIDENCE_FOR_APPLICATION,aggregates::LATEST_SEEN_WITH_EVIDENCE_FOR_APPLICATION))
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_optional(executor)
            .await
    }

    /// Reports whether a worker-page cursor names an agent of this application
    /// whose latest event is exactly at the cursor's time.
    pub async fn worker_cursor_is_valid<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        agent_id: Uuid,
        last_observed_at: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM runtime_events WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND agent_id=$4 GROUP BY agent_id HAVING max(observed_at)=$5)")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(agent_id)
            .bind(last_observed_at)
            .fetch_one(executor)
            .await
    }

    /// A page of the agents that reported events for an application, most
    /// recently observed first, after the cursor when one is given.
    ///
    /// Selects the agent's identity and its `first_observed_at` and
    /// `last_observed_at` over the application's events.
    pub async fn worker_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cursor_last_observed_at: Option<DateTime<Utc>>,
        cursor_agent_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH observed AS (SELECT agent_id,min(observed_at) first_observed_at,max(observed_at) last_observed_at FROM runtime_events WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 GROUP BY agent_id) SELECT a.id agent_id,a.cluster_id,c.name cluster_name,a.node_name,a.agent_version,a.architecture,a.kernel_release,o.first_observed_at,o.last_observed_at,a.last_seen_at agent_last_seen_at FROM observed o JOIN agents a ON a.organization_id=$1 AND a.id=o.agent_id JOIN clusters c ON c.organization_id=$1 AND c.id=a.cluster_id WHERE ($4::timestamptz IS NULL OR (o.last_observed_at,o.agent_id)<($4,$5)) ORDER BY o.last_observed_at DESC,o.agent_id DESC LIMIT $6")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cursor_last_observed_at)
            .bind(cursor_agent_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// Resolves a project id used as a cursor into its `(created_at, id)`
    /// ordering key, within the organization.
    pub async fn project_cursor<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (DateTime<Utc>, Uuid)>(
            "SELECT created_at,id FROM projects WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id)
        .bind(project_id)
        .fetch_optional(executor)
        .await
    }

    /// Resolves an application id used as a cursor into its `(created_at, id)`
    /// ordering key, within the organization and project.
    pub async fn application_cursor<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Option<Uuid>,
        application_id: Uuid,
    ) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (DateTime<Utc>, Uuid)>("SELECT created_at,id FROM applications WHERE organization_id=$1 AND project_id=$2 AND id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_optional(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::NavigationRepository;
    use crate::repository::test_support::{exec, ingest, tenant};
    use chrono::{DateTime, Duration, Utc};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    #[derive(Debug, FromRow)]
    struct Project {
        id: Uuid,
        created_at: DateTime<Utc>,
        application_count: i64,
        runtime_group_count: i64,
    }

    #[derive(Debug, FromRow)]
    struct Application {
        id: Uuid,
        created_at: DateTime<Utc>,
        release_count: i64,
        runtime_group_count: i64,
        latest_observed_at: Option<DateTime<Utc>>,
    }

    #[derive(Debug, FromRow)]
    struct Worker {
        agent_id: Uuid,
        cluster_name: String,
        first_observed_at: DateTime<Utc>,
        last_observed_at: DateTime<Utc>,
    }

    #[derive(Debug, FromRow)]
    struct Organization {
        id: Uuid,
        slug: String,
    }

    async fn add_project(pool: &PgPool, organization: Uuid, slug: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,$3,$3)")
            .bind(id)
            .bind(organization)
            .bind(slug)
            .execute(pool)
            .await
            .unwrap();
        id
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn reads_only_the_named_organization(pool: PgPool) {
        let own = tenant(&pool, "nav-org").await;
        let found: Organization = NavigationRepository::organization(&pool, own.organization_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (found.id, found.slug.as_str()),
            (own.organization_id, "nav-org")
        );
        assert!(
            NavigationRepository::organization::<_, Organization>(&pool, Uuid::new_v4())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Projects page by `(created_at, id)` ascending, within the organization
    /// only, and a cursor resumes strictly after itself.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn pages_projects_in_order_within_the_organization(pool: PgPool) {
        let own = tenant(&pool, "nav-projects").await;
        let other = tenant(&pool, "nav-projects-other").await;
        add_project(&pool, own.organization_id, "second").await;
        add_project(&pool, own.organization_id, "third").await;

        let all: Vec<Project> =
            NavigationRepository::project_page(&pool, own.organization_id, None, None, 10)
                .await
                .unwrap();
        assert_eq!(all.len(), 3, "the bootstrapped project and two more");
        assert!(all.iter().all(|p| p.id != other.project_id));
        assert!(
            all.windows(2)
                .all(|w| (w[0].created_at, w[0].id) < (w[1].created_at, w[1].id))
        );

        let first: Vec<Project> =
            NavigationRepository::project_page(&pool, own.organization_id, None, None, 1)
                .await
                .unwrap();
        assert_eq!(first.len(), 1, "fetch_limit bounds the page");
        let rest: Vec<Project> = NavigationRepository::project_page(
            &pool,
            own.organization_id,
            Some(first[0].created_at),
            Some(first[0].id),
            10,
        )
        .await
        .unwrap();
        assert_eq!(
            rest.iter().map(|p| p.id).collect::<Vec<_>>(),
            all[1..].iter().map(|p| p.id).collect::<Vec<_>>(),
            "the cursor resumes strictly after itself"
        );
    }

    /// A project's summary counts its applications and its runtime groups.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_project_carries_its_counts_and_is_tenant_scoped(pool: PgPool) {
        let own = tenant(&pool, "nav-project").await;
        let other = tenant(&pool, "nav-project-other").await;
        let now = Utc::now();
        ingest(
            &pool,
            &own,
            &[exec(&own, "/bin/a", now), exec(&own, "/bin/b", now)],
        )
        .await;

        let project: Project =
            NavigationRepository::project(&pool, own.organization_id, own.project_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            (project.application_count, project.runtime_group_count),
            (1, 2)
        );
        assert!(
            NavigationRepository::project::<_, Project>(
                &pool,
                other.organization_id,
                own.project_id
            )
            .await
            .unwrap()
            .is_none(),
            "another organization must not read the project"
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn an_application_carries_its_counts_and_latest_sighting(pool: PgPool) {
        let own = tenant(&pool, "nav-app").await;
        let other = tenant(&pool, "nav-app-other").await;
        let later = Utc::now();
        let earlier = later - Duration::minutes(5);
        ingest(
            &pool,
            &own,
            &[exec(&own, "/bin/a", earlier), exec(&own, "/bin/b", later)],
        )
        .await;
        sqlx::query("INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) VALUES($1,$2,$3,$4,'1.0',now())")
            .bind(Uuid::new_v4())
            .bind(own.organization_id)
            .bind(own.project_id)
            .bind(own.application_id)
            .execute(&pool)
            .await
            .unwrap();

        let application: Application = NavigationRepository::application(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            (application.release_count, application.runtime_group_count),
            (1, 2)
        );
        assert_eq!(
            application
                .latest_observed_at
                .map(|at| at.timestamp_micros()),
            Some(later.timestamp_micros())
        );

        let page: Vec<Application> = NavigationRepository::application_page(
            &pool,
            own.organization_id,
            own.project_id,
            None,
            None,
            10,
        )
        .await
        .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, own.application_id);
        let after: Vec<Application> = NavigationRepository::application_page(
            &pool,
            own.organization_id,
            own.project_id,
            Some(page[0].created_at),
            Some(page[0].id),
            10,
        )
        .await
        .unwrap();
        assert!(after.is_empty(), "nothing after the last application");

        assert!(
            NavigationRepository::application::<_, Application>(
                &pool,
                other.organization_id,
                own.project_id,
                own.application_id
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    /// Workers are the agents that reported events, with the span of their
    /// events; the cursor check accepts exactly an agent's latest time.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn workers_span_their_events_and_validate_cursors(pool: PgPool) {
        let own = tenant(&pool, "nav-workers").await;
        let first = Utc::now() - Duration::minutes(10);
        let last = Utc::now();
        ingest(
            &pool,
            &own,
            &[exec(&own, "/bin/a", first), exec(&own, "/bin/b", last)],
        )
        .await;

        let workers: Vec<Worker> = NavigationRepository::worker_page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            None,
            None,
            10,
        )
        .await
        .unwrap();
        assert_eq!(workers.len(), 1);
        let worker = &workers[0];
        assert_eq!(
            (
                worker.agent_id,
                worker.cluster_name.as_str(),
                worker.first_observed_at.timestamp_micros(),
                worker.last_observed_at.timestamp_micros()
            ),
            (
                own.agent_id,
                "Cluster",
                first.timestamp_micros(),
                last.timestamp_micros()
            )
        );

        assert!(
            NavigationRepository::worker_cursor_is_valid(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                own.agent_id,
                worker.last_observed_at,
            )
            .await
            .unwrap()
        );
        assert!(
            !NavigationRepository::worker_cursor_is_valid(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                own.agent_id,
                worker.first_observed_at,
            )
            .await
            .unwrap(),
            "only the agent's latest time is a valid cursor"
        );

        let after: Vec<Worker> = NavigationRepository::worker_page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            Some(worker.last_observed_at),
            Some(worker.agent_id),
            10,
        )
        .await
        .unwrap();
        assert!(after.is_empty(), "the cursor excludes itself");
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn cursors_resolve_within_their_scope(pool: PgPool) {
        let own = tenant(&pool, "nav-cursors").await;
        let other = tenant(&pool, "nav-cursors-other").await;

        let (_, id) =
            NavigationRepository::project_cursor(&pool, own.organization_id, own.project_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(id, own.project_id);
        assert!(
            NavigationRepository::project_cursor(&pool, other.organization_id, own.project_id)
                .await
                .unwrap()
                .is_none()
        );

        let (_, id) = NavigationRepository::application_cursor(
            &pool,
            own.organization_id,
            Some(own.project_id),
            own.application_id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(id, own.application_id);
        assert!(
            NavigationRepository::application_cursor(
                &pool,
                own.organization_id,
                Some(other.project_id),
                own.application_id
            )
            .await
            .unwrap()
            .is_none(),
            "an application resolves only under its own project"
        );
    }
}
