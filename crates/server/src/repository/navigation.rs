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
