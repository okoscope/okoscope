//! Release persistence.
//!
//! A release belongs to an application, so every lookup here is scoped by the
//! full path — organization, project, application — and that path was restated
//! as three positional `Uuid` binds at five call sites. [`ApplicationScope`]
//! carries it as one value, the way [`crate::repository::GroupKey`] carries a
//! group's identity.
//!
//! # What is not here
//!
//! Creation stays with the code that owns each kind of release. A manual
//! release is created by the releases API, whose statement returns a joined
//! projection for its response; an observed release is created by
//! [`crate::release_discovery`] under its own advisory lock and conflict
//! protocol. The release listings and the diff queries in [`crate::attention`]
//! are endpoint-specific projections.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// The tenant path of an application, which scopes every release lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationScope {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
}

/// Scalar subqueries aggregating an application's releases.
pub mod aggregates {
    /// Counts the releases of an application. Expects `applications` aliased
    /// as `a`.
    ///
    /// Carries the full tenant path. One of its three call sites matched on
    /// `application_id` alone; the composite foreign key makes that equivalent,
    /// so the count does not change.
    pub const COUNT_FOR_APPLICATION: &str = "(SELECT count(*) FROM releases r \
         WHERE r.organization_id=a.organization_id AND r.project_id=a.project_id \
           AND r.application_id=a.id)";
}

/// Queries against the `releases` table.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseRepository;

impl ReleaseRepository {
    /// Creates a manual release and returns it with its display name.
    ///
    /// A version already used by the application violates
    /// `UNIQUE (application_id, version)`; the caller reports that as a
    /// conflict. Selects the columns of the releases API's release view.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_manual<'e, E, T>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        version: &str,
        description: Option<String>,
        deployed_at: DateTime<Utc>,
    ) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH inserted AS (INSERT INTO releases (id,organization_id,project_id,application_id,version,description,deployed_at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *) SELECT r.id,r.project_id,r.application_id,r.version,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) display_name,r.description,r.deployed_at,r.created_at,r.source,r.identity_version,encode(r.identity_digest,'hex') identity_digest,r.identity_components,0::bigint revision_count,0::bigint active_episode_count FROM inserted r JOIN applications a ON a.id=r.application_id")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(version)
            .bind(description)
            .bind(deployed_at)
            .fetch_one(executor)
            .await
    }

    /// A page of an application's releases, newest deployment first, after
    /// the cursor's `(deployed_at, id)` when one is given. Same columns as
    /// [`Self::create_manual`].
    pub async fn page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cursor_deployed_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT r.id,r.project_id,r.application_id,r.version,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) display_name,r.description,r.deployed_at,r.created_at,r.source,r.identity_version,encode(r.identity_digest,'hex') identity_digest,r.identity_components,(SELECT count(*) FROM kubernetes_workload_revisions v WHERE v.release_id=r.id)::bigint revision_count,(SELECT count(*) FROM deployment_episodes e WHERE e.release_id=r.id AND e.state<>'inactive')::bigint active_episode_count FROM releases r JOIN applications a ON a.id=r.application_id WHERE r.organization_id=$1 AND r.project_id=$2 AND r.application_id=$3 AND ($4::timestamptz IS NULL OR (r.deployed_at,r.id)<($4,$5)) ORDER BY r.deployed_at DESC,r.id DESC LIMIT $6")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cursor_deployed_at)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// A page of the deployment episodes of one release, after the cursor
    /// episode when one is given.
    pub async fn deployment_episode_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        release_id: Uuid,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT e.id,e.release_id,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) release_display_name,e.revision_id,e.cluster_id,e.occurrence_number,e.state,e.transition_kind,e.first_observed_at,e.first_ready_at,e.last_observed_at,e.ended_at,e.pod_count,e.ready_pod_count,e.workload_ready_pod_count,CASE WHEN e.workload_ready_pod_count>0 THEN e.ready_pod_count::double precision/e.workload_ready_pod_count::double precision END ready_pod_share,e.snapshot_observed_at,COALESCE((SELECT jsonb_agg(jsonb_build_object('episode_id',p.predecessor_episode_id,'observed_at',p.observed_at,'concurrent',p.concurrent) ORDER BY p.observed_at DESC,p.predecessor_episode_id DESC) FROM deployment_episode_predecessors p WHERE p.episode_id=e.id),'[]'::jsonb) predecessors FROM deployment_episodes e JOIN releases r ON r.id=e.release_id JOIN applications a ON a.id=e.application_id WHERE e.organization_id=$1 AND e.project_id=$2 AND e.application_id=$3 AND e.release_id=$4 AND ($5::uuid IS NULL OR e.id<$5) ORDER BY e.first_observed_at DESC,e.id DESC LIMIT $6")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(release_id)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// One release of the application, with the same columns as
    /// [`Self::create_manual`].
    pub async fn get<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        release_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT r.id,r.project_id,r.application_id,r.version,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) display_name,r.description,r.deployed_at,r.created_at,r.source,r.identity_version,encode(r.identity_digest,'hex') identity_digest,r.identity_components,(SELECT count(*) FROM kubernetes_workload_revisions v WHERE v.release_id=r.id)::bigint revision_count,(SELECT count(*) FROM deployment_episodes e WHERE e.release_id=r.id AND e.state<>'inactive')::bigint active_episode_count FROM releases r JOIN applications a ON a.id=r.application_id WHERE r.organization_id=$1 AND r.project_id=$2 AND r.application_id=$3 AND r.id=$4")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(release_id)
            .fetch_optional(executor)
            .await
    }

    /// The releases a deployment of `release_id` replaced, from the recorded
    /// deployment-episode transitions. More than one means concurrent
    /// transitions, which the diff resolves by falling back.
    pub async fn transition_predecessors<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        release_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT p.release_id FROM deployment_episodes t JOIN deployment_episode_predecessors x ON x.episode_id=t.id JOIN deployment_episodes p ON p.id=x.predecessor_episode_id WHERE t.organization_id=$1 AND t.project_id=$2 AND t.application_id=$3 AND t.release_id=$4 ORDER BY t.first_observed_at DESC,t.id DESC,x.observed_at DESC,p.id DESC LIMIT 2")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(release_id)
            .fetch_all(executor)
            .await
    }

    /// The release deployed immediately before the given one by deployment
    /// order — the baseline used when no transition was recorded. Same
    /// columns as [`Self::create_manual`].
    pub async fn legacy_predecessor<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        deployed_at: DateTime<Utc>,
        release_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT r.id,r.project_id,r.application_id,r.version,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) display_name,r.description,r.deployed_at,r.created_at,r.source,r.identity_version,encode(r.identity_digest,'hex') identity_digest,r.identity_components,(SELECT count(*) FROM kubernetes_workload_revisions v WHERE v.release_id=r.id)::bigint revision_count,(SELECT count(*) FROM deployment_episodes e WHERE e.release_id=r.id AND e.state<>'inactive')::bigint active_episode_count FROM releases r JOIN applications a ON a.id=r.application_id WHERE r.organization_id=$1 AND r.project_id=$2 AND r.application_id=$3 AND (r.deployed_at,r.id)<($4,$5) ORDER BY r.deployed_at DESC,r.id DESC LIMIT 1")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(deployed_at)
            .bind(release_id)
            .fetch_optional(executor)
            .await
    }

    /// A page of the runtime-group differences between a baseline and a
    /// target release, after the cursor group when one is given. With no
    /// baseline, the baseline side of the comparison is empty.
    #[allow(clippy::too_many_arguments)]
    pub async fn diff_page<'e, E, T>(
        executor: E,
        baseline_id: Option<Uuid>,
        target_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH b AS (SELECT * FROM runtime_event_group_releases WHERE release_id=$1 AND occurrence_count>0), t AS (SELECT * FROM runtime_event_group_releases WHERE release_id=$2 AND occurrence_count>0), evidence AS (SELECT (EXISTS(SELECT 1 FROM runtime_events WHERE release_id=$2) OR EXISTS(SELECT 1 FROM runtime_event_group_releases WHERE release_id=$2 AND occurrence_count>0)) target_observed,EXISTS(SELECT 1 FROM releases r JOIN projects p ON p.id=r.project_id WHERE r.id=$1 AND r.deployed_at<p.runtime_history_expired_before) baseline_expired,EXISTS(SELECT 1 FROM releases r JOIN projects p ON p.id=r.project_id WHERE r.id=$2 AND r.deployed_at<p.runtime_history_expired_before) target_expired) SELECT COALESCE(t.group_id,b.group_id) group_id,CASE WHEN b.group_id IS NULL AND evidence.baseline_expired THEN 'unknown' WHEN b.group_id IS NULL THEN 'new' WHEN t.group_id IS NULL AND (NOT evidence.target_observed OR evidence.target_expired) THEN 'unknown' WHEN t.group_id IS NULL THEN 'disappeared' ELSE 'unchanged' END classification,g.event_kind,g.semantic_summary,b.occurrence_count baseline_occurrence_count,b.first_seen_at baseline_first_seen_at,b.last_seen_at baseline_last_seen_at,t.occurrence_count target_occurrence_count,t.first_seen_at target_first_seen_at,t.last_seen_at target_last_seen_at FROM b FULL OUTER JOIN t ON t.group_id=b.group_id JOIN runtime_event_groups g ON g.id=COALESCE(t.group_id,b.group_id) CROSS JOIN evidence WHERE g.organization_id=$3 AND g.project_id=$4 AND g.application_id=$5 AND g.event_kind <> 'network.accept' AND ($6::uuid IS NULL OR g.id>$6) ORDER BY g.id LIMIT $7")
            .bind(baseline_id)
            .bind(target_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// Makes the rest of the caller's transaction a read-only snapshot, so
    /// the diff summary's several statements see one state of the data.
    ///
    /// Must be the first statement of the transaction; pass `&mut *tx`.
    pub async fn begin_consistent_read<'e, E>(
        executor: E,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(executor)
            .await
    }

    /// Counts of differences between two releases by classification.
    pub async fn diff_classifications<'e, E, T>(
        executor: E,
        baseline_id: Uuid,
        target_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH b AS (SELECT group_id,occurrence_count FROM runtime_event_group_releases WHERE release_id=$1 AND occurrence_count>0), t AS (SELECT group_id,occurrence_count FROM runtime_event_group_releases WHERE release_id=$2 AND occurrence_count>0), evidence AS (SELECT (EXISTS(SELECT 1 FROM runtime_events WHERE release_id=$2) OR EXISTS(SELECT 1 FROM runtime_event_group_releases WHERE release_id=$2 AND occurrence_count>0)) target_observed,EXISTS(SELECT 1 FROM releases r JOIN projects p ON p.id=r.project_id WHERE r.id=$1 AND r.deployed_at<p.runtime_history_expired_before) baseline_expired,EXISTS(SELECT 1 FROM releases r JOIN projects p ON p.id=r.project_id WHERE r.id=$2 AND r.deployed_at<p.runtime_history_expired_before) target_expired), compared AS (SELECT COALESCE(t.group_id,b.group_id) group_id,CASE WHEN b.group_id IS NULL AND evidence.baseline_expired THEN 'unknown' WHEN b.group_id IS NULL THEN 'new' WHEN t.group_id IS NULL AND (NOT evidence.target_observed OR evidence.target_expired) THEN 'unknown' WHEN t.group_id IS NULL THEN 'disappeared' ELSE 'unchanged' END classification FROM b FULL OUTER JOIN t ON t.group_id=b.group_id JOIN runtime_event_groups g ON g.id=COALESCE(t.group_id,b.group_id) CROSS JOIN evidence WHERE g.organization_id=$3 AND g.project_id=$4 AND g.application_id=$5 AND g.event_kind <> 'network.accept') SELECT classification,count(*)::bigint item_count FROM compared GROUP BY classification ORDER BY CASE classification WHEN 'new' THEN 1 WHEN 'disappeared' THEN 2 WHEN 'unchanged' THEN 3 ELSE 4 END")
            .bind(baseline_id)
            .bind(target_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_all(executor)
            .await
    }

    /// The differences between two releases with the largest change in
    /// occurrences, up to `limit`.
    pub async fn diff_largest_changes<'e, E, T>(
        executor: E,
        baseline_id: Uuid,
        target_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH b AS (SELECT group_id,occurrence_count FROM runtime_event_group_releases WHERE release_id=$1 AND occurrence_count>0), t AS (SELECT group_id,occurrence_count FROM runtime_event_group_releases WHERE release_id=$2 AND occurrence_count>0), evidence AS (SELECT (EXISTS(SELECT 1 FROM runtime_events WHERE release_id=$2) OR EXISTS(SELECT 1 FROM runtime_event_group_releases WHERE release_id=$2 AND occurrence_count>0)) target_observed,EXISTS(SELECT 1 FROM releases r JOIN projects p ON p.id=r.project_id WHERE r.id=$1 AND r.deployed_at<p.runtime_history_expired_before) baseline_expired,EXISTS(SELECT 1 FROM releases r JOIN projects p ON p.id=r.project_id WHERE r.id=$2 AND r.deployed_at<p.runtime_history_expired_before) target_expired) SELECT COALESCE(t.group_id,b.group_id) group_id,CASE WHEN b.group_id IS NULL AND evidence.baseline_expired THEN 'unknown' WHEN b.group_id IS NULL THEN 'new' WHEN t.group_id IS NULL AND (NOT evidence.target_observed OR evidence.target_expired) THEN 'unknown' WHEN t.group_id IS NULL THEN 'disappeared' ELSE 'unchanged' END classification,g.event_kind,g.semantic_summary,COALESCE(b.occurrence_count,0)::bigint baseline_occurrence_count,COALESCE(t.occurrence_count,0)::bigint target_occurrence_count,(COALESCE(t.occurrence_count,0)-COALESCE(b.occurrence_count,0))::bigint occurrence_delta FROM b FULL OUTER JOIN t ON t.group_id=b.group_id JOIN runtime_event_groups g ON g.id=COALESCE(t.group_id,b.group_id) CROSS JOIN evidence WHERE g.organization_id=$3 AND g.project_id=$4 AND g.application_id=$5 AND g.event_kind <> 'network.accept' ORDER BY ABS(COALESCE(t.occurrence_count,0)-COALESCE(b.occurrence_count,0)) DESC,g.id ASC LIMIT $6")
            .bind(baseline_id)
            .bind(target_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Reports whether the release belongs to the application.
    ///
    /// `false` covers a release of another application as well as one that
    /// does not exist, so a caller filtering by release cannot reach another
    /// tenant's.
    pub async fn exists<'e, E>(
        executor: E,
        scope: ApplicationScope,
        release_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT EXISTS(SELECT 1 FROM releases
                          WHERE organization_id = $1 AND project_id = $2
                            AND application_id = $3 AND id = $4)
            "#,
        )
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(release_id)
        .fetch_one(executor)
        .await
    }

    /// Resolves a release id used as a pagination cursor into the key the
    /// release listings are ordered by, `(deployed_at, id)`.
    ///
    /// Two listings — the releases API and the inventory release presence —
    /// page over an application's releases newest first and each looked this
    /// up separately. `None` means the cursor names no release of this
    /// application, which callers report as an invalid cursor.
    pub async fn cursor<'e, E>(
        executor: E,
        scope: ApplicationScope,
        release_id: Uuid,
    ) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT deployed_at, id FROM releases
            WHERE organization_id = $1 AND project_id = $2
              AND application_id = $3 AND id = $4
            "#,
        )
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(release_id)
        .fetch_optional(executor)
        .await
    }

    /// Returns the release of the application with this version string.
    ///
    /// Versions are unique per application (`UNIQUE (application_id,
    /// version)`), so there is at most one. Ingestion uses this to attribute an
    /// event to the release its agent reported.
    pub async fn id_by_version<'e, E>(
        executor: E,
        scope: ApplicationScope,
        version: &str,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT id FROM releases
            WHERE organization_id = $1 AND project_id = $2
              AND application_id = $3 AND version = $4
            "#,
        )
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(version)
        .fetch_optional(executor)
        .await
    }

    /// Returns the observed release with this workload identity.
    ///
    /// Only observed releases carry an identity — the check constraint keeps
    /// it null on manual ones — so no `source` filter is needed to exclude
    /// them.
    pub async fn id_by_identity<'e, E>(
        executor: E,
        scope: ApplicationScope,
        identity_version: i16,
        identity_digest: &[u8],
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT id FROM releases
            WHERE organization_id = $1 AND project_id = $2 AND application_id = $3
              AND identity_version = $4 AND identity_digest = $5
            "#,
        )
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(identity_version)
        .bind(identity_digest)
        .fetch_optional(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{ApplicationScope, ReleaseRepository, aggregates};
    use crate::repository::{ApplicationRepository, ProjectRepository};
    use chrono::{DateTime, Duration, Utc};
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn seed_application(pool: &PgPool) -> ApplicationScope {
        let organization = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Releases')")
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
        let application = ApplicationRepository::insert(pool, Uuid::new_v4(), project, "a", "A")
            .await
            .unwrap()
            .unwrap()
            .id;
        ApplicationScope {
            organization_id: organization,
            project_id: project,
            application_id: application,
        }
    }

    async fn manual(
        pool: &PgPool,
        scope: ApplicationScope,
        version: &str,
        at: DateTime<Utc>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) \
             VALUES($1,$2,$3,$4,$5,$6)",
        )
        .bind(id)
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(version)
        .bind(at)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    /// A release id from another application must not pass for this one, in
    /// the existence check or as a pagination cursor.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_release_is_visible_only_through_its_own_application(pool: PgPool) {
        let scope = seed_application(&pool).await;
        let other = seed_application(&pool).await;
        let deployed_at = Utc::now() - Duration::hours(1);
        let release = manual(&pool, scope, "1.0.0", deployed_at).await;
        let foreign = manual(&pool, other, "1.0.0", deployed_at).await;

        assert!(
            ReleaseRepository::exists(&pool, scope, release)
                .await
                .unwrap()
        );
        assert!(
            !ReleaseRepository::exists(&pool, scope, foreign)
                .await
                .unwrap(),
            "another application's release must not pass"
        );

        let (at, id) = ReleaseRepository::cursor(&pool, scope, release)
            .await
            .unwrap()
            .expect("own release resolves");
        assert_eq!(
            (at.timestamp_micros(), id),
            (deployed_at.timestamp_micros(), release)
        );
        assert!(
            ReleaseRepository::cursor(&pool, scope, foreign)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The same version string in two applications names two releases.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_version_resolves_within_its_application_only(pool: PgPool) {
        let scope = seed_application(&pool).await;
        let other = seed_application(&pool).await;
        let release = manual(&pool, scope, "2.1.0", Utc::now()).await;
        let foreign = manual(&pool, other, "2.1.0", Utc::now()).await;

        assert_eq!(
            ReleaseRepository::id_by_version(&pool, scope, "2.1.0")
                .await
                .unwrap(),
            Some(release)
        );
        assert_eq!(
            ReleaseRepository::id_by_version(&pool, other, "2.1.0")
                .await
                .unwrap(),
            Some(foreign)
        );
        assert_eq!(
            ReleaseRepository::id_by_version(&pool, scope, "9.9.9")
                .await
                .unwrap(),
            None
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn an_identity_resolves_to_its_observed_release(pool: PgPool) {
        let scope = seed_application(&pool).await;
        let digest = [4u8; 32];
        let observed = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at,\
             source,identity_version,identity_digest,identity_components) \
             VALUES($1,$2,$3,$4,$5,now(),'observed',1,$6,'[\"container\"]'::jsonb)",
        )
        .bind(observed)
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(format!("sha256:{}", hex::encode(digest)))
        .bind(digest.as_slice())
        .execute(&pool)
        .await
        .unwrap();
        manual(&pool, scope, "manual", Utc::now()).await;

        assert_eq!(
            ReleaseRepository::id_by_identity(&pool, scope, 1, &digest)
                .await
                .unwrap(),
            Some(observed)
        );
        assert_eq!(
            ReleaseRepository::id_by_identity(&pool, scope, 2, &digest)
                .await
                .unwrap(),
            None,
            "the identity version is part of the key"
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_count_fragment_counts_an_applications_releases(pool: PgPool) {
        let scope = seed_application(&pool).await;
        let other = seed_application(&pool).await;
        manual(&pool, scope, "1", Utc::now()).await;
        manual(&pool, scope, "2", Utc::now()).await;
        manual(&pool, other, "1", Utc::now()).await;

        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT {} FROM applications a WHERE a.id=$1",
            aggregates::COUNT_FOR_APPLICATION
        ))
        .bind(scope.application_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 2);
    }
}
