//! Resource usage persistence: the per-interval contributions agents report,
//! their minute and hour rollups, retention of both, and the release
//! regression findings computed from the rollups.
//!
//! Reads returning projections owned by the resource endpoints are generic
//! over the row type and document the columns they select.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

/// Resource contributions, rollups and regression findings.
#[derive(Clone, Copy, Debug)]
pub struct ResourceRepository;

impl ResourceRepository {
    /// How many of the application's resource findings are open.
    pub async fn open_finding_count<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM release_resource_findings WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND closed_at IS NULL")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_one(executor)
            .await
    }

    /// Locks the project and returns its effective detail and rollup
    /// retention in days, falling back to the organization's.
    pub async fn retention_days_for_update<'e, E>(
        executor: E,
        project_id: Uuid,
    ) -> Result<(i32, i32), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (i32, i32)>("SELECT COALESCE(p.resource_detail_retention_days,o.resource_detail_retention_days),COALESCE(p.resource_rollup_retention_days,o.resource_rollup_retention_days) FROM projects p JOIN organizations o ON o.id=p.organization_id WHERE p.id=$1 FOR UPDATE OF p")
            .bind(project_id)
            .fetch_one(executor)
            .await
    }

    /// Moves the project's detail and rollup horizons forward, never back.
    pub async fn advance_retention_horizons<'e, E>(
        executor: E,
        project_id: Uuid,
        detail_before: DateTime<Utc>,
        rollup_before: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE projects SET resource_closed_before=GREATEST(resource_closed_before,$2),resource_rollup_expired_before=GREATEST(resource_rollup_expired_before,$3) WHERE id=$1")
            .bind(project_id)
            .bind(detail_before)
            .bind(rollup_before)
            .execute(executor)
            .await
    }

    /// Deletes up to `limit` of the project's contributions that ended
    /// before `detail_before`, oldest first, skipping locked rows.
    pub async fn delete_expired_contributions<'e, E>(
        executor: E,
        project_id: Uuid,
        detail_before: DateTime<Utc>,
        limit: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM resource_contributions WHERE (organization_id,application_id,id) IN (SELECT organization_id,application_id,id FROM resource_contributions WHERE project_id=$1 AND interval_end<$2 ORDER BY interval_end,id LIMIT $3 FOR UPDATE SKIP LOCKED)")
            .bind(project_id)
            .bind(detail_before)
            .bind(limit)
            .execute(executor)
            .await
    }

    /// Deletes up to `limit` of the project's expired rollup points, oldest
    /// first, skipping locked rows: minute points before `detail_before` and
    /// any point before `rollup_before`.
    pub async fn delete_expired_rollups<'e, E>(
        executor: E,
        project_id: Uuid,
        detail_before: DateTime<Utc>,
        rollup_before: DateTime<Utc>,
        limit: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM resource_rollup_points WHERE (application_id,release_key,container_name,bucket_start,step_seconds,metric) IN (SELECT application_id,release_key,container_name,bucket_start,step_seconds,metric FROM resource_rollup_points WHERE project_id=$1 AND ((step_seconds=60 AND bucket_start<$2) OR bucket_start<$3) ORDER BY bucket_start,application_id LIMIT $4 FOR UPDATE SKIP LOCKED)")
            .bind(project_id)
            .bind(detail_before)
            .bind(rollup_before)
            .bind(limit)
            .execute(executor)
            .await
    }

    /// The project's effective detail retention in days, falling back to the
    /// organization's.
    pub async fn detail_retention_days<'e, E>(
        executor: E,
        project_id: Uuid,
    ) -> Result<i32, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i32>("SELECT COALESCE(p.resource_detail_retention_days,o.resource_detail_retention_days) FROM projects p JOIN organizations o ON o.id=p.organization_id WHERE p.id=$1")
            .bind(project_id)
            .fetch_one(executor)
            .await
    }

    /// Stores one reported contribution, once: a repeated id affects no row.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_contribution<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
        agent_id: Uuid,
        release_id: Option<Uuid>,
        schema_version: i16,
        interval_start: DateTime<Utc>,
        interval_end: DateTime<Utc>,
        covered_usec: i64,
        sample_count: i32,
        contributing_containers: i32,
        namespace: &str,
        workload_uid: &str,
        workload_kind: &str,
        workload_name: &str,
        container_name: &str,
        node_name: &str,
        unavailable_sources: i64,
        values: Value,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO resource_contributions(id,organization_id,project_id,application_id,cluster_id,agent_id,release_id,schema_version,interval_start,interval_end,covered_usec,sample_count,contributing_containers,namespace,workload_uid,workload_kind,workload_name,container_name,node_name,unavailable_sources,values) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT(organization_id,application_id,id) DO NOTHING")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cluster_id)
            .bind(agent_id)
            .bind(release_id)
            .bind(schema_version)
            .bind(interval_start)
            .bind(interval_end)
            .bind(covered_usec)
            .bind(sample_count)
            .bind(contributing_containers)
            .bind(namespace)
            .bind(workload_uid)
            .bind(workload_kind)
            .bind(workload_name)
            .bind(container_name)
            .bind(node_name)
            .bind(unavailable_sources)
            .bind(values)
            .execute(executor)
            .await
    }

    /// Folds one contribution's metric into its rollup bucket of `step`
    /// seconds: sums and weights add, minimum and maximum widen, the limit
    /// keeps its latest value, and replica counts keep their maximum.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_rollup_point<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        release_key: Uuid,
        release_id: Option<Uuid>,
        container_name: &str,
        interval_start: DateTime<Utc>,
        step_seconds: i32,
        metric: &str,
        unit: &str,
        value: f64,
        value_weight: f64,
        limit_value: Option<f64>,
        covered_usec: i64,
        expected_usec: i64,
        sample_count: i64,
        observed_replicas: i32,
        ready_replicas: i32,
        unavailable_sources: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO resource_rollup_points(organization_id,project_id,application_id,release_key,release_id,container_name,bucket_start,step_seconds,metric,unit,value_sum,value_min,value_max,value_weight,limit_value,covered_usec,expected_usec,sample_count,contributor_count,observed_replicas,ready_replicas,unavailable_sources) VALUES($1,$2,$3,$4,$5,$6,to_timestamp(floor(extract(epoch from $7::timestamptz)/$8)*$8),$8,$9,$10,$11*$12,$11,$11,$12,$13,$14,$15,$16,1,$17,$18,$19) ON CONFLICT(application_id,release_key,container_name,bucket_start,step_seconds,metric) DO UPDATE SET value_sum=resource_rollup_points.value_sum+EXCLUDED.value_sum,value_min=LEAST(resource_rollup_points.value_min,EXCLUDED.value_min),value_max=GREATEST(resource_rollup_points.value_max,EXCLUDED.value_max),value_weight=resource_rollup_points.value_weight+EXCLUDED.value_weight,limit_value=COALESCE(EXCLUDED.limit_value,resource_rollup_points.limit_value),covered_usec=resource_rollup_points.covered_usec+EXCLUDED.covered_usec,expected_usec=resource_rollup_points.expected_usec+EXCLUDED.expected_usec,sample_count=resource_rollup_points.sample_count+EXCLUDED.sample_count,contributor_count=resource_rollup_points.contributor_count+1,observed_replicas=GREATEST(resource_rollup_points.observed_replicas,EXCLUDED.observed_replicas),ready_replicas=GREATEST(resource_rollup_points.ready_replicas,EXCLUDED.ready_replicas),unavailable_sources=resource_rollup_points.unavailable_sources|EXCLUDED.unavailable_sources,updated_at=now()")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(release_key)
            .bind(release_id)
            .bind(container_name)
            .bind(interval_start)
            .bind(step_seconds)
            .bind(metric)
            .bind(unit)
            .bind(value)
            .bind(value_weight)
            .bind(limit_value)
            .bind(covered_usec)
            .bind(expected_usec)
            .bind(sample_count)
            .bind(observed_replicas)
            .bind(ready_replicas)
            .bind(unavailable_sources)
            .execute(executor)
            .await
    }

    /// The application's rollup points of one metric and step over
    /// `[from, to)`, optionally for one release and container, at most 45 360.
    ///
    /// Selects `bucket_start`, `unit`, `value`, `limit_value`,
    /// `covered_usec`, `expected_usec`, `sample_count`, `contributor_count`,
    /// `observed_replicas`, `ready_replicas`, `unavailable_sources`,
    /// `release_id`, `release_display_name` and `container_name`.
    #[allow(clippy::too_many_arguments)]
    pub async fn history<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        metric: &str,
        step_seconds: i32,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        release_id: Option<Uuid>,
        container_name: Option<&str>,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT p.bucket_start,p.unit,p.value_sum/p.value_weight value,p.limit_value,p.covered_usec,p.expected_usec,p.sample_count,p.contributor_count,ceil(p.covered_usec::numeric/($5::bigint*1000000))::int observed_replicas,ceil(p.covered_usec::numeric/($5::bigint*1000000))::int ready_replicas,p.unavailable_sources,p.release_id,CASE WHEN r.id IS NULL THEN NULL ELSE release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) END release_display_name,p.container_name FROM resource_rollup_points p JOIN applications a ON a.id=p.application_id LEFT JOIN releases r ON r.id=p.release_id WHERE p.organization_id=$1 AND p.project_id=$2 AND p.application_id=$3 AND p.metric=$4 AND p.step_seconds=$5 AND p.bucket_start >= $6 AND p.bucket_start < $7 AND ($8::uuid IS NULL OR p.release_id=$8) AND ($9::text IS NULL OR p.container_name=$9) ORDER BY p.bucket_start,p.container_name,p.release_key LIMIT 45360")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(metric)
            .bind(step_seconds)
            .bind(from)
            .bind(to)
            .bind(release_id)
            .bind(container_name)
            .fetch_all(executor)
            .await
    }

    /// The release's latest deployment episode in the application.
    ///
    /// Selects `episode_id`, `release_id`, `release_display_name`,
    /// `first_observed_at` and `first_ready_at`.
    pub async fn episode_window<'e, E, T>(
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
        sqlx::query_as("SELECT e.id episode_id,e.release_id,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) release_display_name,e.first_observed_at,e.first_ready_at FROM deployment_episodes e JOIN releases r ON r.id=e.release_id JOIN applications a ON a.id=e.application_id WHERE e.organization_id=$1 AND e.project_id=$2 AND e.application_id=$3 AND e.release_id=$4 ORDER BY e.first_observed_at DESC,e.id DESC LIMIT 1")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(release_id)
            .fetch_optional(executor)
            .await
    }

    /// Up to two episodes an episode replaced, latest transition first, with
    /// the columns of [`Self::episode_window`].
    pub async fn predecessor_episode_windows<'e, E, T>(
        executor: E,
        episode_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT p.id episode_id,p.release_id,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) release_display_name,p.first_observed_at,p.first_ready_at FROM deployment_episode_predecessors x JOIN deployment_episodes p ON p.id=x.predecessor_episode_id JOIN releases r ON r.id=p.release_id JOIN applications a ON a.id=p.application_id WHERE x.episode_id=$1 AND p.organization_id=$2 AND p.project_id=$3 AND p.application_id=$4 ORDER BY x.observed_at DESC,p.id DESC LIMIT 2")
            .bind(episode_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_all(executor)
            .await
    }

    /// The latest ready deployment episode of each of the project's
    /// applications, at most 64.
    ///
    /// Selects `organization_id`, `application_id` and the columns of
    /// [`Self::episode_window`].
    pub async fn latest_ready_episodes<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT DISTINCT ON(e.application_id) e.organization_id,e.application_id,e.id episode_id,e.release_id,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) release_display_name,e.first_observed_at,e.first_ready_at FROM deployment_episodes e JOIN releases r ON r.id=e.release_id JOIN applications a ON a.id=e.application_id WHERE e.organization_id=$1 AND e.project_id=$2 AND e.first_ready_at IS NOT NULL ORDER BY e.application_id,e.first_observed_at DESC,e.id DESC LIMIT 64")
            .bind(organization_id)
            .bind(project_id)
            .fetch_all(executor)
            .await
    }

    /// Counts a clean evaluation against the target release's open findings
    /// that are not among `active_ids`, closing those clean twice.
    pub async fn age_findings<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        target_release_id: Uuid,
        active_ids: &[Uuid],
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE release_resource_findings SET clean_evaluations=LEAST(clean_evaluations+1,2),closed_at=CASE WHEN clean_evaluations+1>=2 THEN now() ELSE NULL END,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND target_release_id=$4 AND closed_at IS NULL AND NOT(id=ANY($5))")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(target_release_id)
            .bind(active_ids)
            .execute(executor)
            .await
    }

    /// Opens a finding, or refreshes and reopens the existing one for the same
    /// release, reason, metric and rule version.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_finding<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        target_release_id: Uuid,
        baseline_release_id: Uuid,
        reason_code: &str,
        priority: &str,
        metric: &str,
        rule_version: i16,
        facts: Value,
        opened_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO release_resource_findings(id,organization_id,project_id,application_id,target_release_id,baseline_release_id,reason_code,priority,metric,rule_version,facts,opened_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(application_id,target_release_id,reason_code,metric,rule_version) DO UPDATE SET facts=EXCLUDED.facts,priority=EXCLUDED.priority,clean_evaluations=0,closed_at=NULL,updated_at=now()")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(target_release_id)
            .bind(baseline_release_id)
            .bind(reason_code)
            .bind(priority)
            .bind(metric)
            .bind(rule_version)
            .bind(facts)
            .bind(opened_at)
            .execute(executor)
            .await
    }

    /// Per-metric summary of a release's minute rollups over `[from, to)`.
    ///
    /// Selects `metric`, `unit`, `value`, `limit_value`, `covered_usec`,
    /// `expected_usec`, `sample_count`, `contributor_count`,
    /// `observed_replicas`, `ready_replicas` and `bucket_count`.
    pub async fn window_summary<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        release_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT metric,min(unit) unit,sum(value_sum)/sum(value_weight) value,max(limit_value) limit_value,sum(covered_usec)::bigint covered_usec,sum(expected_usec)::bigint expected_usec,sum(sample_count)::bigint sample_count,sum(contributor_count)::bigint contributor_count,ceil(sum(covered_usec)::numeric/1800000000)::int observed_replicas,ceil(sum(covered_usec)::numeric/1800000000)::int ready_replicas,count(DISTINCT bucket_start)::bigint bucket_count FROM resource_rollup_points WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND release_id=$4 AND step_seconds=60 AND bucket_start >= $5 AND bucket_start < $6 GROUP BY metric ORDER BY metric")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(release_id)
            .bind(from)
            .bind(to)
            .fetch_all(executor)
            .await
    }

    /// A release's minute buckets over `[from, to)` with at least 80%
    /// coverage, per metric in time order.
    ///
    /// Selects `metric`, `bucket_start` and `value`.
    pub async fn covered_buckets<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        release_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT metric,bucket_start,sum(value_sum)/sum(value_weight) value FROM resource_rollup_points WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND release_id=$4 AND step_seconds=60 AND bucket_start >= $5 AND bucket_start < $6 GROUP BY metric,bucket_start HAVING sum(covered_usec)::double precision/sum(expected_usec)>=0.8 ORDER BY metric,bucket_start")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(release_id)
            .bind(from)
            .bind(to)
            .fetch_all(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, DurationRound, Utc};
    use serde_json::json;
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::ResourceRepository;
    use crate::repository::ProjectRepository;
    use crate::repository::test_support::{Tenant, observe_revision, tenant};

    #[derive(Debug, FromRow)]
    struct HistoryPoint {
        bucket_start: DateTime<Utc>,
        value: f64,
        sample_count: i64,
        contributor_count: i64,
        release_id: Option<Uuid>,
        container_name: String,
    }

    #[derive(Debug, FromRow)]
    struct EpisodeWindow {
        episode_id: Uuid,
        release_id: Uuid,
        first_ready_at: Option<DateTime<Utc>>,
    }

    #[derive(Debug, FromRow)]
    struct ProjectEpisode {
        application_id: Uuid,
        release_id: Uuid,
    }

    #[derive(Debug, FromRow)]
    struct Summary {
        metric: String,
        value: f64,
        bucket_count: i64,
    }

    #[derive(Debug, FromRow)]
    struct Bucket {
        metric: String,
        bucket_start: DateTime<Utc>,
    }

    fn minute() -> DateTime<Utc> {
        (Utc::now() - Duration::hours(2))
            .duration_trunc(Duration::hours(1))
            .unwrap()
    }

    /// Folds one metric value into a bucket, covering `covered` of the
    /// expected 60 seconds.
    #[allow(clippy::too_many_arguments)]
    async fn point(
        pool: &PgPool,
        own: &Tenant,
        release_id: Option<Uuid>,
        at: DateTime<Utc>,
        step: i32,
        metric: &str,
        value: f64,
        covered_seconds: i64,
    ) {
        ResourceRepository::add_rollup_point(
            pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            release_id.unwrap_or(Uuid::nil()),
            release_id,
            "app",
            at,
            step,
            metric,
            "cores",
            value,
            60_000_000.0,
            None,
            covered_seconds * 1_000_000,
            60_000_000,
            6,
            1,
            1,
            0,
        )
        .await
        .unwrap();
    }

    async fn history(
        pool: &PgPool,
        own: &Tenant,
        step: i32,
        release_id: Option<Uuid>,
        container: Option<&str>,
    ) -> Vec<HistoryPoint> {
        ResourceRepository::history(
            pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            "cpu",
            step,
            minute() - Duration::days(30),
            Utc::now(),
            release_id,
            container,
        )
        .await
        .unwrap()
    }

    /// Contributions are stored once; rollup points fold into their bucket
    /// as a weighted mean; history filters by release and container; the
    /// project's retention resolves, only moves forward, and expires data.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn contributions_roll_up_and_expire(pool: PgPool) {
        let own = tenant(&pool, "resources-rollup").await;
        let start = minute();
        let contribution = Uuid::new_v4();
        let insert = || {
            ResourceRepository::insert_contribution(
                &pool,
                contribution,
                own.organization_id,
                own.project_id,
                own.application_id,
                own.cluster_id,
                own.agent_id,
                None,
                1,
                start,
                start + Duration::minutes(1),
                60_000_000,
                6,
                1,
                "production",
                "workload-a",
                "Deployment",
                "app",
                "app",
                "node-a",
                0,
                json!({}),
            )
        };
        assert_eq!(insert().await.unwrap().rows_affected(), 1);
        assert_eq!(insert().await.unwrap().rows_affected(), 0, "stored once");

        point(
            &pool,
            &own,
            None,
            start + Duration::seconds(10),
            60,
            "cpu",
            1.0,
            60,
        )
        .await;
        point(
            &pool,
            &own,
            None,
            start + Duration::seconds(40),
            60,
            "cpu",
            3.0,
            60,
        )
        .await;
        let minutes = history(&pool, &own, 60, None, None).await;
        assert_eq!(minutes.len(), 1);
        let bucket = &minutes[0];
        assert_eq!(
            bucket.bucket_start, start,
            "folded into the minute's bucket"
        );
        assert!((bucket.value - 2.0).abs() < 1e-9, "a weighted mean");
        assert_eq!((bucket.sample_count, bucket.contributor_count), (12, 2));
        assert_eq!(
            (bucket.release_id, bucket.container_name.as_str()),
            (None, "app")
        );
        assert!(
            history(&pool, &own, 60, None, Some("sidecar"))
                .await
                .is_empty()
        );
        assert!(
            history(&pool, &own, 60, Some(Uuid::new_v4()), None)
                .await
                .is_empty()
        );
        assert!(
            history(&pool, &own, 3600, None, None).await.is_empty(),
            "per step"
        );

        assert_eq!(
            ResourceRepository::detail_retention_days(&pool, own.project_id)
                .await
                .unwrap(),
            7
        );
        assert_eq!(
            ResourceRepository::retention_days_for_update(&pool, own.project_id)
                .await
                .unwrap(),
            (7, 90)
        );
        let horizon = || async {
            sqlx::query_as::<_, (Option<DateTime<Utc>>, Option<DateTime<Utc>>)>(
                "SELECT resource_closed_before,resource_rollup_expired_before FROM projects WHERE id=$1",
            )
            .bind(own.project_id)
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        ResourceRepository::advance_retention_horizons(&pool, own.project_id, start, start)
            .await
            .unwrap();
        ResourceRepository::advance_retention_horizons(
            &pool,
            own.project_id,
            start - Duration::days(1),
            start - Duration::days(1),
        )
        .await
        .unwrap();
        assert_eq!(
            horizon().await,
            (Some(start), Some(start)),
            "horizons never move back"
        );

        let old_hour = start - Duration::days(100);
        point(&pool, &own, None, old_hour, 3600, "cpu", 1.0, 60).await;
        point(&pool, &own, None, start, 3600, "cpu", 1.0, 60).await;
        ResourceRepository::delete_expired_contributions(
            &pool,
            own.project_id,
            start + Duration::hours(1),
            10,
        )
        .await
        .unwrap();
        let contributions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM resource_contributions WHERE project_id=$1")
                .bind(own.project_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(contributions, 0);
        ResourceRepository::delete_expired_rollups(
            &pool,
            own.project_id,
            start + Duration::hours(1),
            start - Duration::days(90),
            10,
        )
        .await
        .unwrap();
        assert!(
            history(&pool, &own, 60, None, None).await.is_empty(),
            "expired minute"
        );
        let hours = history(&pool, &own, 3600, None, None).await;
        assert_eq!(
            hours.iter().map(|p| p.bucket_start).collect::<Vec<_>>(),
            [start],
            "the recent hour stays"
        );
        let old: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM resource_rollup_points WHERE project_id=$1 AND bucket_start=$2",
        )
        .bind(own.project_id)
        .bind(old_hour)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(old, 0, "the expired hour is gone");

        assert_eq!(
            ProjectRepository::organization_id_of(&pool, own.project_id)
                .await
                .unwrap(),
            own.organization_id
        );
        assert!(matches!(
            ProjectRepository::organization_id_of(&pool, Uuid::new_v4()).await,
            Err(sqlx::Error::RowNotFound)
        ));
    }

    /// Episodes resolve per release and to their predecessors; the project's
    /// latest ready episode per application; window summaries and covered
    /// buckets read a release's minute rollups.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn episodes_and_release_windows(pool: PgPool) {
        let own = tenant(&pool, "resources-episodes").await;
        let now = Utc::now();
        let first = observe_revision(
            &pool,
            &own,
            &"a1".repeat(32),
            "rs-a",
            now - Duration::hours(1),
        )
        .await;
        let second = observe_revision(&pool, &own, &"b2".repeat(32), "rs-b", now).await;
        let episode = |release_id: Uuid| {
            ResourceRepository::episode_window::<_, EpisodeWindow>(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                release_id,
            )
        };
        let latest = episode(second).await.unwrap().unwrap();
        assert_eq!(latest.release_id, second);
        assert!(latest.first_ready_at.is_some());
        let before = episode(first).await.unwrap().unwrap();
        let predecessors: Vec<EpisodeWindow> = ResourceRepository::predecessor_episode_windows(
            &pool,
            latest.episode_id,
            own.organization_id,
            own.project_id,
            own.application_id,
        )
        .await
        .unwrap();
        assert_eq!(
            predecessors
                .iter()
                .map(|e| e.episode_id)
                .collect::<Vec<_>>(),
            [before.episode_id]
        );
        assert!(episode(Uuid::new_v4()).await.unwrap().is_none());
        let ready: Vec<ProjectEpisode> =
            ResourceRepository::latest_ready_episodes(&pool, own.organization_id, own.project_id)
                .await
                .unwrap();
        assert_eq!(
            ready
                .iter()
                .map(|e| (e.application_id, e.release_id))
                .collect::<Vec<_>>(),
            [(own.application_id, second)]
        );

        let start = minute();
        point(&pool, &own, Some(second), start, 60, "cpu", 2.0, 60).await;
        point(
            &pool,
            &own,
            Some(second),
            start + Duration::minutes(1),
            60,
            "cpu",
            4.0,
            30,
        )
        .await;
        point(&pool, &own, Some(second), start, 60, "memory", 8.0, 60).await;
        let summary: Vec<Summary> = ResourceRepository::window_summary(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            second,
            start,
            start + Duration::minutes(5),
        )
        .await
        .unwrap();
        assert_eq!(
            summary
                .iter()
                .map(|s| (s.metric.as_str(), s.bucket_count))
                .collect::<Vec<_>>(),
            [("cpu", 2), ("memory", 1)]
        );
        assert!((summary[0].value - 3.0).abs() < 1e-9);
        let covered: Vec<Bucket> = ResourceRepository::covered_buckets(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            second,
            start,
            start + Duration::minutes(5),
        )
        .await
        .unwrap();
        assert_eq!(
            covered
                .iter()
                .map(|b| (b.metric.as_str(), b.bucket_start))
                .collect::<Vec<_>>(),
            [("cpu", start), ("memory", start)],
            "the half-covered minute is left out"
        );
    }

    /// Findings open, age out after two clean evaluations unless still
    /// active, and reopen when found again.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn findings_open_age_and_reopen(pool: PgPool) {
        let own = tenant(&pool, "resources-findings").await;
        let now = Utc::now();
        let baseline = observe_revision(
            &pool,
            &own,
            &"c3".repeat(32),
            "rs-c",
            now - Duration::hours(1),
        )
        .await;
        let target = observe_revision(&pool, &own, &"d4".repeat(32), "rs-d", now).await;
        let finding = Uuid::new_v4();
        let upsert = || {
            ResourceRepository::upsert_finding(
                &pool,
                finding,
                own.organization_id,
                own.project_id,
                own.application_id,
                target,
                baseline,
                "memory_limit_pressure",
                "high",
                "memory",
                1,
                json!({"finding_id": finding}),
                now,
            )
        };
        let open = || {
            ResourceRepository::open_finding_count(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
            )
        };
        let age = |active: Vec<Uuid>| {
            let pool = pool.clone();
            async move {
                ResourceRepository::age_findings(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    own.application_id,
                    target,
                    &active,
                )
                .await
                .unwrap()
            }
        };
        upsert().await.unwrap();
        assert_eq!(open().await.unwrap(), 1);
        age(vec![finding]).await;
        age(vec![finding]).await;
        assert_eq!(open().await.unwrap(), 1, "an active finding does not age");
        age(Vec::new()).await;
        assert_eq!(
            open().await.unwrap(),
            1,
            "one clean evaluation is not enough"
        );
        age(Vec::new()).await;
        assert_eq!(open().await.unwrap(), 0, "closed after two");
        upsert().await.unwrap();
        assert_eq!(open().await.unwrap(), 1, "found again, reopened");
        let clean: i16 = sqlx::query_scalar(
            "SELECT clean_evaluations FROM release_resource_findings WHERE target_release_id=$1",
        )
        .bind(target)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(clean, 0);
    }
}
