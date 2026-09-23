//! Agent health persistence: the agents registered for an application, their
//! heartbeat and signal buckets, diagnostic counter baselines and deltas, their
//! sessions, and the reads behind the agent health endpoint.
//!
//! Writes arrive from the agent protocol, reads from the health endpoint. The
//! read projections belong to that endpoint, so they are generic over the row
//! type and document the columns they select.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// Agent registration, heartbeats, diagnostics and the health reads over them.
#[derive(Clone, Copy, Debug)]
pub struct AgentHealthRepository;

impl AgentHealthRepository {
    /// Deletes signal and diagnostic buckets older than `cutoff`, at most 500
    /// rows per table per call, oldest first. The bound keeps each pass short;
    /// the caller runs it on every heartbeat, so the backlog drains over time.
    ///
    /// Issues a statement per table on one connection; pass `&mut *tx`.
    pub async fn prune_buckets(
        conn: &mut sqlx::PgConnection,
        cutoff: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        for table in [
            "application_agent_signal_buckets",
            "application_agent_diagnostic_buckets",
        ] {
            let query = format!(
                "DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM {table} WHERE bucket_at<$1 ORDER BY bucket_at LIMIT 500)"
            );
            sqlx::query(&query).bind(cutoff).execute(&mut *conn).await?;
        }
        Ok(())
    }

    /// Records that an agent serves an application from a cluster, with the
    /// capabilities it reported.
    pub async fn register_agent<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
        agent_id: Uuid,
        capabilities: serde_json::Value,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO application_agents(organization_id,project_id,application_id,cluster_id,agent_id,capabilities) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(organization_id,project_id,application_id,agent_id) DO UPDATE SET cluster_id=EXCLUDED.cluster_id,capabilities=EXCLUDED.capabilities,authenticated_at=now(),last_session_ended_at=NULL")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cluster_id)
            .bind(agent_id)
            .bind(capabilities)
            .execute(executor)
            .await
    }

    /// Records the time of an agent's latest heartbeat.
    pub async fn touch_heartbeat<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        agent_id: Uuid,
        received_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE application_agents SET last_heartbeat_at=$5 WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND agent_id=$4")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(agent_id)
            .bind(received_at)
            .execute(executor)
            .await
    }

    /// Counts a heartbeat into its one-minute signal bucket.
    pub async fn record_signal<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        agent_id: Uuid,
        bucket_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO application_agent_signal_buckets(organization_id,project_id,application_id,agent_id,bucket_at,first_received_at,last_received_at) VALUES($1,$2,$3,$4,$5,$6,$6) ON CONFLICT(organization_id,project_id,application_id,agent_id,bucket_at) DO UPDATE SET received_count=LEAST(application_agent_signal_buckets.received_count+1,120),last_received_at=GREATEST(application_agent_signal_buckets.last_received_at,EXCLUDED.last_received_at)")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(agent_id)
            .bind(bucket_at)
            .bind(received_at)
            .execute(executor)
            .await
    }

    /// The agent's previous diagnostic counter snapshot and when it was sent,
    /// from which the next snapshot's deltas are computed.
    pub async fn counter_baseline<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<(DateTime<Utc>, serde_json::Value)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (DateTime<Utc>, serde_json::Value)>("SELECT sent_at,counters FROM application_agent_counter_baselines WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND cluster_id=$4 AND agent_id=$5 FOR UPDATE")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cluster_id)
            .bind(agent_id)
            .fetch_optional(executor)
            .await
    }

    /// Replaces the agent's diagnostic counter snapshot.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_counter_baseline<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
        agent_id: Uuid,
        sent_at: DateTime<Utc>,
        counters: serde_json::Value,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO application_agent_counter_baselines(organization_id,project_id,application_id,cluster_id,agent_id,sent_at,counters) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(organization_id,project_id,application_id,cluster_id,agent_id) DO UPDATE SET sent_at=EXCLUDED.sent_at,counters=EXCLUDED.counters")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cluster_id)
            .bind(agent_id)
            .bind(sent_at)
            .bind(counters)
            .execute(executor)
            .await
    }

    /// Adds diagnostic counter deltas into their one-minute bucket. `reset`
    /// marks a bucket in which the agent's counters went backwards, so its
    /// deltas could not be computed.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_diagnostic_deltas<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
        agent_id: Uuid,
        bucket_at: DateTime<Utc>,
        reset: bool,
        dropped: i64,
        rate_limited: i64,
        decode_failed: i64,
        attribution_failed: i64,
        capacity: i64,
        kernel_lost: i64,
        correlation: i64,
        delivery_retry: i64,
        unsupported: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO application_agent_diagnostic_buckets(organization_id,project_id,application_id,cluster_id,agent_id,bucket_at,reset,dropped,rate_limited,decode_failed,attribution_failed,capacity,kernel_lost,correlation,delivery_retry,unsupported) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(organization_id,project_id,application_id,cluster_id,agent_id,bucket_at) DO UPDATE SET reset=application_agent_diagnostic_buckets.reset OR EXCLUDED.reset,dropped=application_agent_diagnostic_buckets.dropped+EXCLUDED.dropped,rate_limited=application_agent_diagnostic_buckets.rate_limited+EXCLUDED.rate_limited,decode_failed=application_agent_diagnostic_buckets.decode_failed+EXCLUDED.decode_failed,attribution_failed=application_agent_diagnostic_buckets.attribution_failed+EXCLUDED.attribution_failed,capacity=application_agent_diagnostic_buckets.capacity+EXCLUDED.capacity,kernel_lost=application_agent_diagnostic_buckets.kernel_lost+EXCLUDED.kernel_lost,correlation=application_agent_diagnostic_buckets.correlation+EXCLUDED.correlation,delivery_retry=application_agent_diagnostic_buckets.delivery_retry+EXCLUDED.delivery_retry,unsupported=application_agent_diagnostic_buckets.unsupported+EXCLUDED.unsupported")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cluster_id)
            .bind(agent_id)
            .bind(bucket_at)
            .bind(reset)
            .bind(dropped)
            .bind(rate_limited)
            .bind(decode_failed)
            .bind(attribution_failed)
            .bind(capacity)
            .bind(kernel_lost)
            .bind(correlation)
            .bind(delivery_retry)
            .bind(unsupported)
            .execute(executor)
            .await
    }

    /// Marks an agent session disconnected, unless it already is.
    pub async fn end_session<'e, E>(
        executor: E,
        session_id: Uuid,
        disconnected_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            "UPDATE agent_sessions SET disconnected_at=$2 WHERE id=$1 AND disconnected_at IS NULL",
        )
        .bind(session_id)
        .bind(disconnected_at)
        .execute(executor)
        .await
    }

    /// Records when the agent's latest session ended.
    pub async fn record_session_end<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        agent_id: Uuid,
        ended_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE application_agents SET last_session_ended_at=$5 WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND agent_id=$4")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(agent_id)
            .bind(ended_at)
            .execute(executor)
            .await
    }

    /// Reports whether a health-page cursor names an agent of this
    /// application authenticated at exactly the cursor's time.
    pub async fn cursor_is_valid<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        agent_id: Uuid,
        authenticated_at: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM application_agents WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND agent_id=$4 AND authenticated_at=$5)")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(agent_id)
            .bind(authenticated_at)
            .fetch_one(executor)
            .await
    }

    /// Reports whether the application exists and the user may see it:
    /// through an organization role that inherits project access, or through
    /// a membership of its project.
    pub async fn application_visible<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        inherits_project_access: bool,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM applications a WHERE a.organization_id=$1 AND a.project_id=$2 AND a.id=$3 AND ($4 OR EXISTS(SELECT 1 FROM project_memberships m WHERE m.organization_id=$1 AND m.project_id=$2 AND m.user_id=$5)))")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(inherits_project_access)
            .bind(user_id)
            .fetch_one(executor)
            .await
    }

    /// A page of the application's agents, most recently authenticated first,
    /// after the cursor when one is given, with their cluster's name.
    pub async fn agent_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cursor_authenticated_at: Option<DateTime<Utc>>,
        cursor_agent_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT aa.organization_id,aa.project_id,aa.application_id,aa.agent_id,aa.cluster_id,c.name cluster_name,a.node_name,a.agent_version,a.architecture,a.kernel_release,aa.capabilities,aa.authenticated_at,aa.history_started_at,aa.last_heartbeat_at,(SELECT min(e.observed_at) FROM runtime_events e WHERE e.organization_id=aa.organization_id AND e.project_id=aa.project_id AND e.application_id=aa.application_id AND e.agent_id=aa.agent_id) first_event_at,(SELECT max(e.observed_at) FROM runtime_events e WHERE e.organization_id=aa.organization_id AND e.project_id=aa.project_id AND e.application_id=aa.application_id AND e.agent_id=aa.agent_id) last_event_at FROM application_agents aa JOIN agents a ON a.organization_id=aa.organization_id AND a.cluster_id=aa.cluster_id AND a.id=aa.agent_id JOIN clusters c ON c.organization_id=aa.organization_id AND c.id=aa.cluster_id WHERE aa.organization_id=$1 AND aa.project_id=$2 AND aa.application_id=$3 AND ($4::timestamptz IS NULL OR (aa.authenticated_at,aa.agent_id)<($4,$5)) ORDER BY aa.authenticated_at DESC,aa.agent_id DESC LIMIT $6")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cursor_authenticated_at)
            .bind(cursor_agent_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// An agent's signal and diagnostic buckets rolled up to `step_minutes`
    /// over `[start, end)`.
    #[allow(clippy::too_many_arguments)]
    pub async fn buckets<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        agent_id: Uuid,
        cluster_id: Uuid,
        step_minutes: i64,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH signals AS (SELECT date_bin(($6::text || ' minutes')::interval,bucket_at,'1970-01-01'::timestamptz) bucket_at,TRUE received FROM application_agent_signal_buckets WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND agent_id=$4 AND bucket_at >= $7 AND bucket_at < $8 GROUP BY 1), diagnostics AS (SELECT date_bin(($6::text || ' minutes')::interval,bucket_at,'1970-01-01'::timestamptz) bucket_at,bool_or(reset) reset,sum(dropped)::bigint dropped,sum(rate_limited)::bigint rate_limited,sum(decode_failed)::bigint decode_failed,sum(attribution_failed)::bigint attribution_failed,sum(capacity)::bigint capacity,sum(kernel_lost)::bigint kernel_lost,sum(correlation)::bigint correlation,sum(delivery_retry)::bigint delivery_retry,sum(unsupported)::bigint unsupported FROM application_agent_diagnostic_buckets WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND cluster_id=$5 AND agent_id=$4 AND bucket_at >= $7 AND bucket_at < $8 GROUP BY 1) SELECT COALESCE(s.bucket_at,d.bucket_at) bucket_at,COALESCE(s.received,FALSE) received,COALESCE(d.reset,FALSE) reset,COALESCE(d.dropped,0) dropped,COALESCE(d.rate_limited,0) rate_limited,COALESCE(d.decode_failed,0) decode_failed,COALESCE(d.attribution_failed,0) attribution_failed,COALESCE(d.capacity,0) capacity,COALESCE(d.kernel_lost,0) kernel_lost,COALESCE(d.correlation,0) correlation,COALESCE(d.delivery_retry,0) delivery_retry,COALESCE(d.unsupported,0) unsupported FROM signals s FULL OUTER JOIN diagnostics d USING(bucket_at) ORDER BY bucket_at")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(agent_id)
            .bind(cluster_id)
            .bind(step_minutes)
            .bind(start)
            .bind(end)
            .fetch_all(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use serde_json::json;
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::AgentHealthRepository;
    use crate::repository::memberships::MembershipRepository;
    use crate::repository::test_support::{Tenant, exec, ingest, tenant, user};

    #[derive(sqlx::FromRow)]
    struct AgentRow {
        agent_id: Uuid,
        cluster_name: String,
        node_name: String,
        capabilities: serde_json::Value,
        authenticated_at: DateTime<Utc>,
        last_heartbeat_at: Option<DateTime<Utc>>,
        first_event_at: Option<DateTime<Utc>>,
        last_event_at: Option<DateTime<Utc>>,
    }

    #[derive(sqlx::FromRow)]
    struct Rollup {
        bucket_at: DateTime<Utc>,
        received: bool,
        reset: bool,
        dropped: i64,
        unsupported: i64,
    }

    fn at(minute: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap() + Duration::minutes(minute)
    }

    async fn register(
        pool: &PgPool,
        own: &Tenant,
        agent_id: Uuid,
        capabilities: serde_json::Value,
    ) {
        AgentHealthRepository::register_agent(
            pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            own.cluster_id,
            agent_id,
            capabilities,
        )
        .await
        .unwrap();
    }

    async fn page(
        pool: &PgPool,
        own: &Tenant,
        cursor: Option<(DateTime<Utc>, Uuid)>,
    ) -> Vec<AgentRow> {
        AgentHealthRepository::agent_page(
            pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            cursor.map(|c| c.0),
            cursor.map(|c| c.1),
            10,
        )
        .await
        .unwrap()
    }

    async fn buckets(pool: &PgPool, own: &Tenant, step_minutes: i64) -> Vec<Rollup> {
        AgentHealthRepository::buckets(
            pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            own.agent_id,
            own.cluster_id,
            step_minutes,
            at(0),
            at(60),
        )
        .await
        .unwrap()
    }

    /// Registration upserts the agent, refreshing its capabilities and
    /// clearing a recorded session end; heartbeats, session ends and events
    /// show up on the health page, which pages newest authentication first.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn agents_register_and_page_newest_first(pool: PgPool) {
        let own = tenant(&pool, "agent-health-page").await;
        register(&pool, &own, own.agent_id, json!(["exec"])).await;
        AgentHealthRepository::record_session_end(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            own.agent_id,
            at(1),
        )
        .await
        .unwrap();
        register(&pool, &own, own.agent_id, json!(["exec", "dns"])).await;
        let ended: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT last_session_ended_at FROM application_agents WHERE agent_id=$1",
        )
        .bind(own.agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ended, None, "registering again clears the session end");

        AgentHealthRepository::touch_heartbeat(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            own.agent_id,
            at(5),
        )
        .await
        .unwrap();
        let observed = Utc::now();
        ingest(&pool, &own, &[exec(&own, "/bin/a", observed)]).await;

        let other = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node-b','test')",
        )
        .bind(other)
        .bind(own.organization_id)
        .bind(own.cluster_id)
        .execute(&pool)
        .await
        .unwrap();
        register(&pool, &own, other, json!([])).await;
        sqlx::query("UPDATE application_agents SET authenticated_at=$2 WHERE agent_id=$1")
            .bind(own.agent_id)
            .bind(at(10))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE application_agents SET authenticated_at=$2 WHERE agent_id=$1")
            .bind(other)
            .bind(at(20))
            .execute(&pool)
            .await
            .unwrap();

        let first = page(&pool, &own, None).await;
        assert_eq!(
            first.iter().map(|a| a.agent_id).collect::<Vec<_>>(),
            [other, own.agent_id]
        );
        assert_eq!(first[0].node_name, "node-b");
        assert_eq!(first[0].first_event_at, None);
        let agent = &first[1];
        assert_eq!(agent.cluster_name, "Cluster");
        assert_eq!(agent.node_name, "node-a");
        assert_eq!(agent.capabilities, json!(["exec", "dns"]));
        assert_eq!(agent.authenticated_at, at(10));
        assert_eq!(agent.last_heartbeat_at, Some(at(5)));
        assert!(agent.first_event_at.is_some());
        assert_eq!(agent.first_event_at, agent.last_event_at);

        let rest = page(&pool, &own, Some((at(20), other))).await;
        assert_eq!(
            rest.iter().map(|a| a.agent_id).collect::<Vec<_>>(),
            [own.agent_id]
        );

        let stranger = tenant(&pool, "agent-health-stranger").await;
        assert!(page(&pool, &stranger, None).await.is_empty());
    }

    /// A cursor is valid only for this application's agent at exactly the
    /// authentication time it names.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_cursor_names_an_exact_authentication(pool: PgPool) {
        let own = tenant(&pool, "agent-health-cursor").await;
        register(&pool, &own, own.agent_id, json!([])).await;
        sqlx::query("UPDATE application_agents SET authenticated_at=$2 WHERE agent_id=$1")
            .bind(own.agent_id)
            .bind(at(10))
            .execute(&pool)
            .await
            .unwrap();
        let valid = |application_id: Uuid, agent_id: Uuid, time: DateTime<Utc>| {
            let pool = pool.clone();
            async move {
                AgentHealthRepository::cursor_is_valid(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    application_id,
                    agent_id,
                    time,
                )
                .await
                .unwrap()
            }
        };
        assert!(valid(own.application_id, own.agent_id, at(10)).await);
        assert!(!valid(own.application_id, own.agent_id, at(11)).await);
        assert!(!valid(own.application_id, Uuid::new_v4(), at(10)).await);
        assert!(!valid(Uuid::new_v4(), own.agent_id, at(10)).await);
    }

    /// An application is visible through an inheriting organization role or
    /// a membership of its project, and never when it does not exist.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn application_visibility_follows_project_access(pool: PgPool) {
        let own = tenant(&pool, "agent-health-visibility").await;
        let member = user(&pool).await;
        MembershipRepository::insert_organization_role(
            &pool,
            own.organization_id,
            member,
            "member",
        )
        .await
        .unwrap();
        let visible = |application_id: Uuid, inherits: bool| {
            let pool = pool.clone();
            async move {
                AgentHealthRepository::application_visible(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    application_id,
                    inherits,
                    member,
                )
                .await
                .unwrap()
            }
        };
        assert!(visible(own.application_id, true).await);
        assert!(!visible(own.application_id, false).await);
        assert!(!visible(Uuid::new_v4(), true).await);

        MembershipRepository::insert_project_role(
            &pool,
            own.organization_id,
            own.project_id,
            member,
            "member",
        )
        .await
        .unwrap();
        assert!(visible(own.application_id, false).await);
    }

    /// The counter baseline is absent until stored, then replaced in place.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_counter_baseline_is_replaced(pool: PgPool) {
        let own = tenant(&pool, "agent-health-baseline").await;
        register(&pool, &own, own.agent_id, json!([])).await;
        let read = || {
            let pool = pool.clone();
            async move {
                AgentHealthRepository::counter_baseline(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    own.application_id,
                    own.cluster_id,
                    own.agent_id,
                )
                .await
                .unwrap()
            }
        };
        assert_eq!(read().await, None);
        for (minute, dropped) in [(1, 3), (2, 7)] {
            AgentHealthRepository::store_counter_baseline(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                own.cluster_id,
                own.agent_id,
                at(minute),
                json!([dropped]),
            )
            .await
            .unwrap();
        }
        assert_eq!(read().await, Some((at(2), json!([7]))));
    }

    /// Signals count per minute and diagnostics accumulate per minute, with a
    /// reset sticking to its bucket; the read rolls both up to the step and
    /// joins them, and pruning removes only buckets before the cutoff.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn buckets_accumulate_roll_up_and_prune(pool: PgPool) {
        let own = tenant(&pool, "agent-health-buckets").await;
        register(&pool, &own, own.agent_id, json!([])).await;
        let signal = |minute: i64, second: i64| {
            let pool = pool.clone();
            async move {
                AgentHealthRepository::record_signal(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    own.application_id,
                    own.agent_id,
                    at(minute),
                    at(minute) + Duration::seconds(second),
                )
                .await
                .unwrap();
            }
        };
        signal(0, 30).await;
        signal(0, 10).await;
        signal(6, 0).await;
        let counts: (i32, DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
            "SELECT received_count,first_received_at,last_received_at FROM application_agent_signal_buckets WHERE bucket_at=$1",
        )
        .bind(at(0))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            counts,
            (
                2,
                at(0) + Duration::seconds(30),
                at(0) + Duration::seconds(30)
            ),
            "the latest receipt wins; the first stays"
        );

        let deltas = |minute: i64, reset: bool, dropped: i64| {
            let pool = pool.clone();
            async move {
                AgentHealthRepository::add_diagnostic_deltas(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    own.application_id,
                    own.cluster_id,
                    own.agent_id,
                    at(minute),
                    reset,
                    dropped,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    1,
                )
                .await
                .unwrap();
            }
        };
        deltas(1, true, 2).await;
        deltas(1, false, 3).await;
        deltas(12, false, 4).await;

        let minutes = buckets(&pool, &own, 1).await;
        let shape: Vec<_> = minutes
            .iter()
            .map(|b| (b.bucket_at, b.received, b.reset, b.dropped, b.unsupported))
            .collect();
        assert_eq!(
            shape,
            [
                (at(0), true, false, 0, 0),
                (at(1), false, true, 5, 2),
                (at(6), true, false, 0, 0),
                (at(12), false, false, 4, 1),
            ]
        );
        let rolled = buckets(&pool, &own, 5).await;
        let shape: Vec<_> = rolled
            .iter()
            .map(|b| (b.bucket_at, b.received, b.reset, b.dropped, b.unsupported))
            .collect();
        assert_eq!(
            shape,
            [
                (at(0), true, true, 5, 2),
                (at(5), true, false, 0, 0),
                (at(10), false, false, 4, 1),
            ]
        );

        let mut conn = pool.acquire().await.unwrap();
        AgentHealthRepository::prune_buckets(&mut conn, at(6))
            .await
            .unwrap();
        drop(conn);
        let left: Vec<_> = buckets(&pool, &own, 1)
            .await
            .iter()
            .map(|b| b.bucket_at)
            .collect();
        assert_eq!(left, [at(6), at(12)]);
    }

    /// Ending a session sets its disconnect time once; a second end keeps it.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_session_ends_once(pool: PgPool) {
        let own = tenant(&pool, "agent-health-session").await;
        let session = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO agent_sessions(id,organization_id,cluster_id,agent_id,protocol_version) VALUES($1,$2,$3,$4,1)",
        )
        .bind(session)
        .bind(own.organization_id)
        .bind(own.cluster_id)
        .bind(own.agent_id)
        .execute(&pool)
        .await
        .unwrap();
        let first = AgentHealthRepository::end_session(&pool, session, at(1))
            .await
            .unwrap();
        let second = AgentHealthRepository::end_session(&pool, session, at(2))
            .await
            .unwrap();
        assert_eq!((first.rows_affected(), second.rows_affected()), (1, 0));
        let disconnected: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT disconnected_at FROM agent_sessions WHERE id=$1")
                .bind(session)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(disconnected, Some(at(1)));
    }
}
