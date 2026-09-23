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
