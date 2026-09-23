//! Raw runtime-event persistence.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// A stored runtime event as persisted in `runtime_events`.
///
/// This is a persistence row, not an API response shape. Endpoints project it
/// into their own serializable types so that the table layout and the public
/// JSON contract can evolve independently.
#[derive(Clone, Debug, FromRow, PartialEq)]
pub struct StoredEvent {
    pub event_id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub event_kind: String,
    pub observed_at: DateTime<Utc>,
    pub payload: Value,
}

/// Queries against the `runtime_events` table.
#[derive(Clone, Copy, Debug)]
pub struct EventRepository;

impl EventRepository {
    /// When the application's earliest and latest retained events were
    /// received; both `None` when it has none.
    pub async fn received_window<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<(Option<DateTime<Utc>>, Option<DateTime<Utc>>), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Option<DateTime<Utc>>, Option<DateTime<Utc>>)>("SELECT min(received_at),max(received_at) FROM runtime_events WHERE organization_id=$1 AND project_id=$2 AND application_id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_one(executor)
            .await
    }

    /// One raw event as an occurrence, within the organization.
    pub async fn occurrence<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT e.id,e.event_id,e.observed_at,e.received_at,e.node_name,e.namespace,e.pod_name,e.container_name,e.process_command,e.event_kind,e.payload,COALESCE((SELECT jsonb_build_object('retention_incomplete',o.retention_incomplete,'status',o.status,'candidate_count',o.candidate_count,'tolerance_seconds',o.tolerance_seconds,'related_event_ids',COALESCE((SELECT jsonb_agg(c.kernel_event_id) FROM runtime_event_correlations c WHERE c.lifecycle_event_id=e.id),'[]'::jsonb)) FROM runtime_event_correlation_outcomes o WHERE o.event_id=e.id),jsonb_build_object('status','absent','candidate_count',0,'related_event_ids','[]'::jsonb)) correlation,e.release_id,r.version release_version,CASE WHEN r.id IS NULL THEN 'Unattributed' ELSE release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) END release_display_name FROM runtime_events e LEFT JOIN releases r ON r.id=e.release_id LEFT JOIN applications a ON a.id=r.application_id WHERE e.organization_id=$1 AND e.id=$2")
            .bind(organization_id)
            .bind(event_id)
            .fetch_optional(executor)
            .await
    }

    /// Evidence correlated with one raw event, up to `limit`.
    pub async fn related_evidence<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        event_id: Uuid,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT e.id,e.event_id,e.observed_at,e.received_at,e.event_kind,COALESCE(e.payload#>>'{data,source}','unknown') source,e.payload FROM runtime_event_correlations c JOIN runtime_events e ON e.id=CASE WHEN c.lifecycle_event_id=$2 THEN c.kernel_event_id ELSE c.lifecycle_event_id END WHERE c.organization_id=$1 AND (c.lifecycle_event_id=$2 OR c.kernel_event_id=$2) ORDER BY e.observed_at,e.received_at,e.id LIMIT $3")
            .bind(organization_id)
            .bind(event_id)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Returns the most recent events of one kind for an application, newest
    /// first.
    ///
    /// `limit` is clamped to `1..=1000` inside the repository so that no call
    /// site can issue an unbounded scan.
    pub async fn recent_for_application<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        event_kind: &str,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<StoredEvent>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, StoredEvent>(
            r#"
            SELECT event_id, organization_id, project_id, application_id,
                   event_kind, observed_at, payload
            FROM runtime_events
            WHERE organization_id = $1
              AND project_id = $2
              AND application_id = $3
              AND event_kind = $4
              AND observed_at >= $5
            ORDER BY observed_at DESC
            LIMIT $6
            "#,
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(event_kind)
        .bind(since)
        .bind(limit.clamp(1, 1000))
        .fetch_all(executor)
        .await
    }
}
