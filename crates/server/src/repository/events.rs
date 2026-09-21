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
