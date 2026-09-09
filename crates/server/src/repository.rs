use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

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

#[derive(Clone, Debug)]
pub struct EventRepository {
    pool: PgPool,
}

impl EventRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn recent_for_application(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        event_kind: &str,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<StoredEvent>, sqlx::Error> {
        sqlx::query_as::<_, StoredEvent>(
            "SELECT event_id, organization_id, project_id, application_id, event_kind, observed_at, payload FROM runtime_events WHERE organization_id = $1 AND project_id = $2 AND application_id = $3 AND event_kind = $4 AND observed_at >= $5 ORDER BY observed_at DESC LIMIT $6",
        )
        .bind(organization_id).bind(project_id).bind(application_id).bind(event_kind).bind(since).bind(limit.clamp(1, 1000))
        .fetch_all(&self.pool).await
    }
}
