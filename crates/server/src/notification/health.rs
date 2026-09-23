use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationHealthState {
    Disabled,
    Idle,
    Backlogged,
    Retrying,
    Failing,
    Draining,
}

impl NotificationHealthState {
    #[must_use]
    pub const fn metric_code(self) -> u64 {
        match self {
            Self::Disabled => 0,
            Self::Idle => 1,
            Self::Backlogged => 2,
            Self::Retrying => 3,
            Self::Failing => 4,
            Self::Draining => 5,
        }
    }
}

#[derive(Clone, Debug, Default, FromRow, PartialEq, Eq)]
pub struct NotificationQueueSnapshot {
    pub enabled_destination_count: i64,
    pub pending_count: i64,
    pub due_count: i64,
    pub retrying_count: i64,
    pub in_flight_count: i64,
    pub expired_lease_count: i64,
    pub failed_count: i64,
    pub oldest_due_age_seconds: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotificationHealthResponse {
    pub state: NotificationHealthState,
    pub delivery_enabled: bool,
    pub enabled_destination_count: i64,
    pub pending_count: i64,
    pub due_count: i64,
    pub retrying_count: i64,
    pub in_flight_count: i64,
    pub expired_lease_count: i64,
    pub failed_count: i64,
    pub oldest_due_age_seconds: Option<i64>,
    pub observed_at: DateTime<Utc>,
}

impl NotificationHealthResponse {
    #[must_use]
    pub fn from_snapshot(
        delivery_enabled: bool,
        local_draining: bool,
        snapshot: &NotificationQueueSnapshot,
    ) -> Self {
        let state = derive_state(delivery_enabled, local_draining, snapshot);
        Self {
            state,
            delivery_enabled,
            enabled_destination_count: non_negative(snapshot.enabled_destination_count),
            pending_count: non_negative(snapshot.pending_count),
            due_count: non_negative(snapshot.due_count),
            retrying_count: non_negative(snapshot.retrying_count),
            in_flight_count: non_negative(snapshot.in_flight_count),
            expired_lease_count: non_negative(snapshot.expired_lease_count),
            failed_count: non_negative(snapshot.failed_count),
            oldest_due_age_seconds: snapshot.oldest_due_age_seconds.map(non_negative),
            observed_at: Utc::now(),
        }
    }
}

#[must_use]
pub fn derive_state(
    delivery_enabled: bool,
    local_draining: bool,
    snapshot: &NotificationQueueSnapshot,
) -> NotificationHealthState {
    if local_draining || (!delivery_enabled && snapshot.in_flight_count > 0) {
        NotificationHealthState::Draining
    } else if !delivery_enabled {
        NotificationHealthState::Disabled
    } else if snapshot.failed_count > 0 || snapshot.expired_lease_count > 0 {
        NotificationHealthState::Failing
    } else if snapshot.retrying_count > 0 {
        NotificationHealthState::Retrying
    } else if snapshot.due_count > 0 || snapshot.pending_count > 0 {
        NotificationHealthState::Backlogged
    } else {
        NotificationHealthState::Idle
    }
}

pub async fn load_project_snapshot(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<NotificationQueueSnapshot, sqlx::Error> {
    sqlx::query_as(PROJECT_SNAPSHOT_SQL)
        .bind(organization_id)
        .bind(project_id)
        .fetch_one(pool)
        .await
}

pub async fn load_global_snapshot(pool: &PgPool) -> Result<NotificationQueueSnapshot, sqlx::Error> {
    sqlx::query_as(GLOBAL_SNAPSHOT_SQL).fetch_one(pool).await
}

fn non_negative(value: i64) -> i64 {
    value.max(0)
}

const PROJECT_SNAPSHOT_SQL: &str = "SELECT (SELECT count(*) FROM webhook_destinations WHERE organization_id=$1 AND project_id=$2 AND enabled=true) enabled_destination_count, count(*) FILTER (WHERE status='pending') pending_count, count(*) FILTER (WHERE status='pending' AND available_at<=now()) due_count, count(*) FILTER (WHERE status='pending' AND attempt_count>0) retrying_count, count(*) FILTER (WHERE status='in_flight') in_flight_count, count(*) FILTER (WHERE status='in_flight' AND lease_expires_at<=now()) expired_lease_count, count(*) FILTER (WHERE status='failed') failed_count, CASE WHEN count(*) FILTER (WHERE status='pending' AND available_at<=now())=0 THEN NULL ELSE GREATEST(EXTRACT(EPOCH FROM (now()-min(available_at) FILTER (WHERE status='pending' AND available_at<=now())))::bigint,0) END oldest_due_age_seconds FROM notification_deliveries WHERE organization_id=$1 AND project_id=$2";

const GLOBAL_SNAPSHOT_SQL: &str = "SELECT (SELECT count(*) FROM webhook_destinations WHERE enabled=true) enabled_destination_count, count(*) FILTER (WHERE status='pending') pending_count, count(*) FILTER (WHERE status='pending' AND available_at<=now()) due_count, count(*) FILTER (WHERE status='pending' AND attempt_count>0) retrying_count, count(*) FILTER (WHERE status='in_flight') in_flight_count, count(*) FILTER (WHERE status='in_flight' AND lease_expires_at<=now()) expired_lease_count, count(*) FILTER (WHERE status='failed') failed_count, CASE WHEN count(*) FILTER (WHERE status='pending' AND available_at<=now())=0 THEN NULL ELSE GREATEST(EXTRACT(EPOCH FROM (now()-min(available_at) FILTER (WHERE status='pending' AND available_at<=now())))::bigint,0) END oldest_due_age_seconds FROM notification_deliveries";

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> NotificationQueueSnapshot {
        NotificationQueueSnapshot::default()
    }

    #[test]
    fn state_precedence_is_stable() {
        assert_eq!(
            derive_state(false, false, &snapshot()),
            NotificationHealthState::Disabled
        );
        assert_eq!(
            derive_state(true, false, &snapshot()),
            NotificationHealthState::Idle
        );
        assert_eq!(
            derive_state(
                true,
                false,
                &NotificationQueueSnapshot {
                    pending_count: 1,
                    ..snapshot()
                }
            ),
            NotificationHealthState::Backlogged
        );
        assert_eq!(
            derive_state(
                true,
                false,
                &NotificationQueueSnapshot {
                    pending_count: 1,
                    retrying_count: 1,
                    ..snapshot()
                }
            ),
            NotificationHealthState::Retrying
        );
        assert_eq!(
            derive_state(
                true,
                false,
                &NotificationQueueSnapshot {
                    failed_count: 1,
                    retrying_count: 1,
                    ..snapshot()
                }
            ),
            NotificationHealthState::Failing
        );
        assert_eq!(
            derive_state(
                false,
                false,
                &NotificationQueueSnapshot {
                    in_flight_count: 1,
                    ..snapshot()
                }
            ),
            NotificationHealthState::Draining
        );
        assert_eq!(
            derive_state(true, true, &snapshot()),
            NotificationHealthState::Draining
        );
        for (state, metric_code) in [
            (NotificationHealthState::Disabled, 0),
            (NotificationHealthState::Idle, 1),
            (NotificationHealthState::Backlogged, 2),
            (NotificationHealthState::Retrying, 3),
            (NotificationHealthState::Failing, 4),
            (NotificationHealthState::Draining, 5),
        ] {
            assert_eq!(state.metric_code(), metric_code);
        }
    }

    #[test]
    fn response_clamps_invalid_negative_database_values() {
        let response = NotificationHealthResponse::from_snapshot(
            true,
            false,
            &NotificationQueueSnapshot {
                pending_count: -1,
                oldest_due_age_seconds: Some(-10),
                ..snapshot()
            },
        );
        assert_eq!(response.pending_count, 0);
        assert_eq!(response.oldest_due_age_seconds, Some(0));
        let serialized = serde_json::to_string(&response).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("url"));
    }
}
