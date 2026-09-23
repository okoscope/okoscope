//! Notification deliveries: one per destination and outbox message (or test),
//! leased to a worker, attempted until they succeed, fail for good, or are
//! cancelled, with a record of every attempt.
//!
//! Reads returning projections owned by the notification endpoints are
//! generic over the row type and document the columns they select.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

const PROJECT_SNAPSHOT_SQL: &str = "SELECT (SELECT count(*) FROM webhook_destinations WHERE organization_id=$1 AND project_id=$2 AND enabled=true) enabled_destination_count, count(*) FILTER (WHERE status='pending') pending_count, count(*) FILTER (WHERE status='pending' AND available_at<=now()) due_count, count(*) FILTER (WHERE status='pending' AND attempt_count>0) retrying_count, count(*) FILTER (WHERE status='in_flight') in_flight_count, count(*) FILTER (WHERE status='in_flight' AND lease_expires_at<=now()) expired_lease_count, count(*) FILTER (WHERE status='failed') failed_count, CASE WHEN count(*) FILTER (WHERE status='pending' AND available_at<=now())=0 THEN NULL ELSE GREATEST(EXTRACT(EPOCH FROM (now()-min(available_at) FILTER (WHERE status='pending' AND available_at<=now())))::bigint,0) END oldest_due_age_seconds FROM notification_deliveries WHERE organization_id=$1 AND project_id=$2";

const GLOBAL_SNAPSHOT_SQL: &str = "SELECT (SELECT count(*) FROM webhook_destinations WHERE enabled=true) enabled_destination_count, count(*) FILTER (WHERE status='pending') pending_count, count(*) FILTER (WHERE status='pending' AND available_at<=now()) due_count, count(*) FILTER (WHERE status='pending' AND attempt_count>0) retrying_count, count(*) FILTER (WHERE status='in_flight') in_flight_count, count(*) FILTER (WHERE status='in_flight' AND lease_expires_at<=now()) expired_lease_count, count(*) FILTER (WHERE status='failed') failed_count, CASE WHEN count(*) FILTER (WHERE status='pending' AND available_at<=now())=0 THEN NULL ELSE GREATEST(EXTRACT(EPOCH FROM (now()-min(available_at) FILTER (WHERE status='pending' AND available_at<=now())))::bigint,0) END oldest_due_age_seconds FROM notification_deliveries";

/// Notification deliveries and their attempts.
#[derive(Clone, Copy, Debug)]
pub struct NotificationDeliveryRepository;

impl NotificationDeliveryRepository {
    /// The project's delivery queue: enabled destinations, pending, due,
    /// retrying, in-flight, lease-expired and failed deliveries, and how long
    /// the oldest due delivery has waited.
    ///
    /// Selects `enabled_destination_count`, `pending_count`, `due_count`,
    /// `retrying_count`, `in_flight_count`, `expired_lease_count`,
    /// `failed_count` and `oldest_due_age_seconds`.
    pub async fn project_queue_snapshot<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as(PROJECT_SNAPSHOT_SQL)
            .bind(organization_id)
            .bind(project_id)
            .fetch_one(executor)
            .await
    }

    /// The delivery queue across all projects, with the columns of
    /// [`Self::project_queue_snapshot`].
    pub async fn queue_snapshot<'e, E, T>(executor: E) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as(GLOBAL_SNAPSHOT_SQL)
            .fetch_one(executor)
            .await
    }

    /// Returns a failed delivery to pending under a new recovery generation,
    /// clearing its attempts, lease and error. Affects no row unless it is
    /// failed.
    pub async fn requeue_failed<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        delivery_id: Uuid,
        recovery_generation: i32,
        operation_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE notification_deliveries SET status='pending',recovery_generation=$4,attempt_count=0,available_at=now(),lease_owner=NULL,lease_expires_at=NULL,terminal_at=NULL,last_error_class=NULL,last_error=NULL,last_recovery_operation_id=$5,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND id=$3 AND status='failed'")
            .bind(organization_id)
            .bind(project_id)
            .bind(delivery_id)
            .bind(recovery_generation)
            .bind(operation_id)
            .execute(executor)
            .await
    }

    /// Cancels a pending delivery on a user's request. Affects no row unless
    /// it is pending.
    pub async fn cancel_pending<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        delivery_id: Uuid,
        operation_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE notification_deliveries SET status='cancelled',terminal_at=now(),last_error_class='user_cancelled',last_error='delivery cancelled by authenticated project user',last_recovery_operation_id=$4,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND id=$3 AND status='pending' AND lease_owner IS NULL AND lease_expires_at IS NULL")
            .bind(organization_id)
            .bind(project_id)
            .bind(delivery_id)
            .bind(operation_id)
            .execute(executor)
            .await
    }

    /// Locks up to `limit` of the project's failed deliveries to enabled
    /// destinations matching the filter, with their recovery generation.
    #[allow(clippy::too_many_arguments)]
    pub async fn failed_for_retry<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Option<Uuid>,
        failed_before: Option<DateTime<Utc>>,
        failed_after: Option<DateTime<Utc>>,
        error_class: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(Uuid, i32)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Uuid, i32)>("SELECT d.id,d.recovery_generation FROM notification_deliveries d JOIN webhook_destinations w ON w.organization_id=d.organization_id AND w.project_id=d.project_id AND w.id=d.destination_id WHERE d.organization_id=$1 AND d.project_id=$2 AND d.status='failed' AND w.enabled=true AND ($3::uuid IS NULL OR d.destination_id=$3) AND ($4::timestamptz IS NULL OR d.terminal_at<$4) AND ($5::timestamptz IS NULL OR d.terminal_at>=$5) AND ($6::text IS NULL OR d.last_error_class=$6) ORDER BY d.terminal_at,d.created_at,d.id FOR UPDATE OF d SKIP LOCKED LIMIT $7")
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .bind(failed_before)
            .bind(failed_after)
            .bind(error_class)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// How many deliveries [`Self::failed_for_retry`] would select without a
    /// limit.
    pub async fn count_failed_for_retry<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Option<Uuid>,
        failed_before: Option<DateTime<Utc>>,
        failed_after: Option<DateTime<Utc>>,
        error_class: Option<&str>,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_deliveries d JOIN webhook_destinations w ON w.organization_id=d.organization_id AND w.project_id=d.project_id AND w.id=d.destination_id WHERE d.organization_id=$1 AND d.project_id=$2 AND d.status='failed' AND w.enabled=true AND ($3::uuid IS NULL OR d.destination_id=$3) AND ($4::timestamptz IS NULL OR d.terminal_at<$4) AND ($5::timestamptz IS NULL OR d.terminal_at>=$5) AND ($6::text IS NULL OR d.last_error_class=$6)")
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .bind(failed_before)
            .bind(failed_after)
            .bind(error_class)
            .fetch_one(executor)
            .await
    }

    /// Locks a delivery of the project for a recovery command and returns
    /// what the command decides on.
    ///
    /// Selects `status`, `destination_enabled`, `lease_expires_at`,
    /// `recovery_generation`, `attempt_count` and `total_attempt_count`.
    pub async fn lock_for_recovery<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        delivery_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT d.status,w.enabled destination_enabled,d.lease_expires_at,d.recovery_generation,d.attempt_count,(SELECT count(*) FROM notification_delivery_attempts a WHERE a.delivery_id=d.id) total_attempt_count FROM notification_deliveries d JOIN webhook_destinations w ON w.organization_id=d.organization_id AND w.project_id=d.project_id AND w.id=d.destination_id WHERE d.organization_id=$1 AND d.project_id=$2 AND d.id=$3 FOR UPDATE OF d")
            .bind(organization_id)
            .bind(project_id)
            .bind(delivery_id)
            .fetch_optional(executor)
            .await
    }

    /// Creates the delivery of a first-seen message to one destination, once
    /// per message and destination: a repeat affects no row. A suppressed
    /// backfill is created already terminal.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_for_outbox<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Uuid,
        outbox_message_id: Uuid,
        source: &str,
        payload: Value,
        status: &str,
        max_attempts: i32,
        terminal_at: Option<DateTime<Utc>>,
        last_error_class: Option<&str>,
        last_error: Option<&str>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO notification_deliveries (id,organization_id,project_id,destination_id,outbox_message_id,origin,source,event_name,payload,status,max_attempts,terminal_at,last_error_class,last_error) VALUES ($1,$2,$3,$4,$5,'outbox',$6,'runtime_group.first_seen',$7,$8,$9,$10,$11,$12) ON CONFLICT (outbox_message_id,destination_id) WHERE outbox_message_id IS NOT NULL DO NOTHING")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .bind(outbox_message_id)
            .bind(source)
            .bind(payload)
            .bind(status)
            .bind(max_attempts)
            .bind(terminal_at)
            .bind(last_error_class)
            .bind(last_error)
            .execute(executor)
            .await
    }

    /// Leases up to `limit` due deliveries to `lease_owner` for
    /// `lease_seconds`: pending ones whose time has come and in-flight ones
    /// whose lease expired, skipping rows another worker holds. Only
    /// deliveries to enabled destinations are returned.
    ///
    /// Selects the delivery's `id`, tenant path, `destination_id`,
    /// `outbox_message_id`, `source`, `event_name`, `payload`,
    /// `recovery_generation`, `attempt_count`, `max_attempts` and
    /// `lease_owner`, and the destination's `url`, `encrypted_secret` and
    /// `secret_nonce`.
    pub async fn claim_due<'e, E, T>(
        executor: E,
        limit: i64,
        lease_owner: Uuid,
        lease_seconds: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH candidates AS (SELECT id FROM notification_deliveries WHERE (status='pending' AND available_at<=now()) OR (status='in_flight' AND lease_expires_at<=now()) ORDER BY available_at,created_at FOR UPDATE SKIP LOCKED LIMIT $1), claimed AS (UPDATE notification_deliveries d SET status='in_flight',lease_owner=$2,lease_expires_at=now()+make_interval(secs=>$3),updated_at=now() FROM candidates c WHERE d.id=c.id RETURNING d.*) SELECT c.id,c.organization_id,c.project_id,c.destination_id,c.outbox_message_id,c.source,c.event_name,c.payload,c.recovery_generation,c.attempt_count,c.max_attempts,c.lease_owner,w.url,w.encrypted_secret,w.secret_nonce FROM claimed c JOIN webhook_destinations w ON w.id=c.destination_id AND w.organization_id=c.organization_id AND w.project_id=c.project_id WHERE w.enabled=true")
            .bind(limit)
            .bind(lease_owner)
            .bind(lease_seconds)
            .fetch_all(executor)
            .await
    }

    /// Creates a single-attempt test delivery already leased to
    /// `lease_owner`.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_test<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Uuid,
        payload: &Value,
        lease_owner: Uuid,
        lease_seconds: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO notification_deliveries (id,organization_id,project_id,destination_id,origin,source,event_name,payload,status,lease_owner,lease_expires_at,max_attempts) VALUES ($1,$2,$3,$4,'test','test','okoscope.test',$5,'in_flight',$6,now()+make_interval(secs=>$7),1)")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .bind(payload)
            .bind(lease_owner)
            .bind(lease_seconds)
            .execute(executor)
            .await
    }

    /// Resolves a delivery id used as a list cursor into its
    /// `(created_at, id)` ordering key.
    pub async fn cursor<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        delivery_id: Uuid,
    ) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (DateTime<Utc>, Uuid)>("SELECT created_at,id FROM notification_deliveries WHERE organization_id=$1 AND project_id=$2 AND id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(delivery_id)
            .fetch_optional(executor)
            .await
    }

    /// A page of the project's deliveries, newest first, after the cursor
    /// when one is given, filtered by destination, status, source, origin and
    /// creation time.
    ///
    /// Selects the delivery with its destination's `destination_name` and
    /// `destination_enabled`; see [`Self::get`].
    #[allow(clippy::too_many_arguments)]
    pub async fn page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Option<Uuid>,
        status: Option<&str>,
        source: Option<&str>,
        origin: Option<&str>,
        since: Option<DateTime<Utc>>,
        cursor_created_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT d.id,d.project_id,d.destination_id,d.outbox_message_id,d.origin,d.source,d.event_name,d.payload,w.name destination_name,w.enabled destination_enabled,d.status,d.available_at,d.recovery_generation,d.attempt_count,(SELECT count(*) FROM notification_delivery_attempts a WHERE a.delivery_id=d.id) total_attempt_count,d.max_attempts,d.last_error_class,d.created_at,d.updated_at,d.terminal_at,d.last_recovery_operation_id FROM notification_deliveries d JOIN webhook_destinations w ON w.organization_id=d.organization_id AND w.project_id=d.project_id AND w.id=d.destination_id WHERE d.organization_id=$1 AND d.project_id=$2 AND ($3::uuid IS NULL OR d.destination_id=$3) AND ($4::text IS NULL OR d.status=$4) AND ($5::text IS NULL OR d.source=$5) AND ($6::text IS NULL OR d.origin=$6) AND ($7::timestamptz IS NULL OR d.created_at >= $7) AND ($8::timestamptz IS NULL OR (d.created_at,d.id)<($8,$9)) ORDER BY d.created_at DESC,d.id DESC LIMIT $10")
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .bind(status)
            .bind(source)
            .bind(origin)
            .bind(since)
            .bind(cursor_created_at)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// A delivery's attempts in order.
    ///
    /// Selects `id`, `recovery_generation`, `attempt_number`, `started_at`,
    /// `finished_at`, `duration_ms`, `outcome`, `http_status`, `error_class`
    /// and `response_excerpt`.
    pub async fn attempts<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        delivery_id: Uuid,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,recovery_generation,attempt_number,started_at,finished_at,duration_ms,outcome,http_status,error_class,response_excerpt FROM notification_delivery_attempts WHERE organization_id=$1 AND project_id=$2 AND delivery_id=$3 ORDER BY recovery_generation DESC,attempt_number DESC LIMIT 100")
            .bind(organization_id)
            .bind(project_id)
            .bind(delivery_id)
            .fetch_all(executor)
            .await
    }

    /// One delivery of the project with the columns of [`Self::page`].
    pub async fn get<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        delivery_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT d.id,d.project_id,d.destination_id,d.outbox_message_id,d.origin,d.source,d.event_name,d.payload,w.name destination_name,w.enabled destination_enabled,d.status,d.available_at,d.recovery_generation,d.attempt_count,(SELECT count(*) FROM notification_delivery_attempts a WHERE a.delivery_id=d.id) total_attempt_count,d.max_attempts,d.last_error_class,d.created_at,d.updated_at,d.terminal_at,d.last_recovery_operation_id FROM notification_deliveries d JOIN webhook_destinations w ON w.organization_id=d.organization_id AND w.project_id=d.project_id AND w.id=d.destination_id WHERE d.organization_id=$1 AND d.project_id=$2 AND d.id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(delivery_id)
            .fetch_optional(executor)
            .await
    }

    /// Records one delivery attempt, finished now.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_attempt<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        delivery_id: Uuid,
        recovery_generation: i32,
        attempt_number: i32,
        started_at: DateTime<Utc>,
        duration_ms: i64,
        outcome: &str,
        http_status: Option<i32>,
        error_class: Option<&str>,
        response_excerpt: Option<String>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO notification_delivery_attempts (id,organization_id,project_id,delivery_id,recovery_generation,attempt_number,started_at,finished_at,duration_ms,outcome,http_status,error_class,response_excerpt) VALUES ($1,$2,$3,$4,$5,$6,$7,now(),$8,$9,$10,$11,$12)")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(delivery_id)
            .bind(recovery_generation)
            .bind(attempt_number)
            .bind(started_at)
            .bind(duration_ms)
            .bind(outcome)
            .bind(http_status)
            .bind(error_class)
            .bind(response_excerpt)
            .execute(executor)
            .await
    }

    /// Returns a delivery leased to `lease_owner` to pending, due after
    /// `delay_seconds`, with its attempt count and last error.
    pub async fn schedule_retry<'e, E>(
        executor: E,
        delivery_id: Uuid,
        lease_owner: Uuid,
        attempt_count: i32,
        delay_seconds: i64,
        error_class: Option<&str>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE notification_deliveries SET status='pending',attempt_count=$3,available_at=now()+make_interval(secs=>$4),lease_owner=NULL,lease_expires_at=NULL,updated_at=now(),last_error_class=$5,last_error=$5 WHERE id=$1 AND lease_owner=$2")
            .bind(delivery_id)
            .bind(lease_owner)
            .bind(attempt_count)
            .bind(delay_seconds)
            .bind(error_class)
            .execute(executor)
            .await
    }

    /// Ends a delivery leased to `lease_owner` with a terminal status.
    pub async fn finish<'e, E>(
        executor: E,
        delivery_id: Uuid,
        lease_owner: Uuid,
        status: &str,
        attempt_count: i32,
        error_class: Option<&str>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE notification_deliveries SET status=$3,attempt_count=$4,lease_owner=NULL,lease_expires_at=NULL,updated_at=now(),terminal_at=now(),last_error_class=$5,last_error=$5 WHERE id=$1 AND lease_owner=$2")
            .bind(delivery_id)
            .bind(lease_owner)
            .bind(status)
            .bind(attempt_count)
            .bind(error_class)
            .execute(executor)
            .await
    }

    /// Cancels the destination's pending and in-flight deliveries because it
    /// was disabled.
    pub async fn cancel_for_destination<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE notification_deliveries SET status='cancelled',terminal_at=now(),updated_at=now(),lease_owner=NULL,lease_expires_at=NULL,last_error_class='destination_disabled',last_error='destination disabled before delivery' WHERE organization_id=$1 AND project_id=$2 AND destination_id=$3 AND status IN ('pending','in_flight')")
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use serde_json::json;
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::NotificationDeliveryRepository;
    use crate::repository::test_support::{
        Tenant, destination, exec, first_seen_messages, ingest, tenant, user,
    };
    use crate::repository::webhook_destinations::WebhookDestinationRepository;

    #[derive(Debug, FromRow)]
    struct Claim {
        id: Uuid,
        lease_owner: Uuid,
        url: String,
        attempt_count: i32,
    }

    #[derive(Debug, FromRow)]
    struct Delivery {
        id: Uuid,
        destination_name: String,
        status: String,
        attempt_count: i32,
        recovery_generation: i32,
        terminal_at: Option<DateTime<Utc>>,
        last_error_class: Option<String>,
        created_at: DateTime<Utc>,
    }

    #[derive(Debug, FromRow)]
    struct AttemptRow {
        attempt_number: i32,
        outcome: String,
        http_status: Option<i32>,
    }

    #[derive(Debug, FromRow)]
    struct Locked {
        status: String,
        destination_enabled: bool,
        recovery_generation: i32,
        total_attempt_count: i64,
    }

    #[allow(clippy::struct_field_names)]
    #[derive(Debug, FromRow)]
    struct Snapshot {
        enabled_destination_count: i64,
        pending_count: i64,
        failed_count: i64,
    }

    async fn delivery(
        pool: &PgPool,
        own: &Tenant,
        destination_id: Uuid,
        message: Uuid,
        status: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let terminal = matches!(status, "failed" | "cancelled" | "succeeded" | "suppressed");
        let inserted = NotificationDeliveryRepository::insert_for_outbox(
            pool,
            id,
            own.organization_id,
            own.project_id,
            destination_id,
            message,
            "live",
            json!({}),
            status,
            3,
            terminal.then(Utc::now),
            terminal.then_some("http_5xx"),
            terminal.then_some("server error"),
        )
        .await
        .unwrap();
        assert_eq!(inserted.rows_affected(), 1);
        id
    }

    async fn get(pool: &PgPool, own: &Tenant, id: Uuid) -> Delivery {
        NotificationDeliveryRepository::get(pool, own.organization_id, own.project_id, id)
            .await
            .unwrap()
            .unwrap()
    }

    async fn claim(pool: &PgPool, owner: Uuid) -> Vec<Claim> {
        NotificationDeliveryRepository::claim_due(pool, 10, owner, 60)
            .await
            .unwrap()
    }

    /// A delivery is created once per message and destination, leased to one
    /// worker, retried, and finished; disabling its destination cancels what
    /// is still pending.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn deliveries_are_leased_retried_and_finished(pool: PgPool) {
        let own = tenant(&pool, "deliveries-lifecycle").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let (message, _) = first_seen_messages(&pool, &own).await[0];
        let kept = destination(&pool, &own, "kept").await;
        let dropped = destination(&pool, &own, "dropped").await;
        let first = delivery(&pool, &own, kept, message, "pending").await;
        let repeated = NotificationDeliveryRepository::insert_for_outbox(
            &pool,
            Uuid::new_v4(),
            own.organization_id,
            own.project_id,
            kept,
            message,
            "live",
            json!({}),
            "pending",
            3,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            repeated.rows_affected(),
            0,
            "one delivery per message and destination"
        );
        let doomed = delivery(&pool, &own, dropped, message, "pending").await;
        WebhookDestinationRepository::disable::<_, (Uuid,)>(
            &pool,
            own.organization_id,
            own.project_id,
            dropped,
        )
        .await
        .unwrap();
        NotificationDeliveryRepository::cancel_for_destination(
            &pool,
            own.organization_id,
            own.project_id,
            dropped,
        )
        .await
        .unwrap();
        let cancelled = get(&pool, &own, doomed).await;
        assert_eq!(
            (
                cancelled.status.as_str(),
                cancelled.last_error_class.as_deref()
            ),
            ("cancelled", Some("destination_disabled"))
        );
        assert!(cancelled.terminal_at.is_some());

        let owner = Uuid::new_v4();
        let leased = claim(&pool, owner).await;
        assert_eq!(leased.iter().map(|c| c.id).collect::<Vec<_>>(), [first]);
        assert_eq!(leased[0].lease_owner, owner);
        assert_eq!(leased[0].url, "https://hooks.example.test/okoscope");
        assert!(claim(&pool, Uuid::new_v4()).await.is_empty(), "leased once");

        NotificationDeliveryRepository::insert_attempt(
            &pool,
            Uuid::new_v4(),
            own.organization_id,
            own.project_id,
            first,
            0,
            1,
            Utc::now(),
            5,
            "retryable",
            Some(503),
            Some("http_5xx"),
            None,
        )
        .await
        .unwrap();
        let stranger = NotificationDeliveryRepository::schedule_retry(
            &pool,
            first,
            Uuid::new_v4(),
            1,
            0,
            Some("http_5xx"),
        )
        .await
        .unwrap();
        assert_eq!(
            stranger.rows_affected(),
            0,
            "only the lease owner reschedules"
        );
        NotificationDeliveryRepository::schedule_retry(&pool, first, owner, 1, 0, Some("http_5xx"))
            .await
            .unwrap();
        let retrying = get(&pool, &own, first).await;
        assert_eq!(
            (retrying.status.as_str(), retrying.attempt_count),
            ("pending", 1)
        );

        let second_owner = Uuid::new_v4();
        let again = claim(&pool, second_owner).await;
        assert_eq!(
            again
                .iter()
                .map(|c| (c.id, c.attempt_count))
                .collect::<Vec<_>>(),
            [(first, 1)]
        );
        NotificationDeliveryRepository::finish(
            &pool,
            first,
            second_owner,
            "failed",
            2,
            Some("http_5xx"),
        )
        .await
        .unwrap();
        let failed = get(&pool, &own, first).await;
        assert_eq!(
            (
                failed.status.as_str(),
                failed.attempt_count,
                failed.destination_name.as_str()
            ),
            ("failed", 2, "kept")
        );
        assert!(failed.terminal_at.is_some());
        let attempts: Vec<AttemptRow> = NotificationDeliveryRepository::attempts(
            &pool,
            own.organization_id,
            own.project_id,
            first,
        )
        .await
        .unwrap();
        assert_eq!(
            attempts
                .iter()
                .map(|a| (a.attempt_number, a.outcome.as_str(), a.http_status))
                .collect::<Vec<_>>(),
            [(1, "retryable", Some(503))]
        );

        let snapshot: Snapshot = NotificationDeliveryRepository::project_queue_snapshot(
            &pool,
            own.organization_id,
            own.project_id,
        )
        .await
        .unwrap();
        assert_eq!(
            (
                snapshot.enabled_destination_count,
                snapshot.pending_count,
                snapshot.failed_count
            ),
            (1, 0, 1)
        );
        let global: Snapshot = NotificationDeliveryRepository::queue_snapshot(&pool)
            .await
            .unwrap();
        assert_eq!(global.failed_count, 1);
    }

    /// The delivery page filters by destination, status, source and origin,
    /// newest first after a cursor; a test delivery starts leased.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn deliveries_page_and_filter(pool: PgPool) {
        let own = tenant(&pool, "deliveries-page").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let (message, _) = first_seen_messages(&pool, &own).await[0];
        let one = destination(&pool, &own, "one").await;
        let two = destination(&pool, &own, "two").await;
        let failed = delivery(&pool, &own, one, message, "failed").await;
        let pending = delivery(&pool, &own, two, message, "pending").await;
        let probe = Uuid::new_v4();
        NotificationDeliveryRepository::insert_test(
            &pool,
            probe,
            own.organization_id,
            own.project_id,
            one,
            &json!({"event": "okoscope.test"}),
            Uuid::new_v4(),
            60,
        )
        .await
        .unwrap();
        assert_eq!(get(&pool, &own, probe).await.status, "in_flight");

        let page = |destination_id: Option<Uuid>,
                    status: Option<&'static str>,
                    origin: Option<&'static str>,
                    cursor: Option<(DateTime<Utc>, Uuid)>| {
            let pool = pool.clone();
            async move {
                NotificationDeliveryRepository::page::<_, Delivery>(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    destination_id,
                    status,
                    None,
                    origin,
                    None,
                    cursor.map(|c| c.0),
                    cursor.map(|c| c.1),
                    10,
                )
                .await
                .unwrap()
                .into_iter()
                .map(|d| d.id)
                .collect::<Vec<_>>()
            }
        };
        let all = page(None, None, None, None).await;
        assert_eq!(all.len(), 3);
        assert_eq!(page(None, Some("failed"), None, None).await, [failed]);
        assert_eq!(page(Some(two), None, None, None).await, [pending]);
        assert_eq!(page(None, None, Some("test"), None).await, [probe]);
        let cursor = NotificationDeliveryRepository::cursor(
            &pool,
            own.organization_id,
            own.project_id,
            all[0],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(cursor.1, all[0]);
        assert_eq!(page(None, None, None, Some(cursor)).await, all[1..]);
        let other = tenant(&pool, "deliveries-page-other").await;
        assert!(
            NotificationDeliveryRepository::get::<_, Delivery>(
                &pool,
                other.organization_id,
                other.project_id,
                failed
            )
            .await
            .unwrap()
            .is_none()
        );
        let _ = get(&pool, &own, failed).await.created_at;
    }

    /// Recovery reads and moves: failed deliveries to enabled destinations
    /// are selected, counted, locked and requeued once under a new
    /// generation; a pending one is cancelled once.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn recovery_requeues_and_cancels(pool: PgPool) {
        let own = tenant(&pool, "deliveries-recovery").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let (message, _) = first_seen_messages(&pool, &own).await[0];
        let one = destination(&pool, &own, "one").await;
        let two = destination(&pool, &own, "two").await;
        let failed = delivery(&pool, &own, one, message, "failed").await;
        let pending = delivery(&pool, &own, two, message, "pending").await;

        let locked: Locked = NotificationDeliveryRepository::lock_for_recovery(
            &pool,
            own.organization_id,
            own.project_id,
            failed,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            (
                locked.status.as_str(),
                locked.destination_enabled,
                locked.recovery_generation,
                locked.total_attempt_count
            ),
            ("failed", true, 0, 0)
        );
        let selected = |error_class: Option<&'static str>| {
            let pool = pool.clone();
            async move {
                NotificationDeliveryRepository::failed_for_retry(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    None,
                    None,
                    None,
                    error_class,
                    10,
                )
                .await
                .unwrap()
            }
        };
        assert_eq!(selected(None).await, [(failed, 0)]);
        assert_eq!(selected(Some("http_5xx")).await, [(failed, 0)]);
        assert!(selected(Some("timeout")).await.is_empty());
        assert_eq!(
            NotificationDeliveryRepository::count_failed_for_retry(
                &pool,
                own.organization_id,
                own.project_id,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap(),
            1
        );

        let operation = Uuid::new_v4();
        let actor = user(&pool).await;
        crate::repository::notification_recovery::NotificationRecoveryRepository::insert(
            &pool,
            operation,
            own.organization_id,
            own.project_id,
            "retry",
            Some(failed),
            actor,
            "request",
            &[1; 32],
            &[2; 32],
            json!({}),
            1,
            1,
            0,
            0,
            0,
            json!({}),
            Utc::now(),
        )
        .await
        .unwrap();
        let requeue = || {
            NotificationDeliveryRepository::requeue_failed(
                &pool,
                own.organization_id,
                own.project_id,
                failed,
                1,
                operation,
            )
        };
        assert_eq!(requeue().await.unwrap().rows_affected(), 1);
        assert_eq!(
            requeue().await.unwrap().rows_affected(),
            0,
            "only a failed one"
        );
        let requeued = get(&pool, &own, failed).await;
        assert_eq!(
            (
                requeued.status.as_str(),
                requeued.recovery_generation,
                requeued.attempt_count
            ),
            ("pending", 1, 0)
        );
        assert!(requeued.terminal_at.is_none());

        let cancel = || {
            NotificationDeliveryRepository::cancel_pending(
                &pool,
                own.organization_id,
                own.project_id,
                pending,
                operation,
            )
        };
        assert_eq!(cancel().await.unwrap().rows_affected(), 1);
        assert_eq!(cancel().await.unwrap().rows_affected(), 0);
        assert_eq!(
            get(&pool, &own, pending).await.last_error_class.as_deref(),
            Some("user_cancelled")
        );
    }
}
