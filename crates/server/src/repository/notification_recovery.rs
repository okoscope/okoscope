//! Notification recovery operations: user-initiated retries and cancellations
//! of deliveries, recorded idempotently with the deliveries each one touched.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

/// Notification recovery operations.
#[derive(Clone, Copy, Debug)]
pub struct NotificationRecoveryRepository;

impl NotificationRecoveryRepository {
    /// Resolves an operation id used as a list cursor into its
    /// `(created_at, id)` ordering key.
    pub async fn cursor<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (DateTime<Utc>, Uuid)>("SELECT created_at,id FROM notification_recovery_operations WHERE organization_id=$1 AND project_id=$2 AND id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(operation_id)
            .fetch_optional(executor)
            .await
    }

    /// A page of the project's recovery operations, newest first, after the
    /// cursor when one is given, optionally of one command type.
    ///
    /// Selects the operation's id, command, actor, request, outcome and
    /// counts, and when it was created and completed.
    pub async fn page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        command_type: Option<&str>,
        cursor_created_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,project_id,command_type,target_delivery_id,actor_kind,actor_id,request_id,outcome,selected_count,retried_count,cancelled_count,skipped_count,remaining_count,created_at,completed_at FROM notification_recovery_operations WHERE organization_id=$1 AND project_id=$2 AND ($3::text IS NULL OR command_type=$3) AND ($4::timestamptz IS NULL OR (created_at,id)<($4,$5)) ORDER BY created_at DESC,id DESC LIMIT $6")
            .bind(organization_id)
            .bind(project_id)
            .bind(command_type)
            .bind(cursor_created_at)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// One recovery operation of the project with the columns of
    /// [`Self::page`].
    pub async fn get<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,project_id,command_type,target_delivery_id,actor_kind,actor_id,request_id,outcome,selected_count,retried_count,cancelled_count,skipped_count,remaining_count,created_at,completed_at FROM notification_recovery_operations WHERE organization_id=$1 AND project_id=$2 AND id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(operation_id)
            .fetch_optional(executor)
            .await
    }

    /// The deliveries an operation touched.
    ///
    /// Selects `delivery_id`, `recovery_generation`, `action` and
    /// `created_at`.
    pub async fn deliveries<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT delivery_id,recovery_generation,action,created_at FROM notification_recovery_operation_deliveries WHERE organization_id=$1 AND project_id=$2 AND operation_id=$3 ORDER BY created_at,delivery_id LIMIT 200")
            .bind(organization_id)
            .bind(project_id)
            .bind(operation_id)
            .fetch_all(executor)
            .await
    }

    /// Locks the operation recorded under an idempotency key hash.
    ///
    /// Selects `request_fingerprint` and `result`.
    pub async fn by_idempotency_key_for_update<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        idempotency_key_hash: &[u8],
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT request_fingerprint,result FROM notification_recovery_operations WHERE organization_id=$1 AND project_id=$2 AND idempotency_key_hash=$3 FOR UPDATE")
            .bind(organization_id)
            .bind(project_id)
            .bind(idempotency_key_hash)
            .fetch_optional(executor)
            .await
    }

    /// Records a completed recovery operation under its idempotency key.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        command_type: &str,
        target_delivery_id: Option<Uuid>,
        actor_id: Uuid,
        request_id: &str,
        idempotency_key_hash: &[u8],
        request_fingerprint: &[u8],
        safe_filters: Value,
        selected_count: i32,
        retried_count: i32,
        cancelled_count: i32,
        skipped_count: i32,
        remaining_count: i32,
        result: Value,
        completed_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO notification_recovery_operations (id,organization_id,project_id,command_type,target_delivery_id,actor_kind,actor_id,request_id,idempotency_key_hash,request_fingerprint,safe_filters,outcome,selected_count,retried_count,cancelled_count,skipped_count,remaining_count,result,completed_at) VALUES ($1,$2,$3,$4,$5,'user',$6,$7,$8,$9,$10,'completed',$11,$12,$13,$14,$15,$16,$17)")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(command_type)
            .bind(target_delivery_id)
            .bind(actor_id)
            .bind(request_id)
            .bind(idempotency_key_hash)
            .bind(request_fingerprint)
            .bind(safe_filters)
            .bind(selected_count)
            .bind(retried_count)
            .bind(cancelled_count)
            .bind(skipped_count)
            .bind(remaining_count)
            .bind(result)
            .bind(completed_at)
            .execute(executor)
            .await
    }

    /// Records what an operation did to one delivery.
    pub async fn link_delivery<'e, E>(
        executor: E,
        operation_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        delivery_id: Uuid,
        recovery_generation: i32,
        action: &str,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO notification_recovery_operation_deliveries (operation_id,organization_id,project_id,delivery_id,recovery_generation,action) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(operation_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(delivery_id)
            .bind(recovery_generation)
            .bind(action)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use serde_json::{Value, json};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::NotificationRecoveryRepository;
    use crate::repository::notification_deliveries::NotificationDeliveryRepository;
    use crate::repository::test_support::{
        Tenant, destination, exec, first_seen_messages, ingest, tenant, user,
    };

    #[derive(Debug, FromRow)]
    struct Operation {
        id: Uuid,
        command_type: String,
        target_delivery_id: Option<Uuid>,
        actor_kind: String,
        retried_count: i32,
        created_at: DateTime<Utc>,
    }

    #[derive(Debug, FromRow)]
    struct Touched {
        delivery_id: Uuid,
        recovery_generation: i32,
        action: String,
    }

    #[derive(Debug, FromRow)]
    struct Existing {
        request_fingerprint: Vec<u8>,
        result: Value,
    }

    async fn record(
        pool: &PgPool,
        own: &Tenant,
        command: &str,
        target: Option<Uuid>,
        key: u8,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let actor = user(pool).await;
        NotificationRecoveryRepository::insert(
            pool,
            id,
            own.organization_id,
            own.project_id,
            command,
            target,
            actor,
            "request-1",
            &[key; 32],
            &[7; 32],
            json!({}),
            1,
            1,
            0,
            0,
            0,
            json!({"retried": 1}),
            Utc::now(),
        )
        .await
        .unwrap();
        id
    }

    /// Operations are recorded under an idempotency key, page newest first by
    /// command type after a cursor, and list the deliveries they touched.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn operations_record_page_and_link(pool: PgPool) {
        let own = tenant(&pool, "recovery-operations").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let (message, _) = first_seen_messages(&pool, &own).await[0];
        let hook = destination(&pool, &own, "hook").await;
        let delivery = Uuid::new_v4();
        NotificationDeliveryRepository::insert_for_outbox(
            &pool,
            delivery,
            own.organization_id,
            own.project_id,
            hook,
            message,
            "live",
            json!({}),
            "failed",
            3,
            Some(Utc::now()),
            Some("http_5xx"),
            Some("server error"),
        )
        .await
        .unwrap();

        let retry = record(&pool, &own, "retry", Some(delivery), 1).await;
        sqlx::query("UPDATE notification_recovery_operations SET created_at=now()-interval '1 minute' WHERE id=$1")
            .bind(retry)
            .execute(&pool)
            .await
            .unwrap();
        let bulk = record(&pool, &own, "bulk_retry", None, 2).await;

        let existing: Existing = NotificationRecoveryRepository::by_idempotency_key_for_update(
            &pool,
            own.organization_id,
            own.project_id,
            &[1; 32],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            (existing.request_fingerprint, existing.result),
            (vec![7; 32], json!({"retried": 1}))
        );
        assert!(
            NotificationRecoveryRepository::by_idempotency_key_for_update::<_, Existing>(
                &pool,
                own.organization_id,
                own.project_id,
                &[3; 32],
            )
            .await
            .unwrap()
            .is_none()
        );

        let page = |command: Option<&'static str>, cursor: Option<(DateTime<Utc>, Uuid)>| {
            let pool = pool.clone();
            async move {
                NotificationRecoveryRepository::page::<_, Operation>(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    command,
                    cursor.map(|c| c.0),
                    cursor.map(|c| c.1),
                    10,
                )
                .await
                .unwrap()
                .into_iter()
                .map(|o| o.id)
                .collect::<Vec<_>>()
            }
        };
        assert_eq!(page(None, None).await, [bulk, retry]);
        assert_eq!(page(Some("retry"), None).await, [retry]);
        let cursor = NotificationRecoveryRepository::cursor(
            &pool,
            own.organization_id,
            own.project_id,
            bulk,
        )
        .await
        .unwrap();
        assert_eq!(page(None, cursor).await, [retry]);

        let one: Operation =
            NotificationRecoveryRepository::get(&pool, own.organization_id, own.project_id, retry)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            (
                one.command_type.as_str(),
                one.target_delivery_id,
                one.actor_kind.as_str(),
                one.retried_count
            ),
            ("retry", Some(delivery), "user", 1)
        );
        assert!(one.created_at < Utc::now());

        NotificationRecoveryRepository::link_delivery(
            &pool,
            retry,
            own.organization_id,
            own.project_id,
            delivery,
            1,
            "retried",
        )
        .await
        .unwrap();
        let touched: Vec<Touched> = NotificationRecoveryRepository::deliveries(
            &pool,
            own.organization_id,
            own.project_id,
            retry,
        )
        .await
        .unwrap();
        assert_eq!(
            touched
                .iter()
                .map(|t| (t.delivery_id, t.recovery_generation, t.action.as_str()))
                .collect::<Vec<_>>(),
            [(delivery, 1, "retried")]
        );
    }
}
