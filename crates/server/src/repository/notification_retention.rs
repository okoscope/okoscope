//! Notification retention: the organization and project settings for how
//! long delivery history is kept, and the statements of the job that deletes
//! expired history.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Notification retention settings and expiry.
#[derive(Clone, Copy, Debug)]
pub struct NotificationRetentionRepository;

impl NotificationRetentionRepository {
    /// Gives every organization whose retention was never initialized this
    /// policy, leaving initialized ones untouched.
    pub async fn initialize_organizations<'e, E>(
        executor: E,
        enabled: bool,
        history_days: i32,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE organizations SET notification_retention_enabled=$1,notification_retention_days=$2,notification_retention_initialized=true,notification_retention_updated_at=now() WHERE NOT notification_retention_initialized")
            .bind(enabled)
            .bind(history_days)
            .execute(executor)
            .await
    }

    /// The organization's retention policy, once initialized.
    ///
    /// Selects `enabled` and `history_days`.
    pub async fn organization_policy<'e, E, T>(
        executor: E,
        organization_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT notification_retention_enabled enabled,notification_retention_days history_days FROM organizations WHERE id=$1 AND notification_retention_initialized")
            .bind(organization_id)
            .fetch_optional(executor)
            .await
    }

    /// The project's retention override, its effective policy and the
    /// organization's policy it inherits otherwise.
    ///
    /// Selects `override_enabled`, `override_days`, `enabled`,
    /// `history_days`, `inherited_enabled` and `inherited_days`.
    pub async fn project_policy<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT p.notification_retention_enabled override_enabled,p.notification_retention_days override_days,e.enabled,e.history_days,o.notification_retention_enabled inherited_enabled,o.notification_retention_days inherited_days FROM projects p JOIN organizations o ON o.id=p.organization_id JOIN effective_notification_retention e ON e.project_id=p.id WHERE p.organization_id=$1 AND p.id=$2")
            .bind(organization_id)
            .bind(project_id)
            .fetch_optional(executor)
            .await
    }

    /// Sets and initializes the organization's retention policy.
    pub async fn set_organization_policy<'e, E>(
        executor: E,
        organization_id: Uuid,
        enabled: bool,
        history_days: i32,
        updated_by: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE organizations SET notification_retention_enabled=$2,notification_retention_days=$3,notification_retention_initialized=true,notification_retention_updated_at=now(),notification_retention_updated_by=$4 WHERE id=$1")
            .bind(organization_id)
            .bind(enabled)
            .bind(history_days)
            .bind(updated_by)
            .execute(executor)
            .await
    }

    /// Sets the project's retention override, or clears it with `None`s.
    pub async fn set_project_override<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        enabled: Option<bool>,
        history_days: Option<i32>,
        updated_by: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE projects SET notification_retention_enabled=$3,notification_retention_days=$4,notification_retention_updated_at=now(),notification_retention_updated_by=$5 WHERE organization_id=$1 AND id=$2")
            .bind(organization_id)
            .bind(project_id)
            .bind(enabled)
            .bind(history_days)
            .bind(updated_by)
            .execute(executor)
            .await
    }

    /// Tries to take the transaction-scoped advisory lock that lets one
    /// retention pass run at a time; `false` when another pass holds it.
    pub async fn try_lock<'e, E>(executor: E) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock(220022)")
            .fetch_one(executor)
            .await
    }

    /// Locks up to `limit` terminal deliveries older than their project's
    /// effective history window, oldest first, skipping locked rows.
    pub async fn expired_delivery_ids<'e, E>(
        executor: E,
        limit: i64,
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT d.id FROM notification_deliveries d JOIN effective_notification_retention e ON e.organization_id=d.organization_id AND e.project_id=d.project_id WHERE e.enabled AND d.status IN ('succeeded','failed','suppressed','cancelled') AND d.terminal_at < now()-make_interval(days=>e.history_days) ORDER BY d.terminal_at,d.id LIMIT $1 FOR UPDATE OF d SKIP LOCKED")
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// The recovery operations that touched any of the deliveries.
    pub async fn operations_of_deliveries<'e, E>(
        executor: E,
        delivery_ids: &[Uuid],
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT DISTINCT operation_id FROM notification_recovery_operation_deliveries WHERE delivery_id=ANY($1)")
            .bind(delivery_ids)
            .fetch_all(executor)
            .await
    }

    /// Deletes the single-delivery recovery operations that target any of
    /// the deliveries.
    pub async fn delete_operations_targeting<'e, E>(
        executor: E,
        delivery_ids: &[Uuid],
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM notification_recovery_operations WHERE target_delivery_id=ANY($1)")
            .bind(delivery_ids)
            .execute(executor)
            .await
    }

    /// Deletes the deliveries, with their attempts and operation links.
    pub async fn delete_deliveries<'e, E>(
        executor: E,
        delivery_ids: &[Uuid],
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM notification_deliveries WHERE id=ANY($1)")
            .bind(delivery_ids)
            .execute(executor)
            .await
    }

    /// Deletes those of the bulk operations that no longer touch any
    /// delivery.
    pub async fn delete_unlinked_bulk_operations<'e, E>(
        executor: E,
        operation_ids: &[Uuid],
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM notification_recovery_operations o WHERE o.id=ANY($1) AND o.target_delivery_id IS NULL AND NOT EXISTS (SELECT 1 FROM notification_recovery_operation_deliveries l WHERE l.operation_id=o.id)")
            .bind(operation_ids)
            .execute(executor)
            .await
    }

    /// Deletes up to `limit` bulk operations that touch no delivery and
    /// completed before their project's history window, oldest first,
    /// skipping locked rows.
    pub async fn delete_expired_empty_operations<'e, E>(
        executor: E,
        limit: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("WITH candidates AS (SELECT o.id FROM notification_recovery_operations o JOIN effective_notification_retention e ON e.organization_id=o.organization_id AND e.project_id=o.project_id WHERE e.enabled AND o.target_delivery_id IS NULL AND o.completed_at < now()-make_interval(days=>e.history_days) AND NOT EXISTS (SELECT 1 FROM notification_recovery_operation_deliveries l WHERE l.operation_id=o.id) ORDER BY o.completed_at,o.id LIMIT $1 FOR UPDATE OF o SKIP LOCKED) DELETE FROM notification_recovery_operations o USING candidates c WHERE o.id=c.id")
            .bind(limit)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::NotificationRetentionRepository;
    use crate::repository::notification_deliveries::NotificationDeliveryRepository;
    use crate::repository::notification_recovery::NotificationRecoveryRepository;
    use crate::repository::test_support::{
        Tenant, destination, exec, first_seen_messages, ingest, tenant, user,
    };

    #[derive(Debug, FromRow, PartialEq)]
    struct Policy {
        enabled: bool,
        history_days: i32,
    }

    #[derive(Debug, FromRow, PartialEq)]
    struct ProjectPolicy {
        override_enabled: Option<bool>,
        override_days: Option<i32>,
        enabled: bool,
        history_days: i32,
        inherited_enabled: bool,
        inherited_days: i32,
    }

    async fn project(pool: &PgPool, own: &Tenant) -> ProjectPolicy {
        NotificationRetentionRepository::project_policy(pool, own.organization_id, own.project_id)
            .await
            .unwrap()
            .unwrap()
    }

    /// Initialization fills only uninitialized organizations; a project
    /// override replaces the inherited policy until cleared.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn settings_initialize_override_and_inherit(pool: PgPool) {
        let fresh = tenant(&pool, "notification-retention-fresh").await;
        let edited = tenant(&pool, "notification-retention-edited").await;
        let actor = user(&pool).await;
        sqlx::query("UPDATE organizations SET notification_retention_initialized=false")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            NotificationRetentionRepository::organization_policy::<_, Policy>(
                &pool,
                fresh.organization_id
            )
            .await
            .unwrap(),
            None,
            "not initialized yet"
        );
        NotificationRetentionRepository::set_organization_policy(
            &pool,
            edited.organization_id,
            false,
            14,
            actor,
        )
        .await
        .unwrap();
        NotificationRetentionRepository::initialize_organizations(&pool, true, 30)
            .await
            .unwrap();
        let policy = |id: Uuid| {
            let pool = pool.clone();
            async move {
                NotificationRetentionRepository::organization_policy::<_, Policy>(&pool, id)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            policy(fresh.organization_id).await,
            Some(Policy {
                enabled: true,
                history_days: 30
            })
        );
        assert_eq!(
            policy(edited.organization_id).await,
            Some(Policy {
                enabled: false,
                history_days: 14
            }),
            "an edited organization is left alone"
        );

        assert_eq!(
            project(&pool, &fresh).await,
            ProjectPolicy {
                override_enabled: None,
                override_days: None,
                enabled: true,
                history_days: 30,
                inherited_enabled: true,
                inherited_days: 30,
            }
        );
        NotificationRetentionRepository::set_project_override(
            &pool,
            fresh.organization_id,
            fresh.project_id,
            Some(false),
            Some(5),
            actor,
        )
        .await
        .unwrap();
        let overridden = project(&pool, &fresh).await;
        assert_eq!(
            (
                overridden.override_enabled,
                overridden.override_days,
                overridden.enabled,
                overridden.history_days
            ),
            (Some(false), Some(5), false, 5)
        );
        NotificationRetentionRepository::set_project_override(
            &pool,
            fresh.organization_id,
            fresh.project_id,
            None,
            None,
            actor,
        )
        .await
        .unwrap();
        assert_eq!(
            project(&pool, &fresh).await.history_days,
            30,
            "cleared, inherited again"
        );
    }

    /// Expiry selects terminal deliveries past their project's window and
    /// deletes them with the operations that no longer touch anything.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn expired_history_is_deleted(pool: PgPool) {
        let own = tenant(&pool, "notification-retention-expiry").await;
        let actor = user(&pool).await;
        NotificationRetentionRepository::set_organization_policy(
            &pool,
            own.organization_id,
            true,
            1,
            actor,
        )
        .await
        .unwrap();
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let (message, _) = first_seen_messages(&pool, &own).await[0];
        let one = destination(&pool, &own, "one").await;
        let two = destination(&pool, &own, "two").await;
        let mut ids = Vec::new();
        for target in [one, two] {
            let id = Uuid::new_v4();
            NotificationDeliveryRepository::insert_for_outbox(
                &pool,
                id,
                own.organization_id,
                own.project_id,
                target,
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
            ids.push(id);
        }
        let (old, recent) = (ids[0], ids[1]);
        sqlx::query("UPDATE notification_deliveries SET created_at=now()-interval '4 days',terminal_at=now()-interval '3 days' WHERE id=$1")
            .bind(old)
            .execute(&pool)
            .await
            .unwrap();

        let operation = |command: &'static str, target: Option<Uuid>, key: u8| {
            let pool = pool.clone();
            async move {
                let id = Uuid::new_v4();
                NotificationRecoveryRepository::insert(
                    &pool,
                    id,
                    own.organization_id,
                    own.project_id,
                    command,
                    target,
                    actor,
                    "request",
                    &[key; 32],
                    &[0; 32],
                    json!({}),
                    0,
                    0,
                    0,
                    0,
                    0,
                    json!({}),
                    Utc::now(),
                )
                .await
                .unwrap();
                id
            }
        };
        let targeted = operation("retry", Some(old), 1).await;
        let bulk = operation("bulk_retry", None, 2).await;
        let empty_old = operation("bulk_retry", None, 3).await;
        let empty_recent = operation("bulk_retry", None, 4).await;
        sqlx::query("UPDATE notification_recovery_operations SET created_at=now()-interval '3 days',completed_at=now()-interval '3 days' WHERE id=$1")
            .bind(empty_old)
            .execute(&pool)
            .await
            .unwrap();
        for (op, delivery) in [(targeted, old), (bulk, old), (bulk, recent)] {
            NotificationRecoveryRepository::link_delivery(
                &pool,
                op,
                own.organization_id,
                own.project_id,
                delivery,
                0,
                "retried",
            )
            .await
            .unwrap();
        }

        let mut tx = pool.begin().await.unwrap();
        assert!(
            NotificationRetentionRepository::try_lock(&mut *tx)
                .await
                .unwrap()
        );
        let other: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(220022)")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!other, "one retention pass at a time");
        let expired = NotificationRetentionRepository::expired_delivery_ids(&mut *tx, 10)
            .await
            .unwrap();
        assert_eq!(expired, [old]);
        let mut touching =
            NotificationRetentionRepository::operations_of_deliveries(&mut *tx, &expired)
                .await
                .unwrap();
        touching.sort();
        let mut expected = vec![targeted, bulk];
        expected.sort();
        assert_eq!(touching, expected);
        NotificationRetentionRepository::delete_operations_targeting(&mut *tx, &expired)
            .await
            .unwrap();
        NotificationRetentionRepository::delete_deliveries(&mut *tx, &expired)
            .await
            .unwrap();
        NotificationRetentionRepository::delete_unlinked_bulk_operations(&mut *tx, &touching)
            .await
            .unwrap();
        NotificationRetentionRepository::delete_expired_empty_operations(&mut *tx, 10)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let deliveries: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM notification_deliveries WHERE project_id=$1")
                .bind(own.project_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(deliveries, [recent]);
        let mut operations: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM notification_recovery_operations WHERE project_id=$1",
        )
        .bind(own.project_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        operations.sort();
        let mut kept = vec![bulk, empty_recent];
        kept.sort();
        assert_eq!(
            operations, kept,
            "the bulk operation still touches a delivery; the recent empty one is in its window"
        );
    }
}
