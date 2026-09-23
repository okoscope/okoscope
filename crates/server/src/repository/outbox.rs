//! The transactional outbox: messages written alongside the data they announce
//! and later materialized into notification deliveries.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// Outbox messages.
#[derive(Clone, Copy, Debug)]
pub struct OutboxRepository;

impl OutboxRepository {
    /// Locks up to `limit` unprocessed, unmaterialized first-seen messages,
    /// oldest first, skipping ones another worker holds.
    ///
    /// Selects `id`, `organization_id`, `project_id`, `aggregate_id`,
    /// `source`, `payload` and `created_at`.
    pub async fn claim_first_seen<'e, E, T>(executor: E, limit: i64) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,organization_id,project_id,aggregate_id,source,payload,created_at FROM outbox_messages WHERE topic='runtime_group.first_seen' AND processed_at IS NULL AND materialized_at IS NULL ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT $1")
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Records the policy eligibility a message was evaluated with.
    pub async fn record_eligibility<'e, E>(
        executor: E,
        id: Uuid,
        reason: &str,
        evaluated_at: DateTime<Utc>,
        policy_revision_id: Option<Uuid>,
        policy_suppression_id: Option<Uuid>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE outbox_messages SET policy_eligibility_reason=$2,policy_evaluated_at=$3,policy_revision_id=$4,policy_suppression_id=$5 WHERE id=$1")
            .bind(id)
            .bind(reason)
            .bind(evaluated_at)
            .bind(policy_revision_id)
            .bind(policy_suppression_id)
            .execute(executor)
            .await
    }

    /// Marks a message materialized and processed for `completion_reason`.
    pub async fn complete<'e, E>(
        executor: E,
        id: Uuid,
        completion_reason: &str,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE outbox_messages SET materialized_at=now(),processed_at=now(),completion_reason=$2 WHERE id=$1")
            .bind(id)
            .bind(completion_reason)
            .execute(executor)
            .await
    }

    /// Marks a message materialized and processed because the project has no
    /// enabled destination.
    pub async fn complete_without_destinations<'e, E>(
        executor: E,
        id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE outbox_messages SET materialized_at=now(),processed_at=now(),completion_reason='no_destinations',policy_eligibility_reason='no_destinations' WHERE id=$1")
            .bind(id)
            .execute(executor)
            .await
    }

    /// Marks a message materialized and processed because every delivery was
    /// a suppressed backfill.
    pub async fn complete_backfill_suppressed<'e, E>(
        executor: E,
        id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE outbox_messages SET materialized_at=now(),processed_at=now(),completion_reason='backfill_suppressed',policy_eligibility_reason='backfill_suppressed' WHERE id=$1")
            .bind(id)
            .execute(executor)
            .await
    }

    /// Marks a message materialized; it is processed once its deliveries end.
    pub async fn mark_materialized<'e, E>(
        executor: E,
        id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE outbox_messages SET materialized_at=now() WHERE id=$1")
            .bind(id)
            .execute(executor)
            .await
    }

    /// Marks a materialized message processed once none of its deliveries is
    /// pending or in flight.
    pub async fn complete_if_deliveries_terminal<'e, E>(
        executor: E,
        id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE outbox_messages o SET processed_at=now(),completion_reason='deliveries_terminal' WHERE o.id=$1 AND o.materialized_at IS NOT NULL AND NOT EXISTS (SELECT 1 FROM notification_deliveries d WHERE d.outbox_message_id=o.id AND d.status NOT IN ('succeeded','failed','suppressed','cancelled'))")
            .bind(id)
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

    use super::OutboxRepository;
    use crate::repository::EventGroupRepository;
    use crate::repository::notification_deliveries::NotificationDeliveryRepository;
    use crate::repository::test_support::{
        Tenant, destination, exec, first_seen_messages, ingest, tenant, user,
    };

    #[derive(Debug, FromRow)]
    struct Message {
        id: Uuid,
        source: String,
    }

    #[derive(Debug, FromRow)]
    struct Eligibility {
        reason: String,
        evaluated_at: DateTime<Utc>,
        policy_revision_id: Option<Uuid>,
        policy_suppression_id: Option<Uuid>,
    }

    type State = (
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<String>,
        Option<String>,
    );

    async fn state(pool: &PgPool, id: Uuid) -> State {
        sqlx::query_as(
            "SELECT materialized_at,processed_at,completion_reason,policy_eligibility_reason FROM outbox_messages WHERE id=$1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn seed(pool: &PgPool, own: &Tenant) -> Vec<(Uuid, Uuid)> {
        ingest(
            pool,
            own,
            &[
                exec(own, "/bin/a", Utc::now()),
                exec(own, "/bin/b", Utc::now()),
                exec(own, "/bin/c", Utc::now()),
            ],
        )
        .await;
        first_seen_messages(pool, own).await
    }

    /// First-seen messages are claimed once while locked, carry their policy
    /// eligibility, and complete for each reason; a materialized message
    /// completes once its deliveries end.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn messages_are_claimed_and_completed(pool: PgPool) {
        let own = tenant(&pool, "outbox-complete").await;
        let messages = seed(&pool, &own).await;
        assert_eq!(messages.len(), 3);

        let mut tx = pool.begin().await.unwrap();
        let claimed: Vec<Message> = OutboxRepository::claim_first_seen(&mut *tx, 10)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 3);
        assert!(claimed.iter().all(|m| m.source == "live"));
        let concurrent: Vec<Message> = OutboxRepository::claim_first_seen(&pool, 10).await.unwrap();
        assert!(concurrent.is_empty(), "locked messages are skipped");
        tx.rollback().await.unwrap();
        let limited: Vec<Message> = OutboxRepository::claim_first_seen(&pool, 1).await.unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].id, messages[0].0, "oldest first");

        let now = Utc::now();
        OutboxRepository::record_eligibility(&pool, messages[0].0, "eligible", now, None, None)
            .await
            .unwrap();
        let recorded: (Option<DateTime<Utc>>,) =
            sqlx::query_as("SELECT policy_evaluated_at FROM outbox_messages WHERE id=$1")
                .bind(messages[0].0)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(recorded.0.is_some());
        OutboxRepository::complete(&pool, messages[0].0, "eligible")
            .await
            .unwrap();
        OutboxRepository::complete_without_destinations(&pool, messages[1].0)
            .await
            .unwrap();
        OutboxRepository::complete_backfill_suppressed(&pool, messages[2].0)
            .await
            .unwrap();
        let reasons: Vec<(Option<String>, Option<String>)> = {
            let mut out = Vec::new();
            for (id, _) in &messages {
                let (materialized, processed, completion, eligibility) = state(&pool, *id).await;
                assert!(materialized.is_some() && processed.is_some());
                out.push((completion, eligibility));
            }
            out
        };
        assert_eq!(
            reasons,
            [
                (Some("eligible".into()), Some("eligible".into())),
                (
                    Some("no_destinations".into()),
                    Some("no_destinations".into())
                ),
                (
                    Some("backfill_suppressed".into()),
                    Some("backfill_suppressed".into())
                ),
            ]
        );
        assert!(
            OutboxRepository::claim_first_seen::<_, Message>(&pool, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A materialized message stays unprocessed while a delivery is open.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_materialized_message_waits_for_its_deliveries(pool: PgPool) {
        let own = tenant(&pool, "outbox-materialized").await;
        let (message, _) = seed(&pool, &own).await[0];
        let target = destination(&pool, &own, "hook").await;
        let delivery = Uuid::new_v4();
        NotificationDeliveryRepository::insert_for_outbox(
            &pool,
            delivery,
            own.organization_id,
            own.project_id,
            target,
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
        OutboxRepository::mark_materialized(&pool, message)
            .await
            .unwrap();
        let (materialized, processed, _, _) = state(&pool, message).await;
        assert!(materialized.is_some() && processed.is_none());
        OutboxRepository::complete_if_deliveries_terminal(&pool, message)
            .await
            .unwrap();
        assert!(
            state(&pool, message).await.1.is_none(),
            "a delivery is still pending"
        );
        let owner = Uuid::new_v4();
        let claimed: Vec<(Uuid,)> = NotificationDeliveryRepository::claim_due(&pool, 10, owner, 60)
            .await
            .unwrap();
        assert_eq!(claimed, [(delivery,)]);
        NotificationDeliveryRepository::finish(&pool, delivery, owner, "succeeded", 1, None)
            .await
            .unwrap();
        OutboxRepository::complete_if_deliveries_terminal(&pool, message)
            .await
            .unwrap();
        let (_, processed, completion, _) = state(&pool, message).await;
        assert!(processed.is_some());
        assert_eq!(completion.as_deref(), Some("deliveries_terminal"));
    }

    /// A group is eligible for notification under a current unclassified
    /// evaluation and pending under another evaluator version; its labels
    /// come back as a JSON array.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn group_eligibility_and_labels(pool: PgPool) {
        let own = tenant(&pool, "outbox-eligibility").await;
        let (_, group) = seed(&pool, &own).await[0];
        let eligibility = |version: i16| {
            let pool = pool.clone();
            async move {
                EventGroupRepository::notification_eligibility::<_, Eligibility>(
                    &pool,
                    own.organization_id,
                    group,
                    version,
                )
                .await
                .unwrap()
            }
        };
        let current = eligibility(crate::policy::POLICY_EVALUATOR_VERSION).await;
        assert_eq!(current.reason, "eligible");
        assert!(current.policy_suppression_id.is_none() && current.policy_revision_id.is_none());
        assert!(current.evaluated_at <= Utc::now());
        assert_eq!(
            eligibility(crate::policy::POLICY_EVALUATOR_VERSION + 1)
                .await
                .reason,
            "evaluation_pending"
        );

        let labels = || EventGroupRepository::user_labels_json(&pool, own.organization_id, group);
        assert_eq!(labels().await.unwrap(), json!([]));
        let actor = user(&pool).await;
        sqlx::query(
            "INSERT INTO runtime_behavior_user_labels(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,display_name,created_by_user_id,updated_by_user_id) \
             SELECT gen_random_uuid(),i.organization_id,i.project_id,i.application_id,i.inventory_kind,i.identity_version,i.identity_digest,'Shell',$2,$2 \
             FROM runtime_inventory_group_links gl JOIN runtime_inventory_items i ON i.id=gl.item_id WHERE gl.group_id=$1",
        )
        .bind(group)
        .bind(actor)
        .execute(&pool)
        .await
        .unwrap();
        let labelled: Value = labels().await.unwrap();
        assert_eq!(labelled.as_array().map(Vec::len), Some(1));
        assert_eq!(labelled[0]["display_name"], "Shell");
    }
}
