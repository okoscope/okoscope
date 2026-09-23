//! The transactional mail outbox: encrypted account and invitation mail waiting
//! to be sent, leased to one worker at a time, and erased once delivered or
//! abandoned.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// Transactional mail outbox.
#[derive(Clone, Copy, Debug)]
pub struct TransactionalMailRepository;

impl TransactionalMailRepository {
    /// How many mails are waiting, and how many seconds the oldest has been
    /// due (0 when none is waiting).
    pub async fn backlog<'e, E>(executor: E) -> Result<(i64, i64), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (i64, i64)>("SELECT count(*)::bigint,COALESCE(EXTRACT(EPOCH FROM (now()-min(available_at)))::bigint,0) FROM transactional_mail_outbox WHERE delivered_at IS NULL AND terminal_at IS NULL AND available_at<=now()")
            .fetch_one(executor)
            .await
    }

    /// Queues an encrypted mail, once per logical key and recipient, kept
    /// for `retention` after it is created.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert<'e, E>(
        executor: E,
        id: Uuid,
        logical_key: &str,
        template_kind: &str,
        recipient_email: &str,
        locale: &str,
        payload_ciphertext: Vec<u8>,
        payload_nonce: Vec<u8>,
        action_id: Option<Uuid>,
        invitation_id: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
        retention: chrono::Duration,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO transactional_mail_outbox(id,logical_key,template_kind,recipient_email,locale,payload_ciphertext,payload_nonce,action_id,invitation_id,expires_at,retain_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()+$11) ON CONFLICT(logical_key,recipient_email) DO NOTHING")
            .bind(id)
            .bind(logical_key)
            .bind(template_kind)
            .bind(recipient_email)
            .bind(locale)
            .bind(payload_ciphertext)
            .bind(payload_nonce)
            .bind(action_id)
            .bind(invitation_id)
            .bind(expires_at)
            .bind(retention)
            .execute(executor)
            .await
    }

    /// Leases up to `limit` due mails to `worker_id` for `lease`, counting an
    /// attempt, skipping rows another worker holds.
    ///
    /// Selects `id`, `template_kind`, `recipient_email`, `locale`,
    /// `payload_ciphertext`, `payload_nonce`, `attempt_count` and
    /// `expires_at`.
    pub async fn claim<'e, E, T>(
        executor: E,
        limit: i64,
        worker_id: Uuid,
        lease: chrono::Duration,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH due AS (SELECT id FROM transactional_mail_outbox WHERE delivered_at IS NULL AND terminal_at IS NULL AND available_at<=now() AND (claimed_until IS NULL OR claimed_until<now()) ORDER BY available_at,created_at,id LIMIT $1 FOR UPDATE SKIP LOCKED) UPDATE transactional_mail_outbox o SET claimed_by=$2,claimed_until=now()+$3,attempt_count=attempt_count+1,last_attempt_at=now() FROM due WHERE o.id=due.id RETURNING o.id,o.template_kind,o.recipient_email,o.locale,o.payload_ciphertext,o.payload_nonce,o.attempt_count,o.expires_at")
            .bind(limit)
            .bind(worker_id)
            .bind(lease)
            .fetch_all(executor)
            .await
    }

    /// Marks a mail leased to `worker_id` delivered and erases its payload.
    pub async fn mark_delivered<'e, E>(
        executor: E,
        id: Uuid,
        worker_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE transactional_mail_outbox SET delivered_at=now(),claimed_by=NULL,claimed_until=NULL,payload_ciphertext=NULL,payload_nonce=NULL,ciphertext_erased_at=now() WHERE id=$1 AND claimed_by=$2")
            .bind(id)
            .bind(worker_id)
            .execute(executor)
            .await
    }

    /// Abandons a mail leased to `worker_id` for `reason` and erases its
    /// payload.
    pub async fn mark_terminal<'e, E>(
        executor: E,
        id: Uuid,
        worker_id: Uuid,
        reason: &str,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE transactional_mail_outbox SET terminal_at=now(),terminal_reason=$3,claimed_by=NULL,claimed_until=NULL,payload_ciphertext=NULL,payload_nonce=NULL,ciphertext_erased_at=now() WHERE id=$1 AND claimed_by=$2")
            .bind(id)
            .bind(worker_id)
            .bind(reason)
            .execute(executor)
            .await
    }

    /// Releases a mail leased to `worker_id`, due again after
    /// `delay_seconds`.
    pub async fn schedule_retry<'e, E>(
        executor: E,
        id: Uuid,
        worker_id: Uuid,
        delay_seconds: f64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE transactional_mail_outbox SET available_at=now()+make_interval(secs=>$3),claimed_by=NULL,claimed_until=NULL WHERE id=$1 AND claimed_by=$2")
            .bind(id)
            .bind(worker_id)
            .bind(delay_seconds)
            .execute(executor)
            .await
    }

    /// Deletes delivered or abandoned mail past its retention.
    pub async fn delete_retained<'e, E>(
        executor: E,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM transactional_mail_outbox WHERE retain_until<now() AND (delivered_at IS NOT NULL OR terminal_at IS NOT NULL)")
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::TransactionalMailRepository;
    use crate::repository::email_actions::EmailActionRepository;
    use crate::repository::invitations::InvitationRepository;
    use crate::repository::test_support::{tenant, user};
    use crate::repository::{MembershipRepository, UserRepository};

    #[derive(Debug, FromRow)]
    struct Claimed {
        id: Uuid,
        template_kind: String,
        attempt_count: i32,
        payload_ciphertext: Option<Vec<u8>>,
    }

    type State = (
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<String>,
        Option<Vec<u8>>,
    );

    async fn queue(pool: &PgPool, key: &str) -> Uuid {
        let id = Uuid::new_v4();
        TransactionalMailRepository::insert(
            pool,
            id,
            key,
            "verify_email",
            "someone@example.test",
            "en",
            vec![1; 16],
            vec![2; 24],
            None,
            None,
            None,
            Duration::days(30),
        )
        .await
        .unwrap();
        id
    }

    async fn state(pool: &PgPool, id: Uuid) -> State {
        sqlx::query_as(
            "SELECT delivered_at,terminal_at,terminal_reason,payload_ciphertext FROM transactional_mail_outbox WHERE id=$1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn claim(pool: &PgPool, worker: Uuid) -> Vec<Claimed> {
        TransactionalMailRepository::claim(pool, 10, worker, Duration::seconds(60))
            .await
            .unwrap()
    }

    /// Mail is queued once per key and recipient, leased to one worker,
    /// retried, and delivered or abandoned with its payload erased; the
    /// backlog counts what waits.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn mail_is_leased_and_finished(pool: PgPool) {
        let first = queue(&pool, "verify:1").await;
        queue(&pool, "verify:1").await;
        let second = queue(&pool, "verify:2").await;
        assert_eq!(
            TransactionalMailRepository::backlog(&pool).await.unwrap().0,
            2,
            "queued once per key"
        );

        let worker = Uuid::new_v4();
        let leased = claim(&pool, worker).await;
        assert_eq!(leased.len(), 2);
        assert!(
            leased
                .iter()
                .all(|m| m.template_kind == "verify_email" && m.attempt_count == 1)
        );
        assert!(leased.iter().all(|m| m.payload_ciphertext.is_some()));
        assert!(claim(&pool, Uuid::new_v4()).await.is_empty(), "leased once");

        TransactionalMailRepository::mark_delivered(&pool, first, Uuid::new_v4())
            .await
            .unwrap();
        assert!(
            state(&pool, first).await.0.is_none(),
            "only the lease holder finishes it"
        );
        TransactionalMailRepository::mark_delivered(&pool, first, worker)
            .await
            .unwrap();
        let (delivered, _, _, payload) = state(&pool, first).await;
        assert!(
            delivered.is_some() && payload.is_none(),
            "delivered and erased"
        );

        TransactionalMailRepository::schedule_retry(&pool, second, worker, 0.0)
            .await
            .unwrap();
        let again = claim(&pool, worker).await;
        assert_eq!(
            again
                .iter()
                .map(|m| (m.id, m.attempt_count))
                .collect::<Vec<_>>(),
            [(second, 2)]
        );
        TransactionalMailRepository::mark_terminal(&pool, second, worker, "attempts_exhausted")
            .await
            .unwrap();
        let (_, terminal, reason, payload) = state(&pool, second).await;
        assert!(terminal.is_some() && payload.is_none());
        assert_eq!(reason.as_deref(), Some("attempts_exhausted"));
        assert_eq!(
            TransactionalMailRepository::backlog(&pool).await.unwrap(),
            (0, 0)
        );

        sqlx::query("UPDATE transactional_mail_outbox SET created_at=now()-interval '2 days',available_at=now()-interval '2 days',retain_until=now()-interval '1 day' WHERE id=$1")
            .bind(first)
            .execute(&pool)
            .await
            .unwrap();
        TransactionalMailRepository::delete_retained(&pool)
            .await
            .unwrap();
        let left: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM transactional_mail_outbox")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(left, [second], "only mail past its retention is deleted");
    }

    /// The cleanups delete stale email actions, invitations past retention,
    /// and owners who never verified, never signed in and are alone in their
    /// organization, with it.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn account_cleanups(pool: PgPool) {
        let actor = user(&pool).await;
        let stale = Uuid::new_v4();
        let fresh = Uuid::new_v4();
        for (id, digest) in [(stale, 1_u8), (fresh, 2)] {
            EmailActionRepository::insert(
                &pool,
                id,
                actor,
                "verify_email",
                vec![digest; 32],
                Utc::now() + Duration::hours(1),
            )
            .await
            .unwrap();
        }
        sqlx::query("UPDATE user_email_actions SET created_at=now()-interval '40 days',expires_at=now()-interval '39 days' WHERE id=$1")
            .bind(stale)
            .execute(&pool)
            .await
            .unwrap();
        EmailActionRepository::delete_stale(&pool).await.unwrap();
        let actions: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM user_email_actions")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(actions, [fresh]);

        let own = tenant(&pool, "mail-cleanups").await;
        let kept = Uuid::new_v4();
        let expired = Uuid::new_v4();
        for (id, digest, email) in [
            (kept, 3_u8, "a@example.test"),
            (expired, 4, "b@example.test"),
        ] {
            InvitationRepository::insert(
                &pool,
                id,
                own.organization_id,
                None,
                email,
                "member",
                actor,
                "en",
                vec![digest; 32],
                Utc::now() + Duration::days(1),
            )
            .await
            .unwrap();
        }
        sqlx::query("UPDATE invitations SET created_at=now()-interval '3 days',expires_at=now()-interval '2 days',retain_until=now()-interval '1 day' WHERE id=$1")
            .bind(expired)
            .execute(&pool)
            .await
            .unwrap();
        InvitationRepository::delete_retained(&pool).await.unwrap();
        let invitations: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM invitations")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(invitations, [kept]);

        let abandoned = tenant(&pool, "mail-cleanups-abandoned").await;
        let owner = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,email,password_hash,created_at) VALUES($1,$2,'$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$0123456789abcdef',now()-interval '8 days')",
        )
        .bind(owner)
        .bind(format!("{owner}@example.test"))
        .execute(&pool)
        .await
        .unwrap();
        MembershipRepository::insert_organization_role(
            &pool,
            abandoned.organization_id,
            owner,
            "owner",
        )
        .await
        .unwrap();
        UserRepository::delete_abandoned_signups(&pool)
            .await
            .unwrap();
        let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id=$1")
            .bind(owner)
            .fetch_one(&pool)
            .await
            .unwrap();
        let organizations: i64 =
            sqlx::query_scalar("SELECT count(*) FROM organizations WHERE id=$1")
                .bind(abandoned.organization_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            (users, organizations),
            (0, 0),
            "the abandoned signup is gone"
        );
        let survivors: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations WHERE id=$1")
            .bind(own.organization_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(survivors, 1);
    }
}
